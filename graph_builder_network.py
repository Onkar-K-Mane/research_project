import win32evtlog
import xml.etree.ElementTree as ET
import networkx as nx
import threading
import time
import logging
import argparse
from datetime import datetime, timezone
import pandas as pd
import joblib
import json

# --- Setup Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# --- ML Model Loading ---
try:
    rf_model = joblib.load("rf_triage_model.pkl")
    logger.info("PowerShell triage model loaded successfully.")
except Exception as e:
    rf_model = None
    logger.warning(f"Could not load triage model: {e}. Triage will be disabled.")

# --- Global Graph Object ---
G = nx.DiGraph()
graph_lock = threading.Lock()

# --- XML Namespaces ---
SYSMON_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
NETPROFILE_NS = "http://manifests.microsoft.com/win/2004/08/windows/events"

# --- Helper: Parse ISO Timestamp ---
def parse_iso_timestamp(ts_str):
    if not ts_str:
        return None
    try:
        if ts_str.endswith('Z'):
            ts_str = ts_str[:-1] + '+00:00'
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception as e:
        logger.debug(f"Failed to parse timestamp: {ts_str} | {e}")
        return None

# --- Node Management ---
def get_process_guid(event_data):
    return event_data.get('ProcessGuid', '').strip('{}')

def get_parent_guid(event_data):
    return event_data.get('ParentProcessGuid', '').strip('{}')

def add_node_if_not_exists(node_id, timestamp, **attrs):
    for key, value in attrs.items():
        if isinstance(value, str):
            attrs[key] = value.strip().encode('ascii', 'ignore').decode('ascii')
    
    dt = parse_iso_timestamp(timestamp)
    if not dt:
        return

    with graph_lock:
        if G.has_node(node_id):
            current_fs = G.nodes[node_id].get('first_seen')
            if current_fs:
                current_dt = parse_iso_timestamp(current_fs)
                if current_dt and dt < current_dt:
                    G.nodes[node_id]['first_seen'] = timestamp
            else:
                G.nodes[node_id]['first_seen'] = timestamp
            for k, v in attrs.items():
                if k != 'first_seen':
                    G.nodes[node_id][k] = v
        else:
            attrs['first_seen'] = timestamp
            G.add_node(node_id, **attrs)
            logger.debug(f"Added node: {node_id} ({attrs.get('type', 'unknown')})")

# --- PID to GUID Resolver ---
def resolve_process_guid_by_pid(pid, image_path=None, event_time_str=None):
    event_dt = parse_iso_timestamp(event_time_str) if event_time_str else datetime.now(timezone.utc)
    if not event_dt:
        return None

    candidates = []
    with graph_lock:
        for node, data in G.nodes(data=True):
            if data.get('type') != 'process':
                continue
            node_pid = data.get('pid')
            if str(node_pid) != str(pid):
                continue

            fs = data.get('first_seen')
            if not fs:
                continue
            fs_dt = parse_iso_timestamp(fs)
            if not fs_dt:
                continue

            time_diff = abs((event_dt - fs_dt).total_seconds())
            if time_diff > 300:
                continue

            score = 1.0
            if image_path:
                node_image = data.get('name', '').lower()
                img_lower = image_path.lower()
                if img_lower in node_image or node_image in img_lower:
                    score += 1.0

            candidates.append((node, score, time_diff))

    if not candidates:
        return None

    best = min(candidates, key=lambda x: (1/x[1], x[2]))
    return best[0]

# --- Sysmon Event Handlers ---
def handle_event_1(event_data, timestamp):
    child_guid = get_process_guid(event_data)
    parent_guid = get_parent_guid(event_data)
    if not child_guid or not parent_guid:
        return

    add_node_if_not_exists(
        child_guid, timestamp,
        type='process', name=event_data.get('Image', 'unknown'),
        pid=event_data.get('ProcessId', 'unknown'),
        command_line=event_data.get('CommandLine', '')
    )
    add_node_if_not_exists(
        parent_guid, timestamp,
        type='process', name=event_data.get('ParentImage', 'unknown'),
        pid=event_data.get('ParentProcessId', 'unknown')
    )

    with graph_lock:
        G.add_edge(parent_guid, child_guid, action='ProcessCreate', timestamp=timestamp)

    # --- PowerShell Triage ---
    image = event_data.get('Image', '').lower()
    if 'powershell' in image and rf_model:
        cmd = event_data.get('CommandLine', '')
        entropy = len(set(cmd)) / len(cmd) if cmd else 0
        
        # Heuristic check
        is_suspicious_heuristic = False
        if any(kw in cmd.lower() for kw in ['invoke', 'iex', 'download', 'webclient', 'encodedcommand']):
            is_suspicious_heuristic = True
            logger.warning(f"SUSPICIOUS PowerShell: {child_guid} | Cmd: {cmd[:100]}...")

        # ML-based check
        try:
            features = {
                'parent_count': len(list(G.predecessors(child_guid))),
                'child_process_count': len(list(G.successors(child_guid))),
                'network_connections': 0, # Placeholder, can be enriched later
                'dns_queries': 0, # Placeholder
                'files_created': 0, # Placeholder
                'has_invoke': 1 if 'invoke' in cmd.lower() or 'iex' in cmd.lower() else 0,
                'has_download': 1 if 'download' in cmd.lower() or 'webclient' in cmd.lower() else 0,
                'has_encoded': 1 if 'encodedcommand' in cmd.lower() else 0,
                'entropy': entropy,
            }
            X = pd.DataFrame([features])
            prediction = rf_model.predict(X)[0]

            if prediction == 1:
                logger.critical(f"[ML TRIAGE ALERT] Malicious PowerShell detected: {child_guid}")
                with open("suspicious_events.jsonl", "a") as f:
                    json.dump({
                        "guid": child_guid, "timestamp": timestamp, "command": cmd,
                        "features": features, "prediction": int(prediction)
                    }, f)
                    f.write("\n")
        except Exception as e:
            logger.error(f"ML triage failed for {child_guid}: {e}")

def handle_event_3(event_data, timestamp):
    process_guid = get_process_guid(event_data)
    dest_ip = event_data.get('DestinationIp')
    if not process_guid or not dest_ip:
        return
    ip_node = f"ip:{dest_ip}"
    add_node_if_not_exists(ip_node, timestamp, type='ip_address')
    with graph_lock:
        if G.has_node(process_guid):
            G.add_edge(process_guid, ip_node, action='NetworkConnect', port=event_data.get('DestinationPort'), timestamp=timestamp, source='sysmon')

def handle_event_11(event_data, timestamp):
    process_guid = get_process_guid(event_data)
    file_path = event_data.get('TargetFilename')
    if not process_guid or not file_path:
        return
    add_node_if_not_exists(file_path, timestamp, type='file')
    with graph_lock:
        if G.has_node(process_guid):
            G.add_edge(process_guid, file_path, action='FileCreate', timestamp=timestamp)

def handle_event_13(event_data, timestamp):
    process_guid = get_process_guid(event_data)
    reg_key = event_data.get('TargetObject')
    if not process_guid or not reg_key:
        return
    add_node_if_not_exists(reg_key, timestamp, type='registry_key')
    with graph_lock:
        if G.has_node(process_guid):
            G.add_edge(process_guid, reg_key, action='RegistrySetValue', details=event_data.get('Details'), timestamp=timestamp)

def handle_event_22(event_data, timestamp):
    process_guid = get_process_guid(event_data)
    domain_name = event_data.get('QueryName')
    if not process_guid or not domain_name:
        return
    add_node_if_not_exists(domain_name, timestamp, type='domain')
    with graph_lock:
        if G.has_node(process_guid):
            G.add_edge(process_guid, domain_name, action='DnsQuery', results=event_data.get('QueryResults', ''), timestamp=timestamp)

# --- NetworkProfile Handler ---
def handle_network_connect_event(event_data, timestamp):
    try:
        process_id = event_data.get('ProcessID')
        app_path = event_data.get('ApplicationPath', '').strip()
        dest_ip = event_data.get('RemoteAddress')
        dest_port = event_data.get('RemotePort')
        protocol = event_data.get('Protocol', 'TCP')

        if not process_id or not dest_ip:
            return

        process_guid = resolve_process_guid_by_pid(int(process_id), app_path, timestamp)
        if not process_guid:
            return

        ip_node_id = f"ip:{dest_ip}"
        add_node_if_not_exists(ip_node_id, timestamp, type='ip_address', port=dest_port, protocol=protocol)

        with graph_lock:
            if G.has_node(process_guid):
                G.add_edge(
                    process_guid, ip_node_id,
                    action='NetworkConnect',
                    port=dest_port,
                    protocol=protocol,
                    timestamp=timestamp,
                    source='networkprofile'
                )

    except Exception as e:
        logger.error(f"Error in handle_network_connect_event: {e}")

# --- XML Parsers ---
def parse_sysmon_event_xml(xml_string):
    try:
        ET.register_namespace('', SYSMON_NS)
        root = ET.fromstring(xml_string)
        system_info = {}
        event_data = {}
        system_node = root.find(f"{{{SYSMON_NS}}}System")
        if system_node is not None:
            for child in system_node:
                tag = child.tag.split('}')[-1]
                if tag == 'TimeCreated':
                    system_info[tag] = child.attrib.get('SystemTime')
                else:
                    system_info[tag] = child.text
        event_data_node = root.find(f"{{{SYSMON_NS}}}EventData")
        if event_data_node is not None:
            for child in event_data_node:
                key = child.attrib.get('Name')
                if key:
                    event_data[key] = child.text
        return system_info, event_data
    except ET.ParseError as e:
        logger.error(f"Sysmon XML Parse Error: {e}")
        return None, None

def parse_networkprofile_event_xml(xml_string):
    try:
        root = ET.fromstring(xml_string)
        ns = {'ns': NETPROFILE_NS}
        event_data = {}

        for elem in root.findall('.//ns:Data', ns):
            name = elem.attrib.get('Name')
            text = elem.text
            if name and text is not None:
                event_data[name] = text.strip()

        time_elem = root.find('.//ns:TimeCreated', ns)
        timestamp = time_elem.attrib.get('SystemTime') if time_elem is not None else None

        system_elem = root.find('.//ns:System', ns)
        event_id = system_elem.find('ns:EventID', ns).text if system_elem is not None else None

        return {'EventID': event_id, 'TimeCreated': timestamp}, event_data
    except Exception as e:
        logger.error(f"NetworkProfile XML Parse Error: {e}")
        return None, None

# --- Event Processors ---
def process_sysmon_event(xml_string):
    system_info, event_data = parse_sysmon_event_xml(xml_string)
    if not system_info or not event_data:
        return
    event_id = system_info.get('EventID')
    timestamp = system_info.get('TimeCreated')
    handlers = {
        '1': handle_event_1,
        '3': handle_event_3,
        '11': handle_event_11,
        '13': handle_event_13,
        '22': handle_event_22,
    }
    handler = handlers.get(event_id)
    if handler:
        handler(event_data, timestamp)

def process_network_event(xml_string):
    system_info, event_data = parse_networkprofile_event_xml(xml_string)
    if not system_info:
        return
    if system_info.get('EventID') == '10000':
        handle_network_connect_event(event_data, system_info.get('TimeCreated'))

# --- Callbacks ---
def sysmon_callback(action, context, event_handle):
    if action == win32evtlog.EvtSubscribeActionDeliver:
        try:
            xml_string = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
            process_sysmon_event(xml_string)
        except Exception as e:
            logger.error(f"Sysmon callback error: {e}")
    elif action == win32evtlog.EvtSubscribeActionError:
        logger.error("Sysmon subscription error")

def network_callback(action, context, event_handle):
    if action == win32evtlog.EvtSubscribeActionDeliver:
        try:
            xml_string = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
            process_network_event(xml_string)
        except Exception as e:
            logger.error(f"Network callback error: {e}")
    elif action == win32evtlog.EvtSubscribeActionError:
        logger.error("Network subscription error")

# --- Background Tasks ---
def prune_loop(prune_hours):
    while True:
        time.sleep(300)
        with graph_lock:
            now = datetime.now(timezone.utc)
            to_remove = []
            for node, data in list(G.nodes(data=True)):
                fs = data.get('first_seen')
                if not fs:
                    continue
                dt = parse_iso_timestamp(fs)
                if not dt:
                    continue
                hours_old = (now - dt).total_seconds() / 3600
                if hours_old > prune_hours and G.degree(node) == 0:
                    to_remove.append(node)
            if to_remove:
                G.remove_nodes_from(to_remove)
                logger.info(f"Pruned {len(to_remove)} stale nodes")

def save_loop():
    while True:
        time.sleep(600)
        with graph_lock:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"provenance_graph_{ts}.gml"
            try:
                nx.write_gml(G, filename)
                logger.info(f"Autosaved: {filename} ({G.number_of_nodes()} nodes, {G.number_of_edges()} edges)")
            except Exception as e:
                logger.error(f"Autosave failed: {e}")

# --- Main ---
def main():
    parser = argparse.ArgumentParser(description="Real-Time Provenance Graph Builder")
    parser.add_argument('--sysmon-channel', default='Microsoft-Windows-Sysmon/Operational')
    parser.add_argument('--network-channel', default='Microsoft-Windows-NetworkProfile/Operational')
    parser.add_argument('--prune-hours', type=int, default=24)
    args = parser.parse_args()

    logger.info("Starting graph builder...")
    logger.info(f"  Sysmon: {args.sysmon_channel}")
    logger.info(f"  Network: {args.network_channel}")
    logger.info(f"  Prune after {args.prune_hours}h")

    threading.Thread(target=prune_loop, args=(args.prune_hours,), daemon=True).start()
    threading.Thread(target=save_loop, daemon=True).start()

    # === Sysmon Subscription ===
    sysmon_handle = None
    try:
        sysmon_handle = win32evtlog.EvtSubscribe(
            args.sysmon_channel,
            win32evtlog.EvtSubscribeToFutureEvents,
            Callback=sysmon_callback
        )
        logger.info("Sysmon subscription active.")
    except Exception as e:
        logger.error(f"Failed to subscribe to Sysmon: {e}")

    # === NetworkProfile Subscription ===
    network_handle = None
    try:
        network_handle = win32evtlog.EvtSubscribe(
            args.network_channel,
            win32evtlog.EvtSubscribeToFutureEvents,
            Callback=network_callback
        )
        logger.info("NetworkProfile subscription active.")
    except Exception as e:
        logger.error(f"Failed to subscribe to NetworkProfile: {e}")

    logger.info("Graph builder running. Generate events to build provenance...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        with graph_lock:
            final_file = "provenance_graph_final.gml"
            nx.write_gml(G, final_file)
            logger.info(f"Final graph saved: {final_file} ({G.number_of_nodes()} nodes, {G.number_of_edges()} edges)")

if __name__ == "__main__":
    main()