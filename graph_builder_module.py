import win32evtlog
import xml.etree.ElementTree as ET
import networkx as nx
import threading
import time
import logging
import argparse
from datetime import datetime, timedelta, timezone  # <-- timezone added

# --- Setup Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# --- Global Graph Object ---
G = nx.DiGraph()
graph_lock = threading.Lock()
XML_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"

# --- Helper: Parse ISO Timestamp with Z support ---
def parse_iso_timestamp(ts_str):
    """Convert Sysmon 'TimeCreated' (e.g., '2025-10-30T12:34:56.789Z') to UTC-aware datetime"""
    if not ts_str:
        return None
    try:
        # Replace Z with +00:00
        if ts_str.endswith('Z'):
            ts_str = ts_str[:-1] + '+00:00'
        # Parse with fromisoformat
        dt = datetime.fromisoformat(ts_str)
        # Ensure UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception as e:
        logger.debug(f"Failed to parse timestamp: {ts_str} | {e}")
        return None

# --- Node Naming & Attribute Helper ---
def get_process_guid(event_data):
    return event_data.get('ProcessGuid', '').strip('{}')

def get_parent_guid(event_data):
    return event_data.get('ParentProcessGuid', '').strip('{}')

def add_node_if_not_exists(node_id, timestamp, **attrs):
    """Add or update node with sanitized attrs and first_seen"""
    # Sanitize string attributes
    for key, value in attrs.items():
        if isinstance(value, str):
            attrs[key] = value.strip().encode('ascii', 'ignore').decode('ascii')
    
    # Parse timestamp
    dt = parse_iso_timestamp(timestamp)
    if not dt:
        return

    with graph_lock:
        if G.has_node(node_id):
            # Update first_seen only if earlier
            current_fs = G.nodes[node_id].get('first_seen')
            if current_fs:
                current_dt = parse_iso_timestamp(current_fs)
                if current_dt and dt < current_dt:
                    G.nodes[node_id]['first_seen'] = timestamp
            else:
                G.nodes[node_id]['first_seen'] = timestamp
            # Merge other attributes
            for k, v in attrs.items():
                if k != 'first_seen':
                    G.nodes[node_id][k] = v
        else:
            attrs['first_seen'] = timestamp
            G.add_node(node_id, **attrs)
            logger.info(f"Added node: {node_id} ({attrs.get('type', 'unknown')})")

# --- Event Handlers ---
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
        logger.debug(f"Edge: {parent_guid} -> {child_guid} (ProcessCreate)")

    # --- PowerShell Triage ---
    image = event_data.get('Image', '').lower()
    if 'powershell' in image:
        cmd = event_data.get('CommandLine', '')
        entropy = len(set(cmd)) / len(cmd) if cmd else 0
        if entropy < 0.3 or any(kw in cmd.lower() for kw in ['invoke', 'download', 'webclient']):
            logger.warning(f"SUSPICIOUS PowerShell: {child_guid} | Cmd: {cmd[:100]}...")

# Other handlers (3, 11, 13, 22) - unchanged for brevity
def handle_event_3(event_data, timestamp):
    process_guid = get_process_guid(event_data)
    dest_ip = event_data.get('DestinationIp')
    if not process_guid or not dest_ip: return
    add_node_if_not_exists(dest_ip, timestamp, type='ip_address')
    with graph_lock:
        if G.has_node(process_guid):
            G.add_edge(process_guid, dest_ip, action='NetworkConnect', port=event_data.get('DestinationPort'), timestamp=timestamp)

def handle_event_11(event_data, timestamp):
    process_guid = get_process_guid(event_data)
    file_path = event_data.get('TargetFilename')
    if not process_guid or not file_path: return
    add_node_if_not_exists(file_path, timestamp, type='file')
    with graph_lock:
        if G.has_node(process_guid):
            G.add_edge(process_guid, file_path, action='FileCreate', timestamp=timestamp)

def handle_event_13(event_data, timestamp):
    process_guid = get_process_guid(event_data)
    reg_key = event_data.get('TargetObject')
    if not process_guid or not reg_key: return
    add_node_if_not_exists(reg_key, timestamp, type='registry_key')
    with graph_lock:
        if G.has_node(process_guid):
            G.add_edge(process_guid, reg_key, action='RegistrySetValue', details=event_data.get('Details'), timestamp=timestamp)

def handle_event_22(event_data, timestamp):
    process_guid = get_process_guid(event_data)
    domain_name = event_data.get('QueryName')
    if not process_guid or not domain_name: return
    add_node_if_not_exists(domain_name, timestamp, type='domain')
    with graph_lock:
        if G.has_node(process_guid):
            G.add_edge(process_guid, domain_name, action='DnsQuery', results=event_data.get('QueryResults', ''), timestamp=timestamp)

# --- XML Parser ---
def parse_sysmon_event_xml(xml_string):
    try:
        ET.register_namespace('', XML_NAMESPACE)
        root = ET.fromstring(xml_string)
        system_info = {}
        event_data = {}
        system_node = root.find(f"{{{XML_NAMESPACE}}}System")
        if system_node is not None:
            for child in system_node:
                tag = child.tag.split('}')[-1]
                if tag == 'TimeCreated':
                    system_info[tag] = child.attrib.get('SystemTime')
                else:
                    system_info[tag] = child.text
        event_data_node = root.find(f"{{{XML_NAMESPACE}}}EventData")
        if event_data_node is not None:
            for child in event_data_node:
                key = child.attrib.get('Name')
                if key:
                    event_data[key] = child.text
        return system_info, event_data
    except ET.ParseError as e:
        logger.error(f"XML Parse Error: {e}\nSnippet: {xml_string[:200]}...")
        return None, None

# --- Event Processor ---
def process_event(xml_string):
    system_info, event_data = parse_sysmon_event_xml(xml_string)
    if not system_info or not event_data:
        return
    event_id = system_info.get('EventID')
    timestamp = system_info.get('TimeCreated')
    try:
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
        else:
            logger.debug(f"No handler for Event ID {event_id}")
    except Exception as e:
        logger.error(f"Handler error for Event {event_id}: {e}")

# --- EvtSubscribe Callback ---
def event_callback(action, context, event_handle):
    if action == win32evtlog.EvtSubscribeActionDeliver:
        try:
            xml_string = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
            process_event(xml_string)
        except Exception as e:
            logger.error(f"Callback render error: {e}")
    elif action == win32evtlog.EvtSubscribeActionError:
        logger.error("Subscription error")

# --- Pruning Loop (FIXED) ---
def prune_loop(prune_hours):
    while True:
        time.sleep(300)  # Every 5 minutes
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
                logger.info(f"Pruned {len(to_remove)} stale isolated nodes")

# --- Periodic Save ---
def save_loop():
    while True:
        time.sleep(600)  # Every 10 minutes
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
    parser = argparse.ArgumentParser(description="Real-Time Sysmon Provenance Graph Builder")
    parser.add_argument('--channel', default='Microsoft-Windows-Sysmon/Operational', help='Event log channel')
    parser.add_argument('--prune-hours', type=int, default=24, help='Prune isolated nodes older than X hours')
    args = parser.parse_args()

    logger.info(f"Starting on channel: {args.channel} | Prune after {args.prune_hours}h")

    # Start background threads
    threading.Thread(target=prune_loop, args=(args.prune_hours,), daemon=True).start()
    threading.Thread(target=save_loop, daemon=True).start()

    try:
        handle = win32evtlog.EvtSubscribe(
            args.channel,
            win32evtlog.EvtSubscribeToFutureEvents,
            Callback=event_callback
        )
        logger.info("Subscription active. Generating events to build graph...")
        while True:
            time.sleep(1)
    except Exception as e:
        logger.error(f"Subscription failed: {e}")
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        with graph_lock:
            logger.info(f"Final graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
            nx.write_gml(G, "provenance_graph_final.gml")
            logger.info("Saved final graph.")

if __name__ == "__main__":
    main()