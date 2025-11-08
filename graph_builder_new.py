# graph_builder_new.py
# ENHANCED: Full RF Triage + Event 5/12/13 + Live Graph Features + GAT + XAI + MITRE

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
import os
import torch
import torch.nn.functional as F
from torch_geometric.utils import from_networkx
from torch_geometric.nn import GATConv, global_mean_pool
import re

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Malicious command logger
malicious_logger = logging.getLogger('malicious')
malicious_logger.setLevel(logging.INFO)
os.makedirs("logs", exist_ok=True)
mal_handler = logging.FileHandler('logs/malicious_commands.log')
mal_handler.setFormatter(logging.Formatter('%(message)s'))
malicious_logger.addHandler(mal_handler)

# --- Load RF Model ---
try:
    rf_model = joblib.load("triage_model/rf_triage_model.pkl")
    logger.info("PowerShell triage model loaded.")
except Exception as e:
    rf_model = None
    logger.error(f"Model failed to load: {e}. Triage disabled.")

# --- Load GAT Model ---
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
class GATDetector(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.gat1 = GATConv(5, 64, heads=4, dropout=0.3)
        self.gat2 = GATConv(64*4, 64, heads=1, dropout=0.3)
        self.lin = torch.nn.Linear(64, 2)
    
    def forward(self, data):
        x, edge_index, batch = data.x, data.edge_index, data.batch
        x = torch.relu(self.gat1(x, edge_index))
        x = torch.relu(self.gat2(x, edge_index))
        x = global_mean_pool(x, batch)
        return self.lin(x)

try:
    gat_model = GATDetector().to(device)
    gat_model.load_state_dict(torch.load("gat_model/detector.pth", map_location=device))
    gat_model.eval()
    logger.info(f"GAT model loaded on {device}.")
except Exception as e:
    gat_model = None
    logger.error(f"GAT model failed to load: {e}. GAT detection disabled.")

# --- Global Graph ---
G = nx.DiGraph()
graph_lock = threading.Lock()

# --- XML Namespaces ---
SYSMON_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# --- MITRE ATT&CK Mapping ---
MITRE = {
    "reg add HKCU.*Run": "T1547.001",
    "schtasks /create": "T1053.005",
    "Net.WebClient.*Download": "T1105",
    "DnsQuery.*c2": "T1071",
    "FileCreate.*Temp.*exe": "T1055"
}

# --- Helper: Parse Timestamp ---
def parse_iso_timestamp(ts_str):
    if not ts_str or not ts_str.strip():
        return None
    try:
        if ts_str.endswith('Z'):
            ts_str = ts_str[:-1] + '+00:00'
        dt = datetime.fromisoformat(ts_str)
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    except:
        return None

# --- Node Management ---
def add_node(guid, ts, **attrs):
    dt = parse_iso_timestamp(ts)
    if not dt:
        return
    with graph_lock:
        if not G.has_node(guid):
            attrs['first_seen'] = ts
            G.add_node(guid, **attrs)
        else:
            if 'first_seen' not in G.nodes[guid]:
                G.nodes[guid]['first_seen'] = ts

# --- Feature Extraction from Graph ---
def extract_features(guid):
    with graph_lock:
        if not G.has_node(guid):
            return None

        node = G.nodes[guid]
        children = len(list(G.successors(guid)))
        parents = len(list(G.predecessors(guid)))

        net = sum(1 for t in G.successors(guid) if G.nodes[t].get('type') == 'ip_address')
        dns = sum(1 for t in G.successors(guid) if G.nodes[t].get('type') == 'domain')
        files = sum(1 for t in G.successors(guid) if G.nodes[t].get('type') == 'file')

        cmd = node.get('command_line', '').lower()
        has_invoke = any(k in cmd for k in ['iex', 'invoke', 'start-job'])
        has_download = any(k in cmd for k in ['download', 'webclient', 'iwr', 'curl'])
        has_encoded = any(k in cmd for k in ['-enc', '-encodedcommand', '-e '])
        entropy = len(set(cmd)) / len(cmd) if cmd else 0

        return {
            'parent_count': parents,
            'child_process_count': children,
            'network_connections': net,
            'dns_queries': dns,
            'files_created': files,
            'has_invoke': int(has_invoke),
            'has_download': int(has_download),
            'has_encoded': int(has_encoded),
            'entropy': round(entropy, 3)
        }

# --- RF Triage ---
def triage_powershell(guid, cmd):
    if not rf_model:
        return False

    feats = extract_features(guid)
    if not feats:
        return False

    X = pd.DataFrame([feats])
    prob = rf_model.predict_proba(X)[0][1]
    pred = rf_model.predict(X)[0]

    if pred == 1:
        alert = f"🚨 MALICIOUS POWERSHELL DETECTED | GUID: {guid} | Prob: {prob:.3f}"
        logger.warning(alert)
        malicious_logger.warning(f"{guid} | {prob:.3f} | {cmd[:200]}")
        return True
    return False

# --- Sysmon Event Handlers ---
def handle_event_1(event_data, timestamp):  # Process Create
    child_guid = event_data.get('ProcessGuid', '').strip('{}')
    parent_guid = event_data.get('ParentProcessGuid', '').strip('{}')
    if not child_guid or not parent_guid:
        return

    cmd = event_data.get('CommandLine', '')
    image = event_data.get('Image', '')

    add_node(child_guid, timestamp,
             type='process',
             name=image,
             pid=event_data.get('ProcessId', ''),
             command_line=cmd)
    add_node(parent_guid, timestamp,
             type='process',
             name=event_data.get('ParentImage', ''),
             pid=event_data.get('ParentProcessId', ''))

    with graph_lock:
        G.add_edge(parent_guid, child_guid, action="ProcessCreate", timestamp=timestamp)

    # RF Triage for PowerShell
    if 'powershell' in image.lower():
        is_suspicious_ml = triage_powershell(child_guid, cmd)

        # GAT + XAI if suspicious
        if gat_model and is_suspicious_ml:
            with graph_lock:
                sub = nx.ego_graph(G, child_guid, radius=2)
            if len(sub) < 3:
                return

            data = from_networkx(sub)
            x = []
            node_list = list(sub.nodes)
            for n in node_list:
                d = sub.nodes[n]
                c = d.get("command_line", "")
                x.append([
                    len(set(c))/max(len(c),1),
                    sub.in_degree(n),
                    sub.out_degree(n),
                    int("-enc" in c.lower()),
                    int(any(k in c.lower() for k in ["download","iwr","webclient"]))
                ])
            data.x = torch.tensor(x, dtype=torch.float).to(device)
            data.edge_index = data.edge_index.to(device)
            data.batch = torch.zeros(len(x), dtype=torch.long).to(device)

            with torch.no_grad():
                out = gat_model(data)
                prob = F.softmax(out, dim=1)[0,1].item()
                # Attention from first GAT layer
                self_attn = gat_model.gat1.attention_weights
                if self_attn is not None:
                    top_idx = self_attn.mean(1).argmax().item()
                    clue_node = node_list[top_idx]
                    clue = sub.nodes[clue_node].get("name", "?").split("\\")[-1]
                else:
                    clue = "unknown"

            if prob > 0.75:
                # Attack chain
                try:
                    chain = nx.shortest_path(sub.to_undirected(), parent_guid, child_guid)
                    chain_names = [sub.nodes[c].get("name","?").split("\\")[-1] for c in chain]
                except:
                    chain_names = ["unknown"]

                # MITRE
                tactic = "Unknown"
                for pattern, tid in MITRE.items():
                    if re.search(pattern, cmd, re.I):
                        tactic = tid
                        break

                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "ALERT": "LIVING_OFF_THE_LAND",
                    "guid": child_guid,
                    "command": cmd[:200],
                    "confidence": round(prob, 3),
                    "attack_chain": " → ".join(chain_names),
                    "top_evidence": clue,
                    "MITRE": tactic
                }
                malicious_logger.info(json.dumps(alert, separators=(',',':')))
                print(f"GAT DETECTED | {prob:.0%} | {tactic} | {cmd[:80]}...")

def handle_event_3(event_data, timestamp):  # Network Connect
    guid = event_data.get('ProcessGuid', '').strip('{}')
    dest_ip = event_data.get('DestinationIp', '')
    if not guid or not dest_ip:
        return
    add_node(f"ip:{dest_ip}", timestamp, type='ip_address')
    with graph_lock:
        G.add_edge(guid, f"ip:{dest_ip}", action='NetworkConnect', timestamp=timestamp)

def handle_event_5(event_data, timestamp):  # Process Terminate
    guid = event_data.get('ProcessGuid', '').strip('{}')
    if not guid:
        return
    with graph_lock:
        if G.has_node(guid):
            G.nodes[guid]['terminated'] = timestamp

def handle_event_11(event_data, timestamp):  # File Create
    guid = event_data.get('ProcessGuid', '').strip('{}')
    file = event_data.get('TargetFilename', '')
    if not guid or not file:
        return
    add_node(f"file:{file}", timestamp, type='file')
    with graph_lock:
        G.add_edge(guid, f"file:{file}", action='FileCreate', timestamp=timestamp)

def handle_event_12(event_data, timestamp):  # Registry Create/Delete
    guid = event_data.get('ProcessGuid', '').strip('{}')
    key = event_data.get('TargetObject', '')
    if not guid or not key:
        return
    add_node(f"reg:{key}", timestamp, type='registry')
    with graph_lock:
        G.add_edge(guid, f"reg:{key}", action='RegistryCreate', timestamp=timestamp)

def handle_event_13(event_data, timestamp):  # Registry Set
    guid = event_data.get('ProcessGuid', '').strip('{}')
    key = event_data.get('TargetObject', '')
    if not guid or not key:
        return
    add_node(f"reg:{key}", timestamp, type='registry')
    with graph_lock:
        G.add_edge(guid, f"reg:{key}", action='RegistrySet', timestamp=timestamp)

def handle_event_22(event_data, timestamp):  # DNS Query
    guid = event_data.get('ProcessGuid', '').strip('{}')
    domain = event_data.get('QueryName', '')
    if not guid or not domain:
        return
    add_node(f"domain:{domain}", timestamp, type='domain')
    with graph_lock:
        G.add_edge(guid, f"domain:{domain}", action='DnsQuery', timestamp=timestamp)

# --- XML Parser ---
def parse_sysmon_event_xml(xml_string):
    try:
        root = ET.fromstring(xml_string)
        ns = {'ns': SYSMON_NS}
        system = root.find('ns:System', ns)
        event_data_elem = root.find('ns:EventData', ns)

        if system is None or event_data_elem is None:
            return None, None

        timestamp = system.find('ns:TimeCreated', ns).get('SystemTime')
        event_id = system.find('ns:EventID', ns).text

        data = {}
        for elem in event_data_elem.findall('ns:Data', ns):
            name = elem.get('Name')
            text = elem.text
            if name and text:
                data[name] = text.strip()

        return {'EventID': event_id, 'TimeCreated': timestamp}, data
    except Exception as e:
        logger.debug(f"XML parse error: {e}")
        return None, None

# --- Event Processor ---
def process_sysmon_event(xml_string):
    system_info, event_data = parse_sysmon_event_xml(xml_string)
    if not system_info:
        return

    event_id = system_info['EventID']
    timestamp = system_info['TimeCreated']

    handlers = {
        '1': handle_event_1,
        '3': handle_event_3,
        '5': handle_event_5,
        '11': handle_event_11,
        '12': handle_event_12,
        '13': handle_event_13,
        '22': handle_event_22,
    }
    handler = handlers.get(event_id)
    if handler:
        handler(event_data, timestamp)

# --- Callback ---
def sysmon_callback(action, context, event_handle):
    if action == win32evtlog.EvtSubscribeActionDeliver:
        try:
            xml = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
            process_sysmon_event(xml)
        except Exception as e:
            logger.error(f"Callback error: {e}")

# --- Background Tasks ---
def save_loop():
    while True:
        time.sleep(600)
        with graph_lock:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            file = f"provenance_graph_{ts}.gml"
            try:
                nx.write_gml(G, file)
                logger.info(f"Autosaved: {file} | Nodes: {G.number_of_nodes()} | Edges: {G.number_of_edges()}")
            except Exception as e:
                logger.error(f"Save failed: {e}")

def prune_loop(hours=24):
    while True:
        time.sleep(300)
        with graph_lock:
            now = datetime.now(timezone.utc)
            to_remove = [
                n for n, d in G.nodes(data=True)
                if d.get('first_seen') and
                   (now - parse_iso_timestamp(d['first_seen'])).total_seconds() > hours * 3600
                   and G.degree(n) == 0
            ]
            if to_remove:
                G.remove_nodes_from(to_remove)
                logger.info(f"Pruned {len(to_remove)} stale nodes")

# --- Main ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prune-hours', type=int, default=24)
    args = parser.parse_args()

    logger.info("Starting Enhanced Provenance Graph Builder + RF Triage + GAT Detection")
    threading.Thread(target=save_loop, daemon=True).start()
    threading.Thread(target=prune_loop, args=(args.prune_hours,), daemon=True).start()

    try:
        handle = win32evtlog.EvtSubscribe(
            'Microsoft-Windows-Sysmon/Operational',
            win32evtlog.EvtSubscribeToFutureEvents,
            Callback=sysmon_callback
        )
        logger.info("Sysmon subscription ACTIVE. Run PowerShell to test.")
        print("\n" + "="*60)
        print("   READY: Watching for malicious PowerShell")
        print("   Logs → logs/malicious_commands.log")
        print("   Graph → provenance_graph_*.gml")
        print("="*60 + "\n")

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        with graph_lock:
            nx.write_gml(G, "provenance_graph_FINAL.gml")
            logger.info("Final graph saved.")

if __name__ == "__main__":
    main()
