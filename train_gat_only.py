# train_gat_only.py
# GAT (Graph Attention) for PowerShell LotL Detection
# Run: python train_gat_only.py

import os, glob, torch, json
import pandas as pd
import networkx as nx
from torch_geometric.data import Data, DataLoader
from torch_geometric.nn import GATConv, global_mean_pool
from torch_geometric.utils import from_networkx
from tqdm import tqdm
from datetime import datetime, timezone

print("Loading 10,000 GAT-ready graphs...")
graphs = sorted(glob.glob("gnn_dataset/graphs/*.gml"))
labels_df = pd.read_csv("gnn_dataset/labels.csv")
print(f"{len(graphs)} graphs → {len(labels_df)} PowerShell nodes")

# ------------------------------------------------------------
# 1. Convert to PyG Data
# ------------------------------------------------------------
data_list = []
for gml in tqdm(graphs, desc="Converting"):
    try:
        Gnx = nx.read_gml(gml)
    except OSError as e:
        print(f"Skipping {gml}: {e}")
        continue
    # Ensure all nodes have the same attributes to avoid PyG error
    for node in Gnx.nodes:
        Gnx.nodes[node].clear()  # Remove all attributes since we don't use them
    data = from_networkx(Gnx)

    x, y = [], []
    for node in Gnx.nodes:
        row = labels_df[labels_df.guid == node]
        if row.empty:
            x.append([0.0]*5); y.append(0); continue
        r = row.iloc[0]
        cmd = Gnx.nodes[node].get("command_line", "")
        x.append([
            r.entropy,
            Gnx.in_degree(node),
            Gnx.out_degree(node),
            r.has_encoded,
            r.has_download
        ])
        y.append(r.label)

    data.x = torch.tensor(x, dtype=torch.float)
    data.y = torch.tensor(y, dtype=torch.long)
    data_list.append(data)

train_loader = DataLoader(data_list[:8000], batch_size=32, shuffle=True)
test_loader  = DataLoader(data_list[8000:], batch_size=32)

# ------------------------------------------------------------
# 2. GAT Model (2 heads × 2 layers)
# ------------------------------------------------------------
class GATDetector(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.gat1 = GATConv(5, 64, heads=4, dropout=0.3)
        self.gat2 = GATConv(64*4, 64, heads=1, dropout=0.3)
        self.lin  = torch.nn.Linear(64, 2)
    
    def forward(self, data):
        x, edge_index, batch = data.x, data.edge_index, data.batch
        x = torch.relu(self.gat1(x, edge_index))
        x = torch.relu(self.gat2(x, edge_index))
        return self.lin(x)

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model = GATDetector().to(device)
opt = torch.optim.Adam(model.parameters(), lr=0.005, weight_decay=1e-4)
criterion = torch.nn.CrossEntropyLoss(weight=torch.tensor([1.0, 6.0]).to(device))  # 6× on malicious

# ------------------------------------------------------------
# 3. Train 18 epochs
# ------------------------------------------------------------
print(f"\nTraining GAT on {device}...")
for epoch in range(1, 19):
    model.train()
    loss_sum = 0
    for batch in train_loader:
        batch = batch.to(device)
        opt.zero_grad()
        out = model(batch)
        loss = criterion(out, batch.y)
        loss.backward()
        opt.step()
        loss_sum += loss.item()
    print(f"Epoch {epoch:02d} → Loss {loss_sum/len(train_loader):.4f}")

# ------------------------------------------------------------
# 4. Final recall
# ------------------------------------------------------------
model.eval()
mal_preds = []
mal_true = []
with torch.no_grad():
    for batch in test_loader:
        batch = batch.to(device)
        pred = model(batch).argmax(dim=1)
        mal_mask = batch.y == 1
        mal_preds.extend(pred[mal_mask].cpu().tolist())
        mal_true.extend(batch.y[mal_mask].cpu().tolist())

recall = sum(p == t for p,t in zip(mal_preds, mal_true)) / len(mal_true)
print(f"\nMALICIOUS RECALL: {recall:.4f}  ({len(mal_true)} samples)")

# ------------------------------------------------------------
# 5. Save
# ------------------------------------------------------------
os.makedirs("gat_model", exist_ok=True)
torch.save(model.state_dict(), "gat_model/detector.pth")
with open("gat_model/feature_names.json", "w") as f:
    json.dump(["entropy","in_degree","out_degree","has_encoded","has_download"], f)

meta = {
    "model": "GAT-4heads-64",
    "trained_at": datetime.now(timezone.utc).isoformat(),
    "malicious_recall": recall,
    "device": str(device),
    "epochs": 18
}
with open("gat_model/metadata.json", "w") as f:
    json.dump(meta, f, indent=2)

print("\nGAT saved → gat_model/detector.pth")
print("Ready for live inference!")