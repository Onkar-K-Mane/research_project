# train_rf_triage.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

df = pd.read_csv("powershell_events.csv")
df = df.fillna(0)

features = [
    'parent_count', 'child_process_count', 'network_connections',
    'dns_queries', 'files_created', 'has_invoke', 'has_download',
    'has_encoded', 'entropy'
]
X = df[features]
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

preds = model.predict(X_test)
print(classification_report(y_test, preds))

joblib.dump(model, "rf_triage_model.pkl")
print("Model saved as rf_triage_model.pkl")