import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# Synthetic cybersecurity dataset
data = pd.DataFrame({
    'open_ports': [5, 2, 10, 1, 0, 8],
    'old_services': [1, 0, 1, 0, 0, 1],
    'cvss_base': [7.5, 3.1, 9.8, 5.3, 0, 8.1],
    'severity': ['High', 'Low', 'Critical', 'Medium', 'None', 'High']
})

X = data.drop('severity', axis=1)
y = pd.get_dummies(data['severity']).values.argmax(1)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

joblib.dump(model, 'ai_vuln_model.pkl')
print("✅ AI Model trained & saved!")