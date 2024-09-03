# Blockchain-Compliance-with-User-Tracking-in-GDPR
Encrypt the users' web cookies and detect the anomaly cookies. 

This encryption used SHA 256 with MPC (Multi-Party Computation) protocol.
The next part of anomaly detection used Isolation Forest.

Implementaion Code
from sklearn.ensemble import IsolationForest

# Assuming X_train is your training data
iso_forest = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
iso_forest.fit(X_train)

# Predict anomalies in new data
anomaly_scores = iso_forest.decision_function(X_new)  # X_new is the new dataset
anomalies = iso_forest.predict(X_new)  # Returns -1 for anomalies, 1 for normal points
