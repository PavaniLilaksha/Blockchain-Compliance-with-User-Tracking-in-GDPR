# Blockchain-Compliance-with-User-Tracking-in-GDPR
Encrypt the users' web cookies and detect the anomaly cookies. 

This encryption used SHA 256 with MPC (Multi-Party Computation) protocol.
The next part of anomaly detection used Isolation Forest.

1. Core Concept: Isolation
The fundamental idea behind Isolation Forest is that anomalies are "few and different." Anomalies are points that are less frequent and more distinct compared to the normal data points. Because of these characteristics, anomalies are easier to isolate.

2. Building Isolation Trees
Isolation Forest creates an ensemble of decision trees, known as Isolation Trees (iTrees), to isolate data points. Here's how these trees are constructed:

Random Partitioning:

For each tree, the algorithm randomly selects a feature (dimension) from the dataset.
Then, it randomly selects a split value between the minimum and maximum values of the chosen feature.
Recursive Splitting:

The dataset is recursively split into two partitions based on the chosen feature and split value.
This process continues until every data point is isolated, i.e., the data point is alone in its partition or until a maximum tree depth is reached.
Isolation Path Length:

The path length for a data point is defined as the number of splits (or nodes) required to isolate the point.
Anomalies, being different from the majority of data points, tend to have shorter path lengths because they can be isolated with fewer splits.
In contrast, normal points, being similar to each other, require more splits to be isolated and thus have longer path lengths.
3. Anomaly Scoring
Once the Isolation Forest is built, each data point is scored based on how easily it was isolated across all the trees in the forest:

Average Path Length:

The average path length is calculated for each data point across all trees in the forest.
A data point with a short average path length is likely an anomaly, while a data point with a long path length is likely normal.
Anomaly Score Calculation:

The anomaly score for a data point is derived from its average path length.
The score typically ranges from 0 to 1:
Scores close to 1 indicate anomalies (short path lengths).
Scores closer to 0 suggest normal points (longer path lengths).
The anomaly score can be computed as:
𝑠
(
𝑥
,
𝑛
)
=
2
−
𝐸
(
ℎ
(
𝑥
)
)
𝑐
(
𝑛
)
s(x,n)=2 
− 
c(n)
E(h(x))
​
 
 
where:
𝑠
(
𝑥
,
𝑛
)
s(x,n) is the anomaly score of point 
𝑥
x with 
𝑛
n data points.
𝐸
(
ℎ
(
𝑥
)
)
E(h(x)) is the average path length for point 
𝑥
x.
𝑐
(
𝑛
)
c(n) is the average path length of an unsuccessful search in a Binary Search Tree, used to normalize the path length.
4. Thresholding
After scoring, a threshold can be set to classify points as normal or anomalous based on their anomaly score.
For example, you might classify all points with a score above 0.7 as anomalies.
5. Advantages of Isolation Forest
Efficiency: Isolation Forest is highly efficient in terms of both time and memory, making it suitable for large datasets.
No Need for Distance Measures: Unlike other anomaly detection methods, Isolation Forest does not rely on distance or density measures, which can be computationally expensive.
Robustness: It performs well on high-dimensional data and is less sensitive to scaling and transformation of the data.
6. Application Example
Let's say you have a dataset of user activity logs, and you want to detect unusual behaviors that might indicate a security breach:

Feature Engineering: You extract features such as login frequency, duration of sessions, IP address locations, and so on.
Model Training: You train the Isolation Forest model on this data.
Anomaly Detection: As new user activity data comes in, you apply the trained Isolation Forest to score the data and identify any sessions that are significantly different from typical behavior (anomalies).

Implementaion Code
from sklearn.ensemble import IsolationForest

# Assuming X_train is your training data
iso_forest = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
iso_forest.fit(X_train)

# Predict anomalies in new data
anomaly_scores = iso_forest.decision_function(X_new)  # X_new is the new dataset
anomalies = iso_forest.predict(X_new)  # Returns -1 for anomalies, 1 for normal points
