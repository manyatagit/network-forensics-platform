import pandas as pd
from sklearn.ensemble import IsolationForest

def analyze_traffic(packets: list):
    """Scores anomalies using Isolation Forest."""
    if not packets:
        return []

    df = pd.DataFrame(packets)

    # Feature extraction using length and ports
    feature_columns = ['length', 'dst_port', 'src_port']
    X = df[feature_columns].fillna(0)

    # Contamination dictates what percentage of traffic is flagged as anomalous
    model = IsolationForest(contamination=0.08, random_state=42)
    predictions = model.fit_predict(X)

    # Isolation Forest outputs: -1 for anomaly, 1 for normal
    df['is_anomalous'] = [True if pred == -1 else False for pred in predictions]

    return df.to_dict(orient="records")