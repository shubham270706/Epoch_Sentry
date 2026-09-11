import pandas as pd
import math
import matplotlib.pyplot as plt
import seaborn as sns
import os
import joblib
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# 1. MATHEMATICAL FEATURE EXTRACTION
def calculate_entropy(text):
    """Calculates Shannon Entropy to detect DNS tunneling and DGA domains."""
    if pd.isna(text) or text == '-' or text == 'None':
        return 0.0
    text = str(text)
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return -sum(p * math.log(p, 2) for p in prob)

def read_zeek_log(file_path):
    """Dynamically extracts column names from Zeek's header so they never misalign."""
    with open(file_path, 'r') as f:
        for line in f:
            if line.startswith("#fields"):
                # Extract all column names, ignoring the literal '#fields' tag
                cols = line.strip().split('\t')[1:]
                break
    
    # Read the data and apply the dynamic headers
    return pd.read_csv(file_path, sep='\t', comment='#', names=cols, low_memory=False)

def load_and_merge_zeek(directory, is_threat):
    """Loads conn, dns, and ssl logs dynamically and merges them by UID."""
    
    # 1. LOAD CONN.LOG
    conn_path = os.path.join(directory, "conn.log")
    df_conn = read_zeek_log(conn_path)
    
    # Clean Zeek's empty '-' values to 0 before converting to math types
    df_conn.replace('-', 0, inplace=True)
    df_conn[["duration", "orig_bytes", "resp_bytes"]] = df_conn[["duration", "orig_bytes", "resp_bytes"]].astype(float)
    
    # 2. LOAD DNS.LOG
    dns_path = os.path.join(directory, "dns.log")
    if os.path.exists(dns_path) and os.path.getsize(dns_path) > 0:
        df_dns = read_zeek_log(dns_path)
        # Merge only what we need on the unique connection ID
        df_conn = pd.merge(df_conn, df_dns[['uid', 'query']], on='uid', how='left')
    else:
        df_conn['query'] = 'None'

    # 3. LOAD SSL.LOG
    ssl_path = os.path.join(directory, "ssl.log")
    if os.path.exists(ssl_path) and os.path.getsize(ssl_path) > 0:
        df_ssl = read_zeek_log(ssl_path)
        df_conn = pd.merge(df_conn, df_ssl[['uid', 'cipher', 'server_name']], on='uid', how='left')
    else:
        df_conn['cipher'] = 'None'
        df_conn['server_name'] = 'None'

    # 4. FEATURE ENGINEERING
    
    # Req F: Unidirectional Data Exfiltration (Byte Ratio)
    df_conn['byte_ratio'] = df_conn['orig_bytes'] / (df_conn['resp_bytes'] + 1)
    
    # Req E: Port Scanning (Map failed connection states)
    state_mapping = {'SF': 0, 'S0': 1, 'REJ': 1, 'RSTR': 1, 'RSTO': 1, 'SH': 1}
    df_conn['failed_state_flag'] = df_conn['conn_state'].map(state_mapping).fillna(0)
    
    # Req C & D: Entropy for DNS Tunneling & Encrypted Malware
    df_conn['query'] = df_conn['query'].fillna('None')
    df_conn['dns_query_entropy'] = df_conn['query'].apply(calculate_entropy)
    
    df_conn['server_name'] = df_conn['server_name'].fillna('None')
    df_conn['sni_entropy'] = df_conn['server_name'].apply(calculate_entropy)
    
    # Assign the Label
    df_conn['is_threat'] = is_threat
    
    return df_conn

def build_pipeline():
    # Dynamically find the exact folder this script is sitting in
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    
    # Build absolute paths to the log folders
    malicious_dir = os.path.join(BASE_DIR, "malicious")
    benign_dir = os.path.join(BASE_DIR, "benign")
    
    print(f"Reading malicious logs from: {malicious_dir}")
    df_malicious = load_and_merge_zeek(malicious_dir, is_threat=1)
    
    print(f"Reading benign logs from: {benign_dir}")
    df_benign = load_and_merge_zeek(benign_dir, is_threat=0)
    
    print("Balancing Dataset to 75/25...")
    # 75% Benign means it must be exactly 3 times the size of the 25% Malicious data
    target_benign_count = len(df_malicious) * 3
    df_benign_shrunk = df_benign.sample(n=target_benign_count, random_state=42)
    
    df_final = pd.concat([df_benign_shrunk, df_malicious])
    
    # Encode categorical text (like cipher suites) into numbers
    print("Encoding Cipher Suites...")
    df_final['cipher'] = df_final['cipher'].fillna('None')
    encoder = LabelEncoder()
    df_final['cipher_encoded'] = encoder.fit_transform(df_final['cipher'])
    
    # Save the encoder so you can decode live traffic later
    encoder_path = os.path.join(BASE_DIR, "cipher_encoder.pkl")
    joblib.dump(encoder, encoder_path)
    
    # Select final numerical features for training
    features = ['duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts',
                'byte_ratio', 'failed_state_flag', 'dns_query_entropy', 
                'sni_entropy', 'cipher_encoded']
    
    X = df_final[features].fillna(0)
    y = df_final['is_threat']
    
    print(f"Dataset Ready: {len(X)} total flows (75/25 split).")
    
    # MODEL TRAINING
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    
    print("Training Random Forest Classifier...")
    # class_weight='balanced' forces the model to pay extra attention to the 25% minority class
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced')
    clf.fit(X_train, y_train)
    
    # EVALUATION
    predictions = clf.predict(X_test)
    print("\n--- Model Evaluation ---")
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print("\nClassification Report:\n", classification_report(y_test, predictions))
    
    # EXPORT
    model_path = os.path.join(BASE_DIR, "epoch_sentry_model.pkl")
    joblib.dump(clf, model_path)
    print(f"Model successfully exported to {model_path}!")

    print("\nGenerating Feature Importance Chart...")
    
    # Extract the mathematical weights the AI assigned to each feature
    importances = clf.feature_importances_
    
    # Create a DataFrame to sort them from most to least important
    feature_df = pd.DataFrame({
        'Feature': features,
        'Importance': importances
    }).sort_values(by='Importance', ascending=False)

    # Plot the chart
    plt.figure(figsize=(10, 6))
    sns.barplot(x='Importance', y='Feature', data=feature_df, palette='viridis')
    plt.title('Epoch Sentry: AI Feature Importances for Threat Detection')
    plt.xlabel('Impact on AI Decision (Percentage)')
    plt.ylabel('Zeek Log Feature')
    plt.tight_layout()
    
    # Save the chart as an image for your presentation
    chart_path = os.path.join(BASE_DIR, "feature_importance.png")
    plt.savefig(chart_path)
    print(f"Chart saved successfully to {chart_path}!")
if __name__ == "__main__":
    build_pipeline()