import scapy.all as scapy
import pandas as pd
import numpy as np
import joblib
import warnings
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

def convert_txt_to_csv(txt_path, csv_path):
    """ Convert a text file with domain names to a CSV file """
    with open(txt_path, "r") as f:
        domains = f.read().splitlines()
    
    df = pd.DataFrame(domains, columns=["domain"])
    df.to_csv(csv_path, index=False)
    print(f"Converted {txt_path} to {csv_path}")

def extract_features(domain_name):
    """ Extract features from a DNS query """
    return {
        'domain_length': len(domain_name),
        'num_subdomains': domain_name.count('.'),
        'entropy': -sum(p * np.log2(p) for p in pd.Series(list(domain_name)).value_counts(normalize=True)),
        'special_chars': sum(c in '!@#$%^&*()_+=<>?' for c in domain_name),
    }

def load_dataset(csv_path):
    """ Load a dataset of domain names from a CSV file """
    df = pd.read_csv(csv_path)
    if 'domain' not in df.columns:
        raise ValueError("CSV must contain a 'domain' column with domain names")
    
    # Extract Features
    feature_data = pd.DataFrame([extract_features(domain) for domain in df['domain']])
    return feature_data

def train_model(data):
    """ Train an Isolation Forest model """
    scaler = StandardScaler()
    data_scaled = scaler.fit_transform(data)
    model = IsolationForest(contamination=0.1)
    model.fit(data_scaled)
    joblib.dump((model, scaler), "dns_anomaly_model.pkl")
    print("Model saved successfully!")

def visualize_anomalies(data, anomalies):
    """ Visualize anomalies in the dataset """
    anomalies = anomalies.map({1: 'Normal', -1: 'Anomalous'})  

    plt.figure(figsize=(12, 5))
    
    # Scatter plot of Domain Length vs. Entropy
    plt.subplot(1, 2, 1)
    sns.scatterplot(x=data['domain_length'], y=data['entropy'], hue=anomalies, palette={'Normal': 'blue', 'Anomalous': 'red'})
    plt.xlabel("Domain Length")
    plt.ylabel("Entropy")
    plt.title("Feature Scatter Plot (Anomalies in Red)")
    
    # Bar chart of Anomaly Counts
    plt.subplot(1, 2, 2)
    sns.countplot(x=anomalies, palette={'Normal': 'blue', 'Anomalous': 'red'})
    plt.xlabel("Category")
    plt.ylabel("Count")
    plt.title("Anomaly Distribution")
    
    plt.show()



def detect_anomalies(real_time=False):
    """ Detect anomalies in real-time using Scapy """
    model, scaler = joblib.load("dns_anomaly_model.pkl")
    
    def process_packet(packet):
        if packet.haslayer(scapy.DNS) and packet[scapy.DNS].qr == 0:
            domain_name = packet[scapy.DNSQR].qname.decode('utf-8', errors='ignore')
            features = pd.DataFrame([extract_features(domain_name)])
            features_scaled = scaler.transform(features)
            prediction = model.predict(features_scaled)
            if prediction[0] == -1:
                print(f"[ALERT] Anomalous DNS Query: {domain_name}")
    
    if real_time:
        print("Monitoring real-time DNS traffic...")
        scapy.sniff(filter="udp port 53", prn=process_packet, store=False)
    else:
        print("Processing dataset for anomalies...")
        df = load_dataset("dns_dataset.csv")
        df_scaled = scaler.transform(df)
        df['anomaly'] = model.predict(df_scaled)
        visualize_anomalies(df, df['anomaly'])
        print(df[df['anomaly'] == -1])

if __name__ == "__main__":
    convert_txt_to_csv("opendns-top-domains.txt", "dns_dataset.csv")  
    dataset_path = "dns_dataset.csv"  
    sample_data = load_dataset(dataset_path)
    train_model(sample_data)
    detect_anomalies(real_time=False)
