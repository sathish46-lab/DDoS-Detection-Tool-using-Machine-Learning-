import pandas as pd
import numpy as np

# Generate sample data for the CSV
num_rows = 100  # Number of rows in your sample dataset
data = {
    'Src IP': np.random.choice(['192.168.0.1', '10.0.0.5', '172.16.0.2'], num_rows),
    'Fwd Pkt Len Mean': np.random.rand(num_rows) * 1000,
    'Fwd Seg Size Avg': np.random.rand(num_rows) * 500,
    'Pkt Len Min': np.random.rand(num_rows) * 200,
    'Fwd Pkt Len Min': np.random.rand(num_rows) * 100,
    'Pkt Len Mean': np.random.rand(num_rows) * 1500,
    'Protocol': np.random.choice([6, 17], num_rows),  # 6 for TCP, 17 for UDP
    'Fwd Act Data Pkts': np.random.randint(0, 10, num_rows),
    'Pkt Size Avg': np.random.rand(num_rows) * 1400,
    'Tot Fwd Pkts': np.random.randint(0, 100, num_rows),
    'Subflow Fwd Pkts': np.random.randint(0, 100, num_rows),
    'Dst Port': np.random.randint(1024, 65535, num_rows),
}

# Convert to DataFrame and save as CSV
df = pd.DataFrame(data)
df.to_csv('traffic.pcap_Flow.csv', index=False)
print("Sample traffic.pcap_Flow.csv file created.")
