import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import os

# Constants
import os
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')
ENCODERS_PATH = os.path.join(os.path.dirname(__file__), 'encoders.pkl')
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

# Feature columns to use for training
# Using column indices for UNSW-NB15 dataset
NUMERIC_FEATURES = list(range(5, 42))  # Columns 5-41 for numeric features
CATEGORICAL_FEATURES = [1, 2, 3]  # Protocol, service, state
TARGET = 43  # Label column (assuming attack_cat is at index 43)

# Column names for reference (not used in code, just for documentation)
COLUMN_NAMES = [
    'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes',
    'sttl', 'dttl', 'sloss', 'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts',
    'swin', 'dwin', 'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len',
    'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 'tcprtt', 'synack', 'ackdat',
    'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd',
    'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm',
    'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'label'
]

def load_data():
    """Load and combine dataset files."""
    dataset_files = [f for f in os.listdir(DATA_DIR) if f.startswith('UNSW-NB15_') and f.endswith('.csv')]
    if not dataset_files:
        raise FileNotFoundError(f"No dataset files found in {DATA_DIR}")
    
    print(f"Found {len(dataset_files)} dataset files. Loading...")
    dfs = []
    for file in dataset_files:
        # Load data without header, we'll add column names manually
        df = pd.read_csv(os.path.join(DATA_DIR, file), header=None)
        dfs.append(df)
    
    # Combine all dataframes
    df = pd.concat(dfs, ignore_index=True)
    print(f"Loaded {len(df)} total samples")
    
    # Add column names (simplified for the example)
    # In a real scenario, you'd want to map these to meaningful names
    df.columns = [f'col_{i}' for i in range(len(df.columns))]
    
    return df

def preprocess_data(df):
    """Preprocess the dataset."""
    print("Preprocessing data...")
    
    # Convert column names to strings for easier handling
    df.columns = [str(i) for i in range(len(df.columns))]
    
    # For this example, we'll use a simple binary classification:
    # 0 for normal traffic, 1 for any type of attack
    # The label is in the last column (assuming it's column 43)
    df['label'] = (df[df.columns[-1]] != 'Normal').astype(int)
    
    # Select only the columns we need
    features = [str(i) for i in NUMERIC_FEATURES + CATEGORICAL_FEATURES]
    X = df[features].copy()
    y = df['label']
    
    # Convert all columns to numeric, coercing errors
    for col in features:
        X[col] = pd.to_numeric(X[col], errors='coerce')
    
    # Fill any remaining NaN values with 0
    X = X.fillna(0)
    
    # Scale the features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    return X_scaled, y, {'scaler': scaler, 'feature_names': features}

def train_model(X, y):
    """Train the Random Forest classifier."""
    print("Training model...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1,
        verbose=1
    )
    
    model.fit(X_train, y_train)
    
    # Calculate training accuracy
    train_acc = model.score(X_train, y_train)
    test_acc = model.score(X_test, y_test)
    print(f"Training accuracy: {train_acc:.4f}")
    print(f"Test accuracy: {test_acc:.4f}")

    # Save the accuracy to a file
    with open("model_accuracy.txt", "w") as f:
        f.write(f"{test_acc:.4f}")
    
    return model

def save_artifacts(model, artifacts):
    """Save the trained model and artifacts."""
    print("Saving artifacts...")
    joblib.dump(model, MODEL_PATH)
    joblib.dump(artifacts, ENCODERS_PATH)
    print(f"Model saved to {MODEL_PATH}")
    print(f"Artifacts saved to {ENCODERS_PATH}")

def main():
    try:
        # Load data
        df = load_data()
        print(f"Loaded dataset with {len(df)} samples")
        
        # Preprocess data
        X, y, artifacts = preprocess_data(df)
        print(f"Preprocessed data shape: {X.shape}")
        print(f"Class distribution: {dict(zip(*np.unique(y, return_counts=True)))}")
        
        # Train model
        model = train_model(X, y)
        
        # Save artifacts
        save_artifacts(model, artifacts)
        
        print("Training completed successfully!")
        
    except Exception as e:
        print(f"Error during training: {str(e)}")
        import traceback
        traceback.print_exc()
        raise

if __name__ == "__main__":
    main()
