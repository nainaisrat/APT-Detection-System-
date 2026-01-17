"""
Feature Engineering Module for APT Detection System
Handles feature extraction, transformation, and selection
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder, MinMaxScaler
from sklearn.feature_selection import SelectKBest, mutual_info_classif
import yaml
import logging
from typing import Tuple, List
import joblib
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FeatureEngineer:
    """
    Handles all feature engineering tasks for APT detection
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize with configuration"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.feature_config = self.config['features']
        self.scalers = {}
        self.encoders = {}
        
    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean the dataset by handling missing values and duplicates
        
        Args:
            df: Input DataFrame
            
        Returns:
            Cleaned DataFrame
        """
        logger.info("Cleaning data...")
        initial_rows = len(df)
        
        # Remove duplicates
        df = df.drop_duplicates()
        logger.info(f"Removed {initial_rows - len(df)} duplicate rows")
        
        # Handle missing values
        # For numerical columns: fill with median
        numerical_cols = df.select_dtypes(include=[np.number]).columns
        for col in numerical_cols:
            if df[col].isnull().any():
                df[col].fillna(df[col].median(), inplace=True)
        
        # For categorical columns: fill with mode
        categorical_cols = df.select_dtypes(include=['object']).columns
        for col in categorical_cols:
            if df[col].isnull().any():
                df[col].fillna(df[col].mode()[0], inplace=True)
        
        # Remove infinite values
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)
        
        logger.info(f"Data cleaned. Final shape: {df.shape}")
        return df
    
    def encode_categorical_features(self, df: pd.DataFrame, fit: bool = True) -> pd.DataFrame:
        """
        Encode categorical features using Label Encoding
        
        Args:
            df: Input DataFrame
            fit: Whether to fit encoders (True for training, False for test)
            
        Returns:
            DataFrame with encoded features
        """
        logger.info("Encoding categorical features...")
        
        categorical_cols = df.select_dtypes(include=['object']).columns
        categorical_cols = [col for col in categorical_cols if col != 'label']
        
        for col in categorical_cols:
            if fit:
                # Fit and transform
                self.encoders[col] = LabelEncoder()
                df[col] = self.encoders[col].fit_transform(df[col].astype(str))
            else:
                # Transform only
                if col in self.encoders:
                    # Handle unseen labels
                    df[col] = df[col].map(lambda x: x if x in self.encoders[col].classes_ 
                                         else self.encoders[col].classes_[0])
                    df[col] = self.encoders[col].transform(df[col].astype(str))
        
        logger.info(f"Encoded {len(categorical_cols)} categorical features")
        return df
    
    def create_time_based_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Create time-based features for sequence analysis
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with additional time-based features
        """
        logger.info("Creating time-based features...")
        
        if 'duration' in df.columns:
            # Duration-based features
            df['duration_log'] = np.log1p(df['duration'])
            df['is_short_connection'] = (df['duration'] < 1).astype(int)
            df['is_long_connection'] = (df['duration'] > 100).astype(int)
        
        return df
    
    def create_statistical_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Create statistical features from existing ones
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with additional statistical features
        """
        logger.info("Creating statistical features...")
        
        # Byte-related features
        if 'src_bytes' in df.columns and 'dst_bytes' in df.columns:
            df['total_bytes'] = df['src_bytes'] + df['dst_bytes']
            df['bytes_ratio'] = df['src_bytes'] / (df['dst_bytes'] + 1)
            df['bytes_diff'] = df['src_bytes'] - df['dst_bytes']
        
        # Count-based features
        if 'count' in df.columns and 'srv_count' in df.columns:
            df['count_ratio'] = df['count'] / (df['srv_count'] + 1)
        
        # Error rate features
        error_cols = [col for col in df.columns if 'error_rate' in col]
        if error_cols:
            df['avg_error_rate'] = df[error_cols].mean(axis=1)
            df['max_error_rate'] = df[error_cols].max(axis=1)
        
        return df
    
    def create_apt_specific_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Create features specifically designed for APT detection
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with APT-specific features
        """
        logger.info("Creating APT-specific features...")
        
        # Lateral movement indicators
        if all(col in df.columns for col in ['dst_host_count', 'dst_host_srv_count']):
            df['lateral_movement_score'] = (
                df['dst_host_count'] * df['dst_host_srv_count']
            ) / (df['count'] + 1)
        
        # Data exfiltration indicators
        if 'src_bytes' in df.columns:
            # Flag unusually large outbound transfers
            df['large_transfer_flag'] = (df['src_bytes'] > df['src_bytes'].quantile(0.95)).astype(int)
        
        # Command & Control indicators
        if 'same_srv_rate' in df.columns and 'diff_srv_rate' in df.columns:
            # Regular beaconing behavior
            df['beaconing_score'] = df['same_srv_rate'] - df['diff_srv_rate']
        
        # Reconnaissance indicators
        if 'dst_host_count' in df.columns:
            # Port scanning behavior
            df['scanning_score'] = np.log1p(df['dst_host_count'])
        
        return df
    
    def scale_features(self, df: pd.DataFrame, fit: bool = True, 
                      scaler_type: str = 'standard') -> pd.DataFrame:
        """
        Scale numerical features
        
        Args:
            df: Input DataFrame
            fit: Whether to fit scaler (True for training, False for test)
            scaler_type: 'standard' or 'minmax'
            
        Returns:
            DataFrame with scaled features
        """
        logger.info(f"Scaling features using {scaler_type} scaler...")
        
        # Get numerical columns (excluding label)
        numerical_cols = df.select_dtypes(include=[np.number]).columns
        numerical_cols = [col for col in numerical_cols if col not in ['label', 'difficulty']]
        
        if fit:
            # Create and fit scaler
            if scaler_type == 'standard':
                self.scalers['scaler'] = StandardScaler()
            else:
                self.scalers['scaler'] = MinMaxScaler()
            
            df[numerical_cols] = self.scalers['scaler'].fit_transform(df[numerical_cols])
        else:
            # Transform only
            if 'scaler' in self.scalers:
                df[numerical_cols] = self.scalers['scaler'].transform(df[numerical_cols])
        
        logger.info(f"Scaled {len(numerical_cols)} numerical features")
        return df
    
    def select_features(self, X: pd.DataFrame, y: pd.Series, 
                       k: int = 30) -> Tuple[pd.DataFrame, List[str]]:
        """
        Select top k features using mutual information
        
        Args:
            X: Feature DataFrame
            y: Target Series
            k: Number of features to select
            
        Returns:
            Tuple of (selected features DataFrame, list of selected feature names)
        """
        logger.info(f"Selecting top {k} features...")
        
        selector = SelectKBest(score_func=mutual_info_classif, k=k)
        X_selected = selector.fit_transform(X, y)
        
        # Get selected feature names
        selected_mask = selector.get_support()
        selected_features = X.columns[selected_mask].tolist()
        
        logger.info(f"Selected features: {selected_features}")
        
        return pd.DataFrame(X_selected, columns=selected_features), selected_features
    
    def process_labels(self, df: pd.DataFrame, binary: bool = False) -> Tuple[pd.DataFrame, dict]:
        """
        Process labels for training
        
        Args:
            df: Input DataFrame with 'label' column
            binary: If True, convert to binary classification (normal vs attack)
            
        Returns:
            Tuple of (DataFrame with processed labels, label mapping dictionary)
        """
        logger.info("Processing labels...")
        
        if 'label' not in df.columns:
            logger.error("No 'label' column found in DataFrame")
            return df, {}
        
        # Create a copy of labels
        labels = df['label'].copy()
        
        if binary:
            # Binary classification: normal vs attack
            df['label_binary'] = (labels != 'normal').astype(int)
            label_map = {0: 'normal', 1: 'attack'}
        else:
            # Multi-class classification
            label_encoder = LabelEncoder()
            df['label_encoded'] = label_encoder.fit_transform(labels)
            label_map = dict(zip(label_encoder.transform(label_encoder.classes_), 
                               label_encoder.classes_))
            self.encoders['label_encoder'] = label_encoder
        
        logger.info(f"Label distribution: {labels.value_counts().to_dict()}")
        return df, label_map
    
    def create_sequences(self, df: pd.DataFrame, sequence_length: int = 10) -> np.ndarray:
        """
        Create sequences for LSTM/RNN models
        
        Args:
            df: Input DataFrame
            sequence_length: Length of each sequence
            
        Returns:
            3D numpy array of shape (samples, sequence_length, features)
        """
        logger.info(f"Creating sequences of length {sequence_length}...")
        
        # Get numerical features
        numerical_cols = df.select_dtypes(include=[np.number]).columns
        numerical_cols = [col for col in numerical_cols if 'label' not in col]
        
        data = df[numerical_cols].values
        
        sequences = []
        for i in range(len(data) - sequence_length + 1):
            sequences.append(data[i:i + sequence_length])
        
        sequences = np.array(sequences)
        logger.info(f"Created {len(sequences)} sequences of shape {sequences.shape}")
        
        return sequences
    
    def save_preprocessors(self, output_path: str = "results/models"):
        """
        Save scalers and encoders for later use
        
        Args:
            output_path: Directory to save preprocessors
        """
        output_path = Path(output_path)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save scalers
        for name, scaler in self.scalers.items():
            filepath = output_path / f"{name}.pkl"
            joblib.dump(scaler, filepath)
            logger.info(f"Saved {name} to {filepath}")
        
        # Save encoders
        for name, encoder in self.encoders.items():
            filepath = output_path / f"{name}.pkl"
            joblib.dump(encoder, filepath)
            logger.info(f"Saved {name} to {filepath}")
    
    def load_preprocessors(self, input_path: str = "results/models"):
        """
        Load saved scalers and encoders
        
        Args:
            input_path: Directory containing saved preprocessors
        """
        input_path = Path(input_path)
        
        # Load all .pkl files
        for filepath in input_path.glob("*.pkl"):
            name = filepath.stem
            obj = joblib.load(filepath)
            
            if 'scaler' in name:
                self.scalers[name] = obj
            else:
                self.encoders[name] = obj
            
            logger.info(f"Loaded {name} from {filepath}")


def main():
    """
    Test the FeatureEngineer class
    """
    # Load sample data
    from data_loader import DataLoader
    
    loader = DataLoader()
    
    # Try to load real data, fallback to synthetic
    try:
        df = loader.load_nsl_kdd('train')
    except:
        logger.info("Creating synthetic dataset for testing...")
        df = loader.create_sample_dataset(5000)
    
    print("\n" + "="*50)
    print("Testing Feature Engineering Pipeline")
    print("="*50)
    
    # Initialize feature engineer
    engineer = FeatureEngineer()
    
    # Process data
    print("\n1. Cleaning data...")
    df = engineer.clean_data(df)
    print(f"   Shape after cleaning: {df.shape}")
    
    print("\n2. Processing labels...")
    df, label_map = engineer.process_labels(df, binary=False)
    print(f"   Label mapping: {label_map}")
    
    print("\n3. Encoding categorical features...")
    df = engineer.encode_categorical_features(df, fit=True)
    
    print("\n4. Creating time-based features...")
    df = engineer.create_time_based_features(df)
    
    print("\n5. Creating statistical features...")
    df = engineer.create_statistical_features(df)
    
    print("\n6. Creating APT-specific features...")
    df = engineer.create_apt_specific_features(df)
    
    print(f"\n   Total features after engineering: {df.shape[1]}")
    
    print("\n7. Scaling features...")
    df = engineer.scale_features(df, fit=True)
    
    # Save preprocessors
    print("\n8. Saving preprocessors...")
    engineer.save_preprocessors()
    
    print("\n9. Final dataset info:")
    print(f"   Shape: {df.shape}")
    print(f"   Features: {df.columns.tolist()}")
    
    # Save processed data
    output_path = Path("data/processed")
    output_path.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path / "engineered_features.csv", index=False)
    print(f"\n   Saved to {output_path / 'engineered_features.csv'}")


if __name__ == "__main__":
    main()
