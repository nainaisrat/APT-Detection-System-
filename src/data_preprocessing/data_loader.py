"""
Data Loader Module for APT Detection System
Handles loading and initial processing of network traffic datasets
"""

import pandas as pd
import numpy as np
import os
from typing import Tuple, Optional
import yaml
import logging
from pathlib import Path
import requests
import zipfile
import io

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DataLoader:
    """
    Handles loading of various network intrusion detection datasets
    Supports: CICIDS2017, NSL-KDD, and custom datasets
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """
        Initialize DataLoader with configuration
        
        Args:
            config_path: Path to configuration YAML file
        """
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.data_config = self.config['dataset']
        self.raw_data_path = Path(self.data_config['cicids2017_path']).parent
        self.processed_data_path = Path(self.data_config['processed_path'])
        
        # Create directories if they don't exist
        self.raw_data_path.mkdir(parents=True, exist_ok=True)
        self.processed_data_path.mkdir(parents=True, exist_ok=True)
        
    def download_nsl_kdd(self) -> bool:
        """
        Download NSL-KDD dataset from online source
        
        Returns:
            bool: True if successful, False otherwise
        """
        logger.info("Downloading NSL-KDD dataset...")
        
        urls = {
            'train': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt',
            'test': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt'
        }
        
        nsl_kdd_path = self.raw_data_path / 'NSL-KDD'
        nsl_kdd_path.mkdir(exist_ok=True)
        
        try:
            for name, url in urls.items():
                logger.info(f"Downloading {name} data...")
                response = requests.get(url)
                response.raise_for_status()
                
                filepath = nsl_kdd_path / f'KDD{name.capitalize()}+.txt'
                with open(filepath, 'wb') as f:
                    f.write(response.content)
                    
                logger.info(f"Saved {name} data to {filepath}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error downloading NSL-KDD dataset: {e}")
            return False
    
    def load_nsl_kdd(self, dataset_type: str = 'train') -> pd.DataFrame:
        """
        Load NSL-KDD dataset
        
        Args:
            dataset_type: 'train' or 'test'
            
        Returns:
            DataFrame with loaded data
        """
        # Column names for NSL-KDD dataset
        columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
            'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
            'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
            'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
            'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
            'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
            'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
            'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
            'label', 'difficulty'
        ]
        
        nsl_kdd_path = self.raw_data_path / 'NSL-KDD'
        
        # Download if not exists
        if not nsl_kdd_path.exists():
            logger.info("NSL-KDD dataset not found. Downloading...")
            self.download_nsl_kdd()
        
        filename = f'KDD{dataset_type.capitalize()}+.txt'
        filepath = nsl_kdd_path / filename
        
        logger.info(f"Loading NSL-KDD {dataset_type} data from {filepath}")
        
        try:
            df = pd.read_csv(filepath, names=columns, header=None)
            logger.info(f"Loaded {len(df)} samples from NSL-KDD {dataset_type} set")
            return df
            
        except FileNotFoundError:
            logger.error(f"File not found: {filepath}")
            logger.info("Attempting to download...")
            if self.download_nsl_kdd():
                df = pd.read_csv(filepath, names=columns, header=None)
                return df
            else:
                raise
    
    def load_cicids2017(self, day: Optional[str] = None) -> pd.DataFrame:
        """
        Load CICIDS2017 dataset
        
        Args:
            day: Specific day to load (e.g., 'Monday', 'Tuesday')
                 If None, loads all available data
                 
        Returns:
            DataFrame with loaded data
        """
        cicids_path = Path(self.data_config['cicids2017_path'])
        
        if not cicids_path.exists():
            logger.warning(f"CICIDS2017 path not found: {cicids_path}")
            logger.info("Please download CICIDS2017 dataset manually from:")
            logger.info("https://www.unb.ca/cic/datasets/ids-2017.html")
            logger.info(f"and extract to: {cicids_path}")
            return pd.DataFrame()
        
        # Find all CSV files
        csv_files = list(cicids_path.glob('*.csv'))
        
        if not csv_files:
            logger.warning(f"No CSV files found in {cicids_path}")
            return pd.DataFrame()
        
        logger.info(f"Found {len(csv_files)} CSV files in CICIDS2017 dataset")
        
        # Load specific day or all data
        if day:
            csv_files = [f for f in csv_files if day in f.name]
            logger.info(f"Loading data for {day}")
        else:
            logger.info("Loading all CICIDS2017 data")
        
        dfs = []
        for csv_file in csv_files:
            try:
                logger.info(f"Loading {csv_file.name}...")
                df = pd.read_csv(csv_file, encoding='utf-8', low_memory=False)
                dfs.append(df)
            except Exception as e:
                logger.error(f"Error loading {csv_file.name}: {e}")
        
        if dfs:
            combined_df = pd.concat(dfs, ignore_index=True)
            logger.info(f"Loaded total {len(combined_df)} samples from CICIDS2017")
            return combined_df
        else:
            return pd.DataFrame()
    
    def create_sample_dataset(self, n_samples: int = 10000) -> pd.DataFrame:
        """
        Create a sample synthetic dataset for testing
        This is useful when actual datasets are not available
        
        Args:
            n_samples: Number of samples to generate
            
        Returns:
            DataFrame with synthetic network traffic data
        """
        logger.info(f"Creating synthetic dataset with {n_samples} samples...")
        
        np.random.seed(42)
        
        # Generate synthetic features
        data = {
            'duration': np.random.exponential(100, n_samples),
            'src_bytes': np.random.exponential(1000, n_samples),
            'dst_bytes': np.random.exponential(1000, n_samples),
            'count': np.random.poisson(10, n_samples),
            'srv_count': np.random.poisson(10, n_samples),
            'serror_rate': np.random.uniform(0, 1, n_samples),
            'srv_serror_rate': np.random.uniform(0, 1, n_samples),
            'rerror_rate': np.random.uniform(0, 1, n_samples),
            'srv_rerror_rate': np.random.uniform(0, 1, n_samples),
            'same_srv_rate': np.random.uniform(0, 1, n_samples),
            'diff_srv_rate': np.random.uniform(0, 1, n_samples),
            'dst_host_count': np.random.poisson(50, n_samples),
            'dst_host_srv_count': np.random.poisson(20, n_samples),
        }
        
        df = pd.DataFrame(data)
        
        # Add categorical features
        df['protocol_type'] = np.random.choice(['tcp', 'udp', 'icmp'], n_samples, p=[0.7, 0.2, 0.1])
        df['service'] = np.random.choice(['http', 'ftp', 'smtp', 'ssh', 'dns'], n_samples)
        df['flag'] = np.random.choice(['SF', 'S0', 'REJ', 'RSTR'], n_samples, p=[0.6, 0.2, 0.1, 0.1])
        
        # Generate labels (10% attacks for APT simulation)
        apt_attacks = ['reconnaissance', 'exploitation', 'lateral_movement', 
                       'command_control', 'exfiltration']
        
        attack_indices = np.random.choice(n_samples, int(n_samples * 0.1), replace=False)
        df['label'] = 'normal'
        df.loc[attack_indices, 'label'] = np.random.choice(apt_attacks, len(attack_indices))
        
        logger.info("Synthetic dataset created successfully")
        return df
    
    def get_data_statistics(self, df: pd.DataFrame) -> dict:
        """
        Get basic statistics about the dataset
        
        Args:
            df: Input DataFrame
            
        Returns:
            Dictionary with dataset statistics
        """
        stats = {
            'total_samples': len(df),
            'features': df.shape[1],
            'missing_values': df.isnull().sum().sum(),
            'duplicate_rows': df.duplicated().sum(),
        }
        
        if 'label' in df.columns:
            stats['label_distribution'] = df['label'].value_counts().to_dict()
            stats['attack_percentage'] = (df['label'] != 'normal').sum() / len(df) * 100
        
        return stats


def main():
    """
    Test the DataLoader class
    """
    # Initialize loader
    loader = DataLoader()
    
    # Try loading NSL-KDD
    print("\n" + "="*50)
    print("Testing NSL-KDD Dataset Loading")
    print("="*50)
    
    try:
        df_train = loader.load_nsl_kdd('train')
        df_test = loader.load_nsl_kdd('test')
        
        print(f"\nTraining set shape: {df_train.shape}")
        print(f"Test set shape: {df_test.shape}")
        
        print("\nTraining set statistics:")
        stats = loader.get_data_statistics(df_train)
        for key, value in stats.items():
            print(f"  {key}: {value}")
            
    except Exception as e:
        print(f"Error loading NSL-KDD: {e}")
        print("\nCreating synthetic dataset instead...")
        df_train = loader.create_sample_dataset(10000)
        df_test = loader.create_sample_dataset(2000)
    
    # Save processed data
    output_path = loader.processed_data_path
    df_train.to_csv(output_path / 'train_data.csv', index=False)
    df_test.to_csv(output_path / 'test_data.csv', index=False)
    
    print(f"\nData saved to {output_path}")
    print("\nFirst few rows of training data:")
    print(df_train.head())


if __name__ == "__main__":
    main()
