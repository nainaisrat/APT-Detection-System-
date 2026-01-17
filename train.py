"""
Main Training Pipeline for APT Detection System
Orchestrates the complete training workflow
"""

import sys
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
import logging
import yaml

# Add src to path
sys.path.append(str(Path(__file__).parent / 'src'))

from src.data_preprocessing.data_loader import DataLoader
from src.data_preprocessing.feature_engineering import FeatureEngineer
from src.models.random_forest_detector import RandomForestDetector
from src.models.lstm_detector import LSTMDetector

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TrainingPipeline:
    """
    Complete training pipeline for APT detection models
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize pipeline"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.data_config = self.config['dataset']
        self.loader = DataLoader(config_path)
        self.engineer = FeatureEngineer(config_path)
        
        # Storage for processed data
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.feature_names = None
        
    def load_data(self, use_synthetic: bool = False):
        """
        Load and prepare dataset
        
        Args:
            use_synthetic: Whether to use synthetic data
        """
        logger.info("="*60)
        logger.info("STEP 1: Loading Dataset")
        logger.info("="*60)
        
        if use_synthetic:
            logger.info("Using synthetic dataset...")
            df = self.loader.create_sample_dataset(10000)
        else:
            try:
                logger.info("Attempting to load NSL-KDD dataset...")
                df = self.loader.load_nsl_kdd('train')
                logger.info("Successfully loaded NSL-KDD dataset")
            except Exception as e:
                logger.warning(f"Could not load NSL-KDD: {e}")
                logger.info("Falling back to synthetic dataset...")
                df = self.loader.create_sample_dataset(10000)
        
        # Get statistics
        stats = self.loader.get_data_statistics(df)
        logger.info(f"Dataset Statistics:")
        for key, value in stats.items():
            logger.info(f"  {key}: {value}")
        
        return df
    
    def preprocess_data(self, df: pd.DataFrame):
        """
        Preprocess and engineer features
        
        Args:
            df: Raw DataFrame
        """
        logger.info("\n" + "="*60)
        logger.info("STEP 2: Data Preprocessing & Feature Engineering")
        logger.info("="*60)
        
        # Clean data
        logger.info("Cleaning data...")
        df = self.engineer.clean_data(df)
        
        # Process labels
        logger.info("Processing labels...")
        df, label_map = self.engineer.process_labels(df, binary=False)
        logger.info(f"Label mapping: {label_map}")
        
        # Encode categorical features
        logger.info("Encoding categorical features...")
        df = self.engineer.encode_categorical_features(df, fit=True)
        
        # Create new features
        logger.info("Creating time-based features...")
        df = self.engineer.create_time_based_features(df)
        
        logger.info("Creating statistical features...")
        df = self.engineer.create_statistical_features(df)
        
        logger.info("Creating APT-specific features...")
        df = self.engineer.create_apt_specific_features(df)
        
        # Scale features
        logger.info("Scaling features...")
        df = self.engineer.scale_features(df, fit=True)
        
        logger.info(f"Final feature count: {df.shape[1]}")
        
        # Save preprocessors
        self.engineer.save_preprocessors()
        
        return df
    
    def split_data(self, df: pd.DataFrame):
        """
        Split data into train and test sets
        
        Args:
            df: Processed DataFrame
        """
        logger.info("\n" + "="*60)
        logger.info("STEP 3: Splitting Data")
        logger.info("="*60)
        
        # Separate features and labels
        label_col = 'label_encoded' if 'label_encoded' in df.columns else 'label_binary'
        
        X = df.drop(columns=[col for col in df.columns if 'label' in col])
        y = df[label_col]
        
        self.feature_names = X.columns.tolist()
        
        # Split data
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y,
            test_size=self.data_config['test_size'],
            random_state=self.data_config['random_state'],
            stratify=y
        )
        
        logger.info(f"Training samples: {len(self.X_train)}")
        logger.info(f"Test samples: {len(self.X_test)}")
        logger.info(f"Number of features: {X.shape[1]}")
        
        # Save processed data
        processed_path = Path(self.data_config['processed_path'])
        processed_path.mkdir(parents=True, exist_ok=True)
        
        pd.DataFrame(self.X_train, columns=self.feature_names).to_csv(
            processed_path / 'X_train.csv', index=False
        )
        pd.DataFrame(self.X_test, columns=self.feature_names).to_csv(
            processed_path / 'X_test.csv', index=False
        )
        pd.DataFrame(self.y_train).to_csv(processed_path / 'y_train.csv', index=False)
        pd.DataFrame(self.y_test).to_csv(processed_path / 'y_test.csv', index=False)
        
        logger.info(f"Saved processed data to {processed_path}")
    
    def train_random_forest(self):
        """Train Random Forest model"""
        logger.info("\n" + "="*60)
        logger.info("STEP 4: Training Random Forest Model")
        logger.info("="*60)
        
        # Initialize detector
        rf_detector = RandomForestDetector()
        
        # Train
        rf_detector.train(self.X_train.values, self.y_train.values)
        
        # Evaluate
        metrics = rf_detector.evaluate(self.X_test.values, self.y_test.values)
        
        # Plot feature importance
        rf_detector.plot_feature_importance(
            feature_names=self.feature_names,
            top_n=20,
            save_path='results/metrics/rf_feature_importance.png'
        )
        
        # Save model
        rf_detector.save_model()
        
        logger.info("Random Forest training completed!")
        return rf_detector, metrics
    
    def train_lstm(self):
        """Train LSTM model"""
        logger.info("\n" + "="*60)
        logger.info("STEP 5: Training LSTM Model")
        logger.info("="*60)
        
        # Create sequences for LSTM
        sequence_length = 10
        
        # For LSTM, we need 3D input
        # We'll create sliding windows
        logger.info(f"Creating sequences of length {sequence_length}...")
        
        # Simple approach: reshape data into sequences
        # For demonstration, we'll treat each 10 consecutive samples as a sequence
        n_train_sequences = len(self.X_train) - sequence_length + 1
        n_test_sequences = len(self.X_test) - sequence_length + 1
        
        X_train_seq = np.array([
            self.X_train.values[i:i+sequence_length] 
            for i in range(n_train_sequences)
        ])
        y_train_seq = self.y_train.values[sequence_length-1:n_train_sequences+sequence_length-1]
        
        X_test_seq = np.array([
            self.X_test.values[i:i+sequence_length] 
            for i in range(n_test_sequences)
        ])
        y_test_seq = self.y_test.values[sequence_length-1:n_test_sequences+sequence_length-1]
        
        logger.info(f"Training sequences shape: {X_train_seq.shape}")
        logger.info(f"Test sequences shape: {X_test_seq.shape}")
        
        # Initialize detector
        lstm_detector = LSTMDetector()
        
        # Train
        lstm_detector.train(X_train_seq, y_train_seq, X_test_seq, y_test_seq)
        
        # Evaluate
        metrics = lstm_detector.evaluate(X_test_seq, y_test_seq)
        
        # Plot training history
        lstm_detector.plot_training_history(
            save_path='results/metrics/lstm_training_history.png'
        )
        
        # Save model
        lstm_detector.save_model()
        
        logger.info("LSTM training completed!")
        return lstm_detector, metrics
    
    def run(self, use_synthetic: bool = False, train_rf: bool = True, 
            train_lstm: bool = True):
        """
        Run complete training pipeline
        
        Args:
            use_synthetic: Whether to use synthetic data
            train_rf: Whether to train Random Forest
            train_lstm: Whether to train LSTM
        """
        logger.info("\n" + "="*60)
        logger.info("APT DETECTION SYSTEM - TRAINING PIPELINE")
        logger.info("="*60)
        
        # Load data
        df = self.load_data(use_synthetic=use_synthetic)
        
        # Preprocess
        df = self.preprocess_data(df)
        
        # Split data
        self.split_data(df)
        
        results = {}
        
        # Train models
        if train_rf:
            rf_detector, rf_metrics = self.train_random_forest()
            results['random_forest'] = rf_metrics
        
        if train_lstm:
            lstm_detector, lstm_metrics = self.train_lstm()
            results['lstm'] = lstm_metrics
        
        # Summary
        logger.info("\n" + "="*60)
        logger.info("TRAINING COMPLETE - RESULTS SUMMARY")
        logger.info("="*60)
        
        for model_name, metrics in results.items():
            logger.info(f"\n{model_name.upper()}:")
            for metric, value in metrics.items():
                logger.info(f"  {metric}: {value:.4f}")
        
        logger.info("\n" + "="*60)
        logger.info("All models saved to: results/models/")
        logger.info("Metrics saved to: results/metrics/")
        logger.info("="*60)
        
        return results


def main():
    """
    Main execution
    """
    # Initialize pipeline
    pipeline = TrainingPipeline()
    
    # Run training
    results = pipeline.run(
        use_synthetic=True,  # Set to False to use real datasets
        train_rf=True,
        train_lstm=True
    )
    
    print("\n✅ Training pipeline completed successfully!")
    print("📁 Check results/models/ for trained models")
    print("📊 Check results/metrics/ for evaluation plots")


if __name__ == "__main__":
    main()
