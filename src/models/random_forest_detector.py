"""
Random Forest Model for APT Detection
Implements ensemble tree-based classification
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (classification_report, confusion_matrix, 
                            accuracy_score, precision_score, recall_score, 
                            f1_score, roc_auc_score)
import yaml
import joblib
import logging
from pathlib import Path
from typing import Tuple, Dict
import matplotlib.pyplot as plt
import seaborn as sns

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RandomForestDetector:
    """
    Random Forest classifier for APT detection
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize with configuration"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.rf_config = self.config['models']['random_forest']
        self.model = None
        self.feature_importance = None
        
    def build_model(self):
        """Build Random Forest model with configured parameters"""
        logger.info("Building Random Forest model...")
        
        self.model = RandomForestClassifier(
            n_estimators=self.rf_config['n_estimators'],
            max_depth=self.rf_config['max_depth'],
            min_samples_split=self.rf_config['min_samples_split'],
            min_samples_leaf=self.rf_config['min_samples_leaf'],
            random_state=self.rf_config['random_state'],
            n_jobs=self.rf_config['n_jobs'],
            verbose=1
        )
        
        logger.info(f"Model parameters: {self.model.get_params()}")
        return self.model
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray):
        """
        Train the Random Forest model
        
        Args:
            X_train: Training features
            y_train: Training labels
        """
        if self.model is None:
            self.build_model()
        
        logger.info(f"Training Random Forest on {len(X_train)} samples...")
        logger.info(f"Features shape: {X_train.shape}")
        logger.info(f"Labels shape: {y_train.shape}")
        
        # Train model
        self.model.fit(X_train, y_train)
        
        # Store feature importance
        self.feature_importance = self.model.feature_importances_
        
        logger.info("Training completed!")
        
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Make predictions
        
        Args:
            X: Features to predict on
            
        Returns:
            Predicted labels
        """
        if self.model is None:
            raise ValueError("Model not trained yet!")
        
        return self.model.predict(X)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Get prediction probabilities
        
        Args:
            X: Features to predict on
            
        Returns:
            Prediction probabilities
        """
        if self.model is None:
            raise ValueError("Model not trained yet!")
        
        return self.model.predict_proba(X)
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """
        Evaluate model performance
        
        Args:
            X_test: Test features
            y_test: True labels
            
        Returns:
            Dictionary with evaluation metrics
        """
        logger.info("Evaluating Random Forest model...")
        
        # Predictions
        y_pred = self.predict(X_test)
        y_pred_proba = self.predict_proba(X_test)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        
        # ROC AUC (for binary classification or OvR for multi-class)
        try:
            if len(np.unique(y_test)) == 2:
                roc_auc = roc_auc_score(y_test, y_pred_proba[:, 1])
            else:
                roc_auc = roc_auc_score(y_test, y_pred_proba, 
                                       multi_class='ovr', average='weighted')
        except:
            roc_auc = 0.0
        
        metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'roc_auc': roc_auc
        }
        
        # Print results
        logger.info("\n" + "="*50)
        logger.info("Random Forest Performance Metrics")
        logger.info("="*50)
        for metric, value in metrics.items():
            logger.info(f"{metric.upper()}: {value:.4f}")
        
        # Classification report
        logger.info("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        return metrics
    
    def plot_feature_importance(self, feature_names: list = None, 
                               top_n: int = 20, 
                               save_path: str = None):
        """
        Plot feature importance
        
        Args:
            feature_names: List of feature names
            top_n: Number of top features to display
            save_path: Path to save plot
        """
        if self.feature_importance is None:
            logger.warning("No feature importance available. Train model first.")
            return
        
        # Create DataFrame
        if feature_names is None:
            feature_names = [f"Feature_{i}" for i in range(len(self.feature_importance))]
        
        importance_df = pd.DataFrame({
            'feature': feature_names,
            'importance': self.feature_importance
        }).sort_values('importance', ascending=False).head(top_n)
        
        # Plot
        plt.figure(figsize=(12, 8))
        sns.barplot(data=importance_df, x='importance', y='feature', palette='viridis')
        plt.title(f'Top {top_n} Feature Importance - Random Forest', fontsize=16, fontweight='bold')
        plt.xlabel('Importance Score', fontsize=12)
        plt.ylabel('Features', fontsize=12)
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"Feature importance plot saved to {save_path}")
        
        plt.show()
    
    def plot_confusion_matrix(self, y_test: np.ndarray, y_pred: np.ndarray = None,
                             labels: list = None, save_path: str = None):
        """
        Plot confusion matrix
        
        Args:
            y_test: True labels
            y_pred: Predicted labels (if None, will predict)
            labels: Class labels
            save_path: Path to save plot
        """
        if y_pred is None:
            y_pred = self.predict(y_test)
        
        # Compute confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        
        # Plot
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=labels, yticklabels=labels)
        plt.title('Confusion Matrix - Random Forest', fontsize=16, fontweight='bold')
        plt.ylabel('True Label', fontsize=12)
        plt.xlabel('Predicted Label', fontsize=12)
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"Confusion matrix saved to {save_path}")
        
        plt.show()
    
    def save_model(self, filepath: str = "results/models/random_forest_model.pkl"):
        """
        Save trained model
        
        Args:
            filepath: Path to save model
        """
        if self.model is None:
            logger.warning("No model to save!")
            return
        
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        joblib.dump(self.model, filepath)
        logger.info(f"Model saved to {filepath}")
        
        # Also save feature importance
        if self.feature_importance is not None:
            importance_path = filepath.parent / "rf_feature_importance.npy"
            np.save(importance_path, self.feature_importance)
            logger.info(f"Feature importance saved to {importance_path}")
    
    def load_model(self, filepath: str = "results/models/random_forest_model.pkl"):
        """
        Load trained model
        
        Args:
            filepath: Path to model file
        """
        filepath = Path(filepath)
        
        if not filepath.exists():
            logger.error(f"Model file not found: {filepath}")
            return False
        
        self.model = joblib.load(filepath)
        logger.info(f"Model loaded from {filepath}")
        
        # Load feature importance if available
        importance_path = filepath.parent / "rf_feature_importance.npy"
        if importance_path.exists():
            self.feature_importance = np.load(importance_path)
            logger.info(f"Feature importance loaded from {importance_path}")
        
        return True


def main():
    """
    Test Random Forest detector
    """
    from sklearn.model_selection import train_test_split
    from sklearn.datasets import make_classification
    
    print("\n" + "="*50)
    print("Testing Random Forest APT Detector")
    print("="*50)
    
    # Create synthetic dataset
    print("\n1. Creating synthetic dataset...")
    X, y = make_classification(
        n_samples=10000,
        n_features=30,
        n_informative=20,
        n_redundant=5,
        n_classes=5,
        random_state=42
    )
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    print(f"   Training samples: {len(X_train)}")
    print(f"   Test samples: {len(X_test)}")
    
    # Initialize detector
    print("\n2. Initializing Random Forest detector...")
    detector = RandomForestDetector()
    
    # Train model
    print("\n3. Training model...")
    detector.train(X_train, y_train)
    
    # Evaluate
    print("\n4. Evaluating model...")
    metrics = detector.evaluate(X_test, y_test)
    
    # Plot feature importance
    print("\n5. Generating visualizations...")
    detector.plot_feature_importance(top_n=15)
    
    # Save model
    print("\n6. Saving model...")
    detector.save_model()
    
    print("\n" + "="*50)
    print("Random Forest detector testing completed!")
    print("="*50)


if __name__ == "__main__":
    main()
