"""
LSTM Model for APT Detection
Implements deep learning-based sequence classification for detecting APT patterns
"""

import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, Dropout, Bidirectional
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint, ReduceLROnPlateau
from sklearn.metrics import classification_report, accuracy_score, f1_score
import yaml
import logging
from pathlib import Path
from typing import Tuple, Dict
import matplotlib.pyplot as plt

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LSTMDetector:
    """
    LSTM-based detector for APT attack sequences
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize with configuration"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.lstm_config = self.config['models']['lstm']
        self.model = None
        self.history = None
        
    def build_model(self, input_shape: Tuple, num_classes: int):
        """
        Build LSTM model architecture
        
        Args:
            input_shape: Shape of input data (sequence_length, features)
            num_classes: Number of output classes
        """
        logger.info("Building LSTM model...")
        logger.info(f"Input shape: {input_shape}")
        logger.info(f"Number of classes: {num_classes}")
        
        model = Sequential([
            # First Bidirectional LSTM layer
            Bidirectional(LSTM(
                units=self.lstm_config['units'][0],
                return_sequences=True,
                recurrent_dropout=self.lstm_config['recurrent_dropout']
            ), input_shape=input_shape),
            Dropout(self.lstm_config['dropout']),
            
            # Second LSTM layer
            Bidirectional(LSTM(
                units=self.lstm_config['units'][1],
                return_sequences=True,
                recurrent_dropout=self.lstm_config['recurrent_dropout']
            )),
            Dropout(self.lstm_config['dropout']),
            
            # Third LSTM layer
            LSTM(
                units=self.lstm_config['units'][2],
                recurrent_dropout=self.lstm_config['recurrent_dropout']
            ),
            Dropout(self.lstm_config['dropout']),
            
            # Dense layers
            Dense(64, activation='relu'),
            Dropout(0.3),
            Dense(32, activation='relu'),
            
            # Output layer
            Dense(num_classes, activation='softmax' if num_classes > 2 else 'sigmoid')
        ])
        
        # Compile model
        optimizer = keras.optimizers.Adam(learning_rate=self.lstm_config['learning_rate'])
        
        loss = 'sparse_categorical_crossentropy' if num_classes > 2 else 'binary_crossentropy'
        
        model.compile(
            optimizer=optimizer,
            loss=loss,
            metrics=['accuracy', tf.keras.metrics.Precision(), tf.keras.metrics.Recall()]
        )
        
        self.model = model
        
        # Print model summary
        logger.info("\nModel Summary:")
        model.summary()
        
        return model
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray,
             X_val: np.ndarray = None, y_val: np.ndarray = None):
        """
        Train the LSTM model
        
        Args:
            X_train: Training sequences (samples, sequence_length, features)
            y_train: Training labels
            X_val: Validation sequences (optional)
            y_val: Validation labels (optional)
        """
        if self.model is None:
            # Infer input shape and number of classes
            input_shape = (X_train.shape[1], X_train.shape[2])
            num_classes = len(np.unique(y_train))
            self.build_model(input_shape, num_classes)
        
        logger.info(f"Training LSTM on {len(X_train)} sequences...")
        logger.info(f"Input shape: {X_train.shape}")
        
        # Prepare validation data
        if X_val is None or y_val is None:
            validation_data = None
            logger.info("No validation data provided")
        else:
            validation_data = (X_val, y_val)
            logger.info(f"Validation data: {X_val.shape}")
        
        # Callbacks
        callbacks = [
            EarlyStopping(
                monitor='val_loss' if validation_data else 'loss',
                patience=10,
                restore_best_weights=True,
                verbose=1
            ),
            ModelCheckpoint(
                'results/models/lstm_best_model.h5',
                monitor='val_loss' if validation_data else 'loss',
                save_best_only=True,
                verbose=1
            ),
            ReduceLROnPlateau(
                monitor='val_loss' if validation_data else 'loss',
                factor=0.5,
                patience=5,
                min_lr=1e-7,
                verbose=1
            )
        ]
        
        # Train model
        self.history = self.model.fit(
            X_train, y_train,
            epochs=self.lstm_config['epochs'],
            batch_size=self.lstm_config['batch_size'],
            validation_data=validation_data,
            callbacks=callbacks,
            verbose=1
        )
        
        logger.info("Training completed!")
        
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Make predictions
        
        Args:
            X: Input sequences
            
        Returns:
            Predicted classes
        """
        if self.model is None:
            raise ValueError("Model not trained yet!")
        
        predictions = self.model.predict(X)
        
        # Convert probabilities to class predictions
        if predictions.shape[1] > 1:
            return np.argmax(predictions, axis=1)
        else:
            return (predictions > 0.5).astype(int).flatten()
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Get prediction probabilities
        
        Args:
            X: Input sequences
            
        Returns:
            Prediction probabilities
        """
        if self.model is None:
            raise ValueError("Model not trained yet!")
        
        return self.model.predict(X)
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """
        Evaluate model performance
        
        Args:
            X_test: Test sequences
            y_test: True labels
            
        Returns:
            Dictionary with evaluation metrics
        """
        logger.info("Evaluating LSTM model...")
        
        # Predictions
        y_pred = self.predict(X_test)
        
        # Metrics
        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average='weighted')
        
        # Keras evaluation
        test_loss, test_acc, test_precision, test_recall = self.model.evaluate(
            X_test, y_test, verbose=0
        )
        
        metrics = {
            'accuracy': accuracy,
            'f1_score': f1,
            'loss': test_loss,
            'precision': test_precision,
            'recall': test_recall
        }
        
        # Print results
        logger.info("\n" + "="*50)
        logger.info("LSTM Performance Metrics")
        logger.info("="*50)
        for metric, value in metrics.items():
            logger.info(f"{metric.upper()}: {value:.4f}")
        
        # Classification report
        logger.info("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        return metrics
    
    def plot_training_history(self, save_path: str = None):
        """
        Plot training history
        
        Args:
            save_path: Path to save plot
        """
        if self.history is None:
            logger.warning("No training history available")
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        
        # Accuracy
        axes[0, 0].plot(self.history.history['accuracy'], label='Train')
        if 'val_accuracy' in self.history.history:
            axes[0, 0].plot(self.history.history['val_accuracy'], label='Validation')
        axes[0, 0].set_title('Model Accuracy', fontsize=14, fontweight='bold')
        axes[0, 0].set_xlabel('Epoch')
        axes[0, 0].set_ylabel('Accuracy')
        axes[0, 0].legend()
        axes[0, 0].grid(True, alpha=0.3)
        
        # Loss
        axes[0, 1].plot(self.history.history['loss'], label='Train')
        if 'val_loss' in self.history.history:
            axes[0, 1].plot(self.history.history['val_loss'], label='Validation')
        axes[0, 1].set_title('Model Loss', fontsize=14, fontweight='bold')
        axes[0, 1].set_xlabel('Epoch')
        axes[0, 1].set_ylabel('Loss')
        axes[0, 1].legend()
        axes[0, 1].grid(True, alpha=0.3)
        
        # Precision
        axes[1, 0].plot(self.history.history['precision'], label='Train')
        if 'val_precision' in self.history.history:
            axes[1, 0].plot(self.history.history['val_precision'], label='Validation')
        axes[1, 0].set_title('Model Precision', fontsize=14, fontweight='bold')
        axes[1, 0].set_xlabel('Epoch')
        axes[1, 0].set_ylabel('Precision')
        axes[1, 0].legend()
        axes[1, 0].grid(True, alpha=0.3)
        
        # Recall
        axes[1, 1].plot(self.history.history['recall'], label='Train')
        if 'val_recall' in self.history.history:
            axes[1, 1].plot(self.history.history['val_recall'], label='Validation')
        axes[1, 1].set_title('Model Recall', fontsize=14, fontweight='bold')
        axes[1, 1].set_xlabel('Epoch')
        axes[1, 1].set_ylabel('Recall')
        axes[1, 1].legend()
        axes[1, 1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"Training history plot saved to {save_path}")
        
        plt.show()
    
    def save_model(self, filepath: str = "results/models/lstm_model.h5"):
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
        
        self.model.save(filepath)
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str = "results/models/lstm_model.h5"):
        """
        Load trained model
        
        Args:
            filepath: Path to model file
        """
        filepath = Path(filepath)
        
        if not filepath.exists():
            logger.error(f"Model file not found: {filepath}")
            return False
        
        self.model = load_model(filepath)
        logger.info(f"Model loaded from {filepath}")
        return True


def main():
    """
    Test LSTM detector
    """
    print("\n" + "="*50)
    print("Testing LSTM APT Detector")
    print("="*50)
    
    # Create synthetic sequence data
    print("\n1. Creating synthetic sequence dataset...")
    
    n_samples = 1000
    sequence_length = 10
    n_features = 20
    n_classes = 5
    
    # Generate random sequences
    X = np.random.randn(n_samples, sequence_length, n_features)
    y = np.random.randint(0, n_classes, n_samples)
    
    # Split data
    split_idx = int(0.8 * n_samples)
    X_train, X_test = X[:split_idx], X[split_idx:]
    y_train, y_test = y[:split_idx], y[split_idx:]
    
    print(f"   Training sequences: {X_train.shape}")
    print(f"   Test sequences: {X_test.shape}")
    
    # Initialize detector
    print("\n2. Initializing LSTM detector...")
    detector = LSTMDetector()
    
    # Train model
    print("\n3. Training model...")
    detector.train(X_train, y_train)
    
    # Evaluate
    print("\n4. Evaluating model...")
    metrics = detector.evaluate(X_test, y_test)
    
    # Plot training history
    print("\n5. Generating visualizations...")
    detector.plot_training_history()
    
    # Save model
    print("\n6. Saving model...")
    detector.save_model()
    
    print("\n" + "="*50)
    print("LSTM detector testing completed!")
    print("="*50)


if __name__ == "__main__":
    main()
