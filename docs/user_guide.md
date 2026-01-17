# APT Detection System - User Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Training Models](#training-models)
5. [Using the Dashboard](#using-the-dashboard)
6. [API Reference](#api-reference)
7. [Troubleshooting](#troubleshooting)
8. [FAQ](#faq)

---

## Introduction

Welcome to the APT Detection System! This guide will help you set up, train, and use the system effectively.

### What is APT Detection?

Advanced Persistent Threats (APTs) are sophisticated cyber attacks that:
- Target specific organizations
- Operate stealthily over extended periods
- Progress through multiple attack stages
- Use advanced evasion techniques

### System Capabilities

✅ Detect APT patterns in network traffic  
✅ Identify attack progression through kill chain  
✅ Provide real-time monitoring and alerts  
✅ Generate detailed threat reports  
✅ Visualize attack patterns interactively  

---

## Installation

### Prerequisites

Before installing, ensure you have:
- **Python 3.8+** installed
- **8GB+ RAM** (16GB recommended)
- **10GB+ free disk space**
- **Internet connection** for dataset download

### Option 1: Automated Setup (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/apt-detection-system.git
cd apt-detection-system

# Run setup script
chmod +x setup.sh
./setup.sh
```

The script will:
1. Create virtual environment
2. Install all dependencies
3. Download datasets
4. Create necessary directories

### Option 2: Manual Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create directories
mkdir -p data/{raw,processed} results/{models,metrics,reports}
```

### Verify Installation

```bash
python -c "import tensorflow as tf; print('TensorFlow:', tf.__version__)"
python -c "import sklearn; print('Scikit-learn: OK')"
python -c "import streamlit; print('Streamlit: OK')"
```

---

## Quick Start

### 1. Train Your First Model

```bash
# Activate virtual environment
source venv/bin/activate

# Run training (uses synthetic data by default)
python train.py
```

**Expected Output:**
```
==========================================
APT DETECTION SYSTEM - TRAINING PIPELINE
==========================================

STEP 1: Loading Dataset
Creating synthetic dataset with 10000 samples...
✓ Dataset loaded

STEP 2: Data Preprocessing
Cleaning data...
✓ Data cleaned

STEP 3: Training Random Forest
Training Random Forest on 8000 samples...
✓ Model trained
Accuracy: 95.2%

STEP 4: Training LSTM
Creating sequences...
Training LSTM...
✓ Model trained
Accuracy: 93.1%

Training Complete!
Models saved to: results/models/
```

### 2. Launch the Dashboard

```bash
cd dashboard
streamlit run app.py
```

Open your browser to `http://localhost:8501`

### 3. Generate Detections

In the dashboard:
1. Click **"🔄 Generate New Detection"** button
2. View real-time threat analysis
3. Explore different visualizations
4. Check detection details table

---

## Training Models

### Training with Real Datasets

#### NSL-KDD Dataset (Automatic)

```python
from train import TrainingPipeline

pipeline = TrainingPipeline()
results = pipeline.run(
    use_synthetic=False,  # Use real NSL-KDD data
    train_rf=True,
    train_lstm=True
)
```

The system will automatically download NSL-KDD if not present.

#### CICIDS2017 Dataset (Manual Download)

1. Download from: https://www.unb.ca/cic/datasets/ids-2017.html
2. Extract to `data/raw/CICIDS2017/`
3. Update config:

```python
# In train.py, modify:
df = loader.load_cicids2017()  # Instead of load_nsl_kdd()
```

### Training Configuration

Edit `config/config.yaml` to customize:

```yaml
models:
  random_forest:
    n_estimators: 200      # Number of trees
    max_depth: 20          # Maximum tree depth
    
  lstm:
    units: [128, 64, 32]  # LSTM layer sizes
    epochs: 50             # Training epochs
    batch_size: 256        # Batch size
```

### Advanced Training Options

```python
pipeline = TrainingPipeline()

# Load data
df = pipeline.load_data(use_synthetic=False)

# Customize preprocessing
df = pipeline.preprocess_data(df)

# Split with custom ratio
pipeline.split_data(df)  # Uses config settings

# Train only specific models
rf_detector, rf_metrics = pipeline.train_random_forest()
# OR
lstm_detector, lstm_metrics = pipeline.train_lstm()
```

### Model Performance Monitoring

Training generates plots in `results/metrics/`:
- `rf_feature_importance.png` - Top features for Random Forest
- `lstm_training_history.png` - LSTM training curves

---

## Using the Dashboard

### Dashboard Layout

```
┌────────────────────────────────────────────┐
│         🛡️ APT Detection System            │
├────────────────────────────────────────────┤
│  [Metric 1] [Metric 2] [Metric 3] [Metric 4]
├────────────────────────────────────────────┤
│  ⚠️ SECURITY ALERT (if applicable)         │
├──────────────────┬─────────────────────────┤
│  Threat Gauge    │  Attack Distribution    │
├──────────────────┼─────────────────────────┤
│  Kill Chain      │  Threat Timeline        │
├──────────────────┴─────────────────────────┤
│  📋 Detection Details Table                 │
└────────────────────────────────────────────┘
```

### Key Features

#### 1. Threat Level Gauge
- **Low (Green)**: Normal operations
- **Medium (Yellow)**: Suspicious activity
- **High (Orange)**: Likely attack
- **Critical (Red)**: Active APT campaign

#### 2. Kill Chain Tracker
Shows which stages of the cyber kill chain are active:
- Reconnaissance
- Weaponization
- Delivery
- Exploitation
- Installation
- Command & Control
- Actions on Objectives

#### 3. Real-time Metrics
- **Total Detections**: Number of scans performed
- **Threat Level**: Current security status
- **Anomalies**: Suspicious flows detected
- **Confidence**: Model certainty (0-100%)

#### 4. Detection Timeline
Historical view of threat levels over time

### Sidebar Controls

- **Simulation Mode**: Enable/disable synthetic data generation
- **Generate New Detection**: Trigger new analysis
- **Statistics**: View detection counts by severity

### Exporting Results

Currently, results are stored in:
- `results/reports/` - JSON detection reports
- `results/metrics/` - Performance plots
- `results/models/` - Trained models

---

## API Reference

### DataLoader Class

```python
from src.data_preprocessing.data_loader import DataLoader

loader = DataLoader()

# Load NSL-KDD
train_data = loader.load_nsl_kdd('train')
test_data = loader.load_nsl_kdd('test')

# Load CICIDS2017
cicids_data = loader.load_cicids2017(day='Monday')

# Create synthetic data
synthetic_data = loader.create_sample_dataset(n_samples=5000)

# Get statistics
stats = loader.get_data_statistics(train_data)
```

### FeatureEngineer Class

```python
from src.data_preprocessing.feature_engineering import FeatureEngineer

engineer = FeatureEngineer()

# Clean data
cleaned_df = engineer.clean_data(raw_df)

# Process labels
df, label_map = engineer.process_labels(cleaned_df, binary=False)

# Encode categorical features
df = engineer.encode_categorical_features(df, fit=True)

# Create APT features
df = engineer.create_apt_specific_features(df)

# Scale features
df = engineer.scale_features(df, fit=True)

# Save preprocessors
engineer.save_preprocessors('results/models/')
```

### RandomForestDetector Class

```python
from src.models.random_forest_detector import RandomForestDetector

detector = RandomForestDetector()

# Train model
detector.train(X_train, y_train)

# Make predictions
predictions = detector.predict(X_test)
probabilities = detector.predict_proba(X_test)

# Evaluate
metrics = detector.evaluate(X_test, y_test)

# Plot importance
detector.plot_feature_importance(
    feature_names=feature_list,
    top_n=20,
    save_path='importance.png'
)

# Save/Load model
detector.save_model('results/models/rf_model.pkl')
detector.load_model('results/models/rf_model.pkl')
```

### LSTMDetector Class

```python
from src.models.lstm_detector import LSTMDetector

detector = LSTMDetector()

# Build model
detector.build_model(input_shape=(10, 30), num_classes=5)

# Train with validation
detector.train(X_train, y_train, X_val, y_val)

# Predict
predictions = detector.predict(X_test)
probabilities = detector.predict_proba(X_test)

# Evaluate
metrics = detector.evaluate(X_test, y_test)

# Plot training history
detector.plot_training_history(save_path='history.png')

# Save/Load model
detector.save_model('results/models/lstm_model.h5')
detector.load_model('results/models/lstm_model.h5')
```

### APTDetector Class

```python
from src.detection.apt_detector import APTDetector

detector = APTDetector()

# Load trained models
detector.load_models({
    'random_forest': 'results/models/random_forest_model.pkl',
    'lstm': 'results/models/lstm_model.h5'
})

# Detect APT patterns
network_data = pd.read_csv('network_traffic.csv')
results = detector.detect_apt_pattern(network_data)

# Analyze kill chain
kill_chain = detector.analyze_kill_chain(results['detections'])

# Detect behavioral anomalies
anomalies = detector.detect_behavioral_anomalies(network_data)

# Generate alert
alert = detector.generate_alert(results, kill_chain)

# Save report
detector.save_detection_report('results/reports/report.json')
```

---

## Troubleshooting

### Common Issues

#### 1. "Module not found" Error

```bash
# Ensure you're in virtual environment
source venv/bin/activate

# Reinstall requirements
pip install -r requirements.txt
```

#### 2. TensorFlow Installation Fails

```bash
# For CPU-only version
pip install tensorflow-cpu==2.13.0

# For Apple Silicon Macs
pip install tensorflow-macos==2.13.0
pip install tensorflow-metal
```

#### 3. Out of Memory During Training

Edit `config/config.yaml`:
```yaml
lstm:
  batch_size: 128  # Reduce from 256
  units: [64, 32, 16]  # Smaller layers
```

#### 4. Dashboard Won't Start

```bash
# Check if port 8501 is in use
lsof -i :8501

# Use different port
streamlit run app.py --server.port 8502
```

#### 5. Dataset Download Fails

Manual download:
```bash
cd data/raw
mkdir NSL-KDD
cd NSL-KDD
wget https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt
wget https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt
```

### Performance Issues

#### Slow Training

- Use GPU: Install `tensorflow-gpu`
- Reduce dataset size: Sample fewer rows
- Decrease model complexity: Fewer LSTM units

#### High Memory Usage

- Use data generators instead of loading all data
- Reduce batch size
- Close other applications

### Getting Help

1. Check [GitHub Issues](https://github.com/yourusername/apt-detection-system/issues)
2. Review documentation in `docs/`
3. Contact: your.email@example.com

---

## FAQ

**Q: Can I use this on live network traffic?**  
A: Yes, but you'll need to integrate with packet capture tools like Wireshark or Zeek. The system expects CSV files with network flow features.

**Q: How often should I retrain models?**  
A: Retrain every 1-3 months as new attack patterns emerge. Use your own network data for best results.

**Q: What's the minimum dataset size for training?**  
A: At least 10,000 samples for basic training, 100,000+ for production use.

**Q: Can it detect zero-day attacks?**  
A: The anomaly detection capabilities can identify unusual patterns, but it's not guaranteed for sophisticated zero-days.

**Q: Is this production-ready?**  
A: It's a research prototype. For production, add:
- Robust error handling
- Scalability improvements
- Security hardening
- Professional monitoring

**Q: How do I add new features?**  
A: Edit `src/data_preprocessing/feature_engineering.py` and add your feature extraction logic in `create_apt_specific_features()`.

**Q: Can I export detection reports?**  
A: Yes, use `detector.save_detection_report()` to save JSON reports.

**Q: What license is this under?**  
A: MIT License - free for academic and commercial use with attribution.

---

## Next Steps

Now that you're familiar with the system:

1. **Customize**: Adapt features for your network environment
2. **Experiment**: Try different model configurations
3. **Extend**: Add new detection algorithms
4. **Deploy**: Integrate with your security infrastructure
5. **Contribute**: Share improvements with the community

---

**Happy Threat Hunting! 🛡️🔍**

For more information, see:
- [README.md](../README.md) - Project overview
- [research_paper.md](research_paper.md) - Technical details
- [GitHub Repository](https://github.com/nainaisrat/apt-detection-system)
