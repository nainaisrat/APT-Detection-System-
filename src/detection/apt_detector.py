"""
APT Detection Engine
Main detection system that integrates all models and performs real-time analysis
"""

import numpy as np
import pandas as pd
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class APTDetector:
    """
    Main APT Detection Engine
    Combines multiple models for comprehensive threat detection
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize APT Detector"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.apt_config = self.config['apt_detection']
        self.models = {}
        self.kill_chain_stages = self.apt_config['kill_chain_stages']
        self.thresholds = self.apt_config['thresholds']
        
        # Detection history
        self.detection_history = []
        self.alerts = []
        
    def load_models(self, model_paths: Dict[str, str]):
        """
        Load trained models
        
        Args:
            model_paths: Dictionary of model_name: model_path pairs
        """
        logger.info("Loading detection models...")
        
        for model_name, model_path in model_paths.items():
            try:
                if 'random_forest' in model_name:
                    from src.models.random_forest_detector import RandomForestDetector
                    detector = RandomForestDetector()
                    detector.load_model(model_path)
                    self.models[model_name] = detector
                    
                elif 'lstm' in model_name:
                    from src.models.lstm_detector import LSTMDetector
                    detector = LSTMDetector()
                    detector.load_model(model_path)
                    self.models[model_name] = detector
                
                logger.info(f"Loaded {model_name} from {model_path}")
                
            except Exception as e:
                logger.error(f"Error loading {model_name}: {e}")
        
        logger.info(f"Loaded {len(self.models)} models successfully")
    
    def detect_apt_pattern(self, network_data: pd.DataFrame) -> Dict:
        """
        Detect APT patterns in network traffic
        
        Args:
            network_data: DataFrame with network traffic features
            
        Returns:
            Detection results dictionary
        """
        logger.info(f"Analyzing {len(network_data)} network flows...")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'total_flows': len(network_data),
            'detections': [],
            'overall_threat_level': 'low',
            'confidence': 0.0
        }
        
        # Ensemble predictions from all models
        predictions = {}
        confidences = {}
        
        for model_name, model in self.models.items():
            try:
                # Get predictions
                if hasattr(model, 'predict_proba'):
                    proba = model.predict_proba(network_data)
                    pred = model.predict(network_data)
                    
                    predictions[model_name] = pred
                    confidences[model_name] = np.max(proba, axis=1)
                    
            except Exception as e:
                logger.error(f"Error in {model_name} prediction: {e}")
        
        # Combine predictions (voting)
        if predictions:
            combined_predictions = self._ensemble_predictions(predictions, confidences)
            results['detections'] = combined_predictions
            
            # Calculate overall threat level
            results['overall_threat_level'] = self._calculate_threat_level(
                combined_predictions
            )
            results['confidence'] = self._calculate_overall_confidence(confidences)
        
        # Store in history
        self.detection_history.append(results)
        
        return results
    
    def _ensemble_predictions(self, predictions: Dict, confidences: Dict) -> List[Dict]:
        """
        Combine predictions from multiple models using weighted voting
        
        Args:
            predictions: Dictionary of model predictions
            confidences: Dictionary of model confidences
            
        Returns:
            List of detection dictionaries
        """
        detections = []
        
        # Get number of samples
        n_samples = len(list(predictions.values())[0])
        
        for i in range(n_samples):
            # Collect votes from all models
            votes = {}
            total_confidence = 0
            
            for model_name in predictions:
                pred = predictions[model_name][i]
                conf = confidences[model_name][i]
                
                if pred not in votes:
                    votes[pred] = []
                votes[pred].append(conf)
                total_confidence += conf
            
            # Find consensus prediction
            consensus_pred = max(votes.keys(), key=lambda x: sum(votes[x]))
            avg_confidence = sum(votes[consensus_pred]) / len(votes[consensus_pred])
            
            # Only report if confidence exceeds threshold
            if avg_confidence >= self.thresholds['confidence_threshold']:
                detections.append({
                    'flow_index': i,
                    'predicted_class': int(consensus_pred),
                    'confidence': float(avg_confidence),
                    'num_models_agree': len(votes[consensus_pred]),
                    'is_anomaly': consensus_pred != 0  # Assuming 0 is normal
                })
        
        return detections
    
    def analyze_kill_chain(self, detections: List[Dict]) -> Dict:
        """
        Analyze attack progression through kill chain stages
        
        Args:
            detections: List of detection dictionaries
            
        Returns:
            Kill chain analysis results
        """
        logger.info("Analyzing kill chain progression...")
        
        # Map predictions to kill chain stages
        stage_mapping = {
            0: 'normal',
            1: 'reconnaissance',
            2: 'exploitation',
            3: 'lateral_movement',
            4: 'command_and_control',
            5: 'exfiltration'
        }
        
        kill_chain_analysis = {
            'detected_stages': [],
            'progression_score': 0.0,
            'current_stage': 'none',
            'risk_level': 'low'
        }
        
        if not detections:
            return kill_chain_analysis
        
        # Identify which stages are present
        detected_stages = set()
        for detection in detections:
            if detection['is_anomaly']:
                stage = stage_mapping.get(detection['predicted_class'], 'unknown')
                detected_stages.add(stage)
        
        kill_chain_analysis['detected_stages'] = list(detected_stages)
        
        # Calculate progression score (0-1)
        # Higher score = more advanced in kill chain
        stage_weights = {
            'reconnaissance': 0.1,
            'exploitation': 0.3,
            'lateral_movement': 0.5,
            'command_and_control': 0.7,
            'exfiltration': 0.9
        }
        
        if detected_stages:
            max_stage_weight = max(stage_weights.get(stage, 0) 
                                  for stage in detected_stages if stage != 'normal')
            kill_chain_analysis['progression_score'] = max_stage_weight
            
            # Determine current stage
            for stage in ['exfiltration', 'command_and_control', 'lateral_movement',
                         'exploitation', 'reconnaissance']:
                if stage in detected_stages:
                    kill_chain_analysis['current_stage'] = stage
                    break
        
        # Assess risk level
        progression = kill_chain_analysis['progression_score']
        if progression >= 0.7:
            kill_chain_analysis['risk_level'] = 'critical'
        elif progression >= 0.5:
            kill_chain_analysis['risk_level'] = 'high'
        elif progression >= 0.3:
            kill_chain_analysis['risk_level'] = 'medium'
        elif progression > 0:
            kill_chain_analysis['risk_level'] = 'low'
        
        return kill_chain_analysis
    
    def detect_behavioral_anomalies(self, network_data: pd.DataFrame) -> List[Dict]:
        """
        Detect suspicious behavioral patterns indicative of APT
        
        Args:
            network_data: Network traffic data
            
        Returns:
            List of behavioral anomalies detected
        """
        logger.info("Detecting behavioral anomalies...")
        
        anomalies = []
        patterns = self.apt_config['patterns']
        
        # Check lateral movement indicators
        if all(col in network_data.columns for col in ['dst_host_count', 'count']):
            # High number of unique destinations
            lateral_movement = network_data[
                network_data['dst_host_count'] > network_data['dst_host_count'].quantile(0.95)
            ]
            
            if len(lateral_movement) > 0:
                anomalies.append({
                    'type': 'lateral_movement',
                    'severity': 'high',
                    'count': len(lateral_movement),
                    'description': 'Unusual lateral movement detected'
                })
        
        # Check data exfiltration indicators
        if 'src_bytes' in network_data.columns:
            # Large outbound transfers
            exfiltration = network_data[
                network_data['src_bytes'] > network_data['src_bytes'].quantile(0.99)
            ]
            
            if len(exfiltration) > 0:
                anomalies.append({
                    'type': 'data_exfiltration',
                    'severity': 'critical',
                    'count': len(exfiltration),
                    'total_bytes': int(exfiltration['src_bytes'].sum()),
                    'description': 'Potential data exfiltration detected'
                })
        
        # Check for port scanning (reconnaissance)
        if 'dst_host_count' in network_data.columns:
            scanning = network_data[
                network_data['dst_host_count'] > 100
            ]
            
            if len(scanning) > 0:
                anomalies.append({
                    'type': 'reconnaissance',
                    'severity': 'medium',
                    'count': len(scanning),
                    'description': 'Port scanning activity detected'
                })
        
        logger.info(f"Detected {len(anomalies)} behavioral anomalies")
        return anomalies
    
    def _calculate_threat_level(self, detections: List[Dict]) -> str:
        """Calculate overall threat level"""
        if not detections:
            return 'low'
        
        # Count high-confidence detections
        high_confidence_detections = [
            d for d in detections 
            if d['confidence'] >= 0.9 and d['is_anomaly']
        ]
        
        if len(high_confidence_detections) > 10:
            return 'critical'
        elif len(high_confidence_detections) > 5:
            return 'high'
        elif len(high_confidence_detections) > 0:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_overall_confidence(self, confidences: Dict) -> float:
        """Calculate overall confidence across all models"""
        all_confidences = []
        for model_confs in confidences.values():
            all_confidences.extend(model_confs)
        
        return float(np.mean(all_confidences)) if all_confidences else 0.0
    
    def generate_alert(self, detection_result: Dict, kill_chain_analysis: Dict):
        """
        Generate security alert based on detection results
        
        Args:
            detection_result: Detection results
            kill_chain_analysis: Kill chain analysis
        """
        alert = {
            'timestamp': datetime.now().isoformat(),
            'alert_id': f"APT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'threat_level': detection_result['overall_threat_level'],
            'confidence': detection_result['confidence'],
            'kill_chain_stage': kill_chain_analysis['current_stage'],
            'risk_level': kill_chain_analysis['risk_level'],
            'num_detections': len(detection_result['detections']),
            'recommendation': self._generate_recommendation(
                detection_result, kill_chain_analysis
            )
        }
        
        self.alerts.append(alert)
        
        # Log critical alerts
        if alert['threat_level'] in ['critical', 'high']:
            logger.warning(f"SECURITY ALERT: {alert['alert_id']}")
            logger.warning(f"Threat Level: {alert['threat_level']}")
            logger.warning(f"Kill Chain Stage: {alert['kill_chain_stage']}")
        
        return alert
    
    def _generate_recommendation(self, detection_result: Dict, 
                                 kill_chain_analysis: Dict) -> str:
        """Generate security recommendations"""
        stage = kill_chain_analysis['current_stage']
        risk = kill_chain_analysis['risk_level']
        
        recommendations = {
            'reconnaissance': "Increase monitoring of network scanning activities. Review firewall rules.",
            'exploitation': "Immediately patch vulnerable systems. Isolate affected hosts.",
            'lateral_movement': "Segment network. Review access controls. Monitor privileged accounts.",
            'command_and_control': "Block suspicious domains/IPs. Analyze network traffic for C2 patterns.",
            'exfiltration': "CRITICAL: Block outbound traffic. Isolate affected systems. Begin incident response."
        }
        
        return recommendations.get(stage, "Continue monitoring for suspicious activity.")
    
    def save_detection_report(self, filepath: str = None):
        """
        Save detection report to file
        
        Args:
            filepath: Path to save report
        """
        if filepath is None:
            filepath = f"results/reports/apt_detection_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'detection_history': self.detection_history,
            'alerts': self.alerts,
            'summary': {
                'total_detections': sum(len(d['detections']) for d in self.detection_history),
                'total_alerts': len(self.alerts),
                'critical_alerts': len([a for a in self.alerts if a['threat_level'] == 'critical'])
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Detection report saved to {filepath}")


def main():
    """
    Test APT Detector
    """
    import sys
    sys.path.append(str(Path(__file__).parent.parent))
    
    print("\n" + "="*50)
    print("Testing APT Detection Engine")
    print("="*50)
    
    # Initialize detector
    detector = APTDetector()
    
    # Create sample network data
    print("\n1. Creating sample network data...")
    sample_data = pd.DataFrame({
        'duration': np.random.exponential(100, 100),
        'src_bytes': np.random.exponential(1000, 100),
        'dst_bytes': np.random.exponential(1000, 100),
        'dst_host_count': np.random.poisson(10, 100),
        'count': np.random.poisson(5, 100)
    })
    
    print(f"   Created {len(sample_data)} network flows")
    
    # Detect behavioral anomalies
    print("\n2. Detecting behavioral anomalies...")
    anomalies = detector.detect_behavioral_anomalies(sample_data)
    print(f"   Found {len(anomalies)} behavioral anomalies")
    
    for anomaly in anomalies:
        print(f"   - {anomaly['type']}: {anomaly['description']}")
    
    print("\n3. APT Detection Engine ready for deployment!")
    print("   Load trained models using load_models() method")
    print("   Then call detect_apt_pattern() for real-time detection")
    
    print("\n" + "="*50)


if __name__ == "__main__":
    main()
