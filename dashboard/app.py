"""
APT Detection System - Real-time Monitoring Dashboard
Interactive Streamlit dashboard for monitoring APT detections
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent))

from src.detection.apt_detector import APTDetector

# Page configuration
st.set_page_config(
    page_title="APT Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 42px;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 20px;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 2px 2px 5px rgba(0,0,0,0.1);
    }
    .alert-critical {
        background-color: #ff4444;
        color: white;
        padding: 15px;
        border-radius: 5px;
        font-weight: bold;
    }
    .alert-high {
        background-color: #ff8800;
        color: white;
        padding: 15px;
        border-radius: 5px;
        font-weight: bold;
    }
    .alert-medium {
        background-color: #ffbb33;
        color: white;
        padding: 15px;
        border-radius: 5px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


def create_threat_gauge(threat_level: str, confidence: float):
    """Create a gauge chart for threat level"""
    
    # Map threat level to value
    level_mapping = {
        'low': 25,
        'medium': 50,
        'high': 75,
        'critical': 100
    }
    
    value = level_mapping.get(threat_level, 0)
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=value,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': f"Threat Level: {threat_level.upper()}", 
               'font': {'size': 24}},
        delta={'reference': 50},
        gauge={
            'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
            'bar': {'color': "darkblue"},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 25], 'color': '#90EE90'},
                {'range': [25, 50], 'color': '#FFD700'},
                {'range': [50, 75], 'color': '#FFA500'},
                {'range': [75, 100], 'color': '#FF4444'}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': value
            }
        }
    ))
    
    fig.update_layout(
        height=300,
        margin=dict(l=20, r=20, t=60, b=20)
    )
    
    return fig


def create_kill_chain_visualization(detected_stages: list):
    """Create kill chain progression visualization"""
    
    all_stages = [
        'Reconnaissance',
        'Weaponization',
        'Delivery',
        'Exploitation',
        'Installation',
        'Command & Control',
        'Actions on Objectives'
    ]
    
    # Check which stages are active
    status = ['Detected' if stage.lower().replace(' ', '_').replace('&', 'and') in 
              [s.lower().replace(' ', '_') for s in detected_stages]
              else 'Not Detected' for stage in all_stages]
    
    colors = ['#FF4444' if s == 'Detected' else '#90EE90' for s in status]
    
    fig = go.Figure(data=[go.Bar(
        x=all_stages,
        y=[1]*len(all_stages),
        marker_color=colors,
        text=status,
        textposition='auto',
        hovertemplate='<b>%{x}</b><br>Status: %{text}<extra></extra>'
    )])
    
    fig.update_layout(
        title="Cyber Kill Chain Analysis",
        title_font_size=20,
        xaxis_title="Kill Chain Stage",
        yaxis_visible=False,
        height=300,
        margin=dict(l=20, r=20, t=60, b=20),
        showlegend=False
    )
    
    return fig


def create_attack_timeline(detection_history: list):
    """Create timeline of attacks"""
    
    if not detection_history:
        return go.Figure()
    
    # Extract timestamps and threat levels
    timestamps = [datetime.fromisoformat(d['timestamp']) for d in detection_history]
    threat_levels = [d['overall_threat_level'] for d in detection_history]
    
    # Map threat levels to numeric values
    level_mapping = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    threat_values = [level_mapping.get(level, 0) for level in threat_levels]
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=timestamps,
        y=threat_values,
        mode='lines+markers',
        name='Threat Level',
        line=dict(color='#FF4444', width=3),
        marker=dict(size=10),
        hovertemplate='<b>Time:</b> %{x}<br><b>Threat:</b> %{text}<extra></extra>',
        text=threat_levels
    ))
    
    fig.update_layout(
        title="Threat Level Timeline",
        title_font_size=20,
        xaxis_title="Time",
        yaxis_title="Threat Level",
        yaxis=dict(
            tickmode='array',
            tickvals=[1, 2, 3, 4],
            ticktext=['Low', 'Medium', 'High', 'Critical']
        ),
        height=300,
        margin=dict(l=20, r=20, t=60, b=20),
        hovermode='x unified'
    )
    
    return fig


def create_detection_distribution(detections: list):
    """Create pie chart of detection distribution"""
    
    if not detections:
        return go.Figure()
    
    # Count detections by class
    classes = [d['predicted_class'] for d in detections if d['is_anomaly']]
    
    if not classes:
        return go.Figure()
    
    class_names = {
        1: 'Reconnaissance',
        2: 'Exploitation',
        3: 'Lateral Movement',
        4: 'Command & Control',
        5: 'Exfiltration'
    }
    
    class_labels = [class_names.get(c, f'Class {c}') for c in classes]
    
    fig = px.pie(
        values=[class_labels.count(label) for label in set(class_labels)],
        names=list(set(class_labels)),
        title="Attack Type Distribution",
        color_discrete_sequence=px.colors.qualitative.Set3
    )
    
    fig.update_layout(
        height=300,
        margin=dict(l=20, r=20, t=60, b=20)
    )
    
    return fig


def main():
    """Main dashboard function"""
    
    # Header
    st.markdown('<p class="main-header">🛡️ APT Detection System Dashboard</p>', 
                unsafe_allow_html=True)
    
    # Sidebar
    st.sidebar.title("⚙️ Controls")
    
    # Simulation mode
    simulation_mode = st.sidebar.checkbox("Simulation Mode", value=True)
    
    if simulation_mode:
        st.sidebar.info("📊 Running in simulation mode with synthetic data")
    
    # Initialize detector
    if 'detector' not in st.session_state:
        st.session_state.detector = APTDetector()
        st.session_state.detection_count = 0
    
    # Generate sample data button
    if st.sidebar.button("🔄 Generate New Detection"):
        # Create synthetic network data
        sample_data = pd.DataFrame({
            'duration': np.random.exponential(100, 100),
            'src_bytes': np.random.exponential(1000, 100),
            'dst_bytes': np.random.exponential(1000, 100),
            'dst_host_count': np.random.poisson(10, 100),
            'count': np.random.poisson(5, 100)
        })
        
        # Detect behavioral anomalies
        anomalies = st.session_state.detector.detect_behavioral_anomalies(sample_data)
        
        # Create mock detection result
        mock_result = {
            'timestamp': datetime.now().isoformat(),
            'total_flows': 100,
            'detections': [
                {
                    'flow_index': i,
                    'predicted_class': np.random.choice([0, 1, 2, 3, 4, 5]),
                    'confidence': np.random.uniform(0.7, 0.99),
                    'num_models_agree': np.random.randint(1, 4),
                    'is_anomaly': np.random.choice([True, False], p=[0.1, 0.9])
                }
                for i in range(10)
            ],
            'overall_threat_level': np.random.choice(['low', 'medium', 'high', 'critical'], 
                                                     p=[0.5, 0.3, 0.15, 0.05]),
            'confidence': np.random.uniform(0.7, 0.95)
        }
        
        st.session_state.detector.detection_history.append(mock_result)
        st.session_state.detection_count += 1
    
    # Main content
    if not st.session_state.detector.detection_history:
        st.info("👆 Click 'Generate New Detection' to start monitoring")
        return
    
    # Get latest detection
    latest_detection = st.session_state.detector.detection_history[-1]
    
    # Top metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="Total Detections",
            value=st.session_state.detection_count,
            delta="+1" if st.session_state.detection_count > 0 else "0"
        )
    
    with col2:
        st.metric(
            label="Threat Level",
            value=latest_detection['overall_threat_level'].upper(),
            delta="Stable"
        )
    
    with col3:
        anomalous_count = sum(1 for d in latest_detection['detections'] if d['is_anomaly'])
        st.metric(
            label="Anomalies Detected",
            value=anomalous_count,
            delta=f"+{anomalous_count}"
        )
    
    with col4:
        st.metric(
            label="Confidence",
            value=f"{latest_detection['confidence']:.2%}",
            delta="High" if latest_detection['confidence'] > 0.8 else "Medium"
        )
    
    # Alert section
    if latest_detection['overall_threat_level'] in ['critical', 'high']:
        alert_class = f"alert-{latest_detection['overall_threat_level']}"
        st.markdown(
            f'<div class="{alert_class}">⚠️ SECURITY ALERT: '
            f'{latest_detection["overall_threat_level"].upper()} threat detected!</div>',
            unsafe_allow_html=True
        )
    
    st.markdown("---")
    
    # Visualization row 1
    col1, col2 = st.columns(2)
    
    with col1:
        # Threat gauge
        gauge_fig = create_threat_gauge(
            latest_detection['overall_threat_level'],
            latest_detection['confidence']
        )
        st.plotly_chart(gauge_fig, use_container_width=True)
    
    with col2:
        # Detection distribution
        dist_fig = create_detection_distribution(latest_detection['detections'])
        st.plotly_chart(dist_fig, use_container_width=True)
    
    # Visualization row 2
    col1, col2 = st.columns(2)
    
    with col1:
        # Kill chain
        kill_chain_fig = create_kill_chain_visualization(['reconnaissance', 'exploitation'])
        st.plotly_chart(kill_chain_fig, use_container_width=True)
    
    with col2:
        # Timeline
        timeline_fig = create_attack_timeline(st.session_state.detector.detection_history)
        st.plotly_chart(timeline_fig, use_container_width=True)
    
    # Detection details
    st.markdown("---")
    st.subheader("📋 Recent Detections")
    
    # Show detection table
    if latest_detection['detections']:
        anomalies_df = pd.DataFrame([
            d for d in latest_detection['detections'] if d['is_anomaly']
        ])
        
        if not anomalies_df.empty:
            st.dataframe(
                anomalies_df.style.background_gradient(
                    subset=['confidence'], 
                    cmap='RdYlGn'
                ),
                use_container_width=True
            )
        else:
            st.success("✅ No anomalies detected in recent traffic")
    
    # Sidebar stats
    st.sidebar.markdown("---")
    st.sidebar.subheader("📊 Statistics")
    
    total_detections = len(st.session_state.detector.detection_history)
    st.sidebar.write(f"Total Scans: {total_detections}")
    
    if total_detections > 0:
        threat_levels = [d['overall_threat_level'] for d in 
                        st.session_state.detector.detection_history]
        
        st.sidebar.write(f"Critical: {threat_levels.count('critical')}")
        st.sidebar.write(f"High: {threat_levels.count('high')}")
        st.sidebar.write(f"Medium: {threat_levels.count('medium')}")
        st.sidebar.write(f"Low: {threat_levels.count('low')}")


if __name__ == "__main__":
    main()
