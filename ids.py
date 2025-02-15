import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import threading
import time
from typing import Any, Dict
from scapy.all import sniff, IP, TCP, Raw
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from collections import deque
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import queue
import psutil
from datetime import datetime
import sys
import logging
import pandas as pd

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('ids.log')
    ]
)

class MLDetector:
    """Machine Learning-based Network Traffic Analyzer"""
    def __init__(self, window_size=1000):
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        self.scaler = StandardScaler()
        self.window_size = window_size
        self.feature_buffer = deque(maxlen=window_size)
        self.is_trained = False
        
    def extract_ml_features(self, packet_features):
        """Extract numerical features for ML model"""
        return np.array([
            packet_features.get('packet_size', 0),
            packet_features.get('window_size', 0),
            packet_features.get('payload_entropy', 0),
            packet_features.get('printable_percent', 0),
            packet_features.get('inter_arrival', 0),
            int(packet_features.get('flags', {}).get('SYN', False)),
            int(packet_features.get('flags', {}).get('ACK', False)),
            int(packet_features.get('flags', {}).get('FIN', False)),
            int(packet_features.get('flags', {}).get('RST', False)),
            packet_features.get('dest_port', 0)
        ])

    def update_and_train(self, packet_features):
        """Update feature buffer and retrain model if needed"""
        features = self.extract_ml_features(packet_features)
        self.feature_buffer.append(features)
        
        if len(self.feature_buffer) == self.window_size and not self.is_trained:
            self._train_model()
            
    def _train_model(self):
        """Train the anomaly detection model"""
        try:
            X = np.array(list(self.feature_buffer))
            X_scaled = self.scaler.fit_transform(X)
            self.isolation_forest.fit(X_scaled)
            self.is_trained = True
            
            joblib.dump(self.isolation_forest, 'ids_model.joblib')
            joblib.dump(self.scaler, 'ids_scaler.joblib')
        except Exception as e:
            logging.error(f"Training error: {str(e)}")
            
    def predict(self, packet_features):
        """Predict if packet is anomalous"""
        if not self.is_trained:
            return 0.5
            
        try:
            features = self.extract_ml_features(packet_features)
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            prediction = self.isolation_forest.predict(features_scaled)[0]
            score = 1.0 if prediction == -1 else 0.0
            return score
        except Exception as e:
            logging.error(f"Prediction error: {str(e)}")
            return 0.5

class EnhancedTrafficAnalyzer:
    """Advanced network traffic analysis engine"""
    def __init__(self):
        self.last_packet_time = None
        self.processed_packets = 0

    def calculate_entropy(self, payload: bytes) -> float:
        """Calculate information entropy of payload"""
        if not payload: return 0.0
        try:
            counts = np.bincount(np.frombuffer(payload, dtype=np.uint8))
            probabilities = counts[counts > 0] / len(payload)
            return -np.sum(probabilities * np.log2(probabilities))
        except Exception as e:
            logging.error(f"Entropy error: {str(e)}")
            return 0.0

    def analyze_flags(self, flags: int) -> dict:
        """Comprehensive TCP flag analysis"""
        return {
            'FIN': bool(flags & 0x01),
            'SYN': bool(flags & 0x02),
            'RST': bool(flags & 0x04),
            'PSH': bool(flags & 0x08),
            'ACK': bool(flags & 0x10),
            'URG': bool(flags & 0x20),
            'ECE': bool(flags & 0x40),
            'CWR': bool(flags & 0x80)
        }

    def payload_printable(self, payload: bytes) -> float:
        """Calculate percentage of printable characters"""
        if not payload: return 0.0
        printable = sum(32 <= c <= 126 for c in payload)
        return (printable / len(payload)) * 100

    def extract_features(self, packet: Any) -> Dict:
        """Comprehensive feature extraction"""
        features = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            'source_ip': packet[IP].src if IP in packet else '0.0.0.0',
            'dest_ip': packet[IP].dst if IP in packet else '0.0.0.0',
            'source_port': packet[TCP].sport if TCP in packet else 0,
            'dest_port': packet[TCP].dport if TCP in packet else 0,
            'packet_size': len(packet),
            'window_size': packet[TCP].window if TCP in packet else 0,
        }

        if TCP in packet:
            tcp = packet[TCP]
            features.update({
                'flags': self.analyze_flags(tcp.flags),
                'payload_entropy': self.calculate_entropy(bytes(tcp.payload)),
                'printable_percent': self.payload_printable(bytes(tcp.payload))
            })

        current_time = time.time()
        features['inter_arrival'] = current_time - self.last_packet_time if self.last_packet_time else 0
        self.last_packet_time = current_time

        self.processed_packets += 1
        return features

class PacketProcessor:
    """Parallel packet processing system"""
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.running = True
        self.analyzer = EnhancedTrafficAnalyzer()
        self.worker_thread = None

    def process_packet(self, packet):
        """Add packet to processing queue"""
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def worker(self):
        """Processing thread"""
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=1)
                features = self.analyzer.extract_features(packet)
                self.result_queue.put(features)
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Worker error: {str(e)}")

    def start(self):
        """Start processing thread"""
        self.running = True
        self.worker_thread = threading.Thread(target=self.worker)
        self.worker_thread.daemon = True
        self.worker_thread.start()

    def stop(self):
        """Stop processing thread"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)

class EnhancedIDSController:
    """Extended IDS Controller with ML capabilities"""
    def __init__(self):
        self.packet_processor = PacketProcessor()
        self.running = False
        self.test_mode = False
        self.ml_detector = MLDetector()

    def calculate_anomaly_score(self, features: dict) -> float:
        """Enhanced anomaly scoring with ML"""
        # Rule-based scoring
        base_score = 0.0
        
        flags = features.get('flags', {})
        if flags.get('SYN') and not flags.get('ACK'):
            base_score += 0.3
        if flags.get('FIN') and not flags.get('ACK'):
            base_score += 0.2
            
        if features.get('payload_entropy', 0) > 7.5:
            base_score += 0.4
        if features.get('printable_percent', 100) < 20:
            base_score += 0.3
            
        if features.get('packet_size', 0) > 1500:
            base_score += 0.2
        if features.get('inter_arrival', 0) < 0.001:
            base_score += 0.3
            
        base_score = min(base_score, 1.0)
        
        # Update ML model and get prediction
        self.ml_detector.update_and_train(features)
        ml_score = self.ml_detector.predict(features)
        
        # Combine scores (70% ML, 30% rule-based)
        combined_score = (0.7 * ml_score) + (0.3 * base_score)
        return combined_score

    def packet_handler(self, packet):
        """Main packet handling method"""
        if IP in packet and TCP in packet:
            self.packet_processor.process_packet(packet)

    def generate_report(self, features: dict, score: float) -> str:
        """Generate detailed analysis report"""
        ml_score = self.ml_detector.predict(features)
        base_score = self.calculate_anomaly_score(features)
        
        report = f"""
Packet Analysis Report
---------------------
Timestamp: {features['timestamp']}
Source: {features['source_ip']}:{features['source_port']}
Destination: {features['dest_ip']}:{features['dest_port']}

Risk Assessment:
- ML Score: {ml_score:.2f}
- Rule-based Score: {base_score:.2f}
- Combined Score: {score:.2f}

Packet Features:
- Size: {features['packet_size']} bytes
- Window Size: {features['window_size']}
- Entropy: {features.get('payload_entropy', 0):.2f}
- Printable Characters: {features.get('printable_percent', 0):.1f}%
- TCP Flags: {', '.join(k for k, v in features['flags'].items() if v)}
"""
        return report

class IDSGUI(ttk.Window):
    """Modern GUI for IDS application"""
    def __init__(self):
        super().__init__(themename="darkly")
        self.title("ML-Enhanced Network Intrusion Detection System")
        self.geometry("1200x800")
        self.ids = EnhancedIDSController()
        self.running = False
        self.test_mode = False
        
        self.configure_style()
        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def configure_style(self):
        """Configure ttkbootstrap styles"""
        self.style.configure('danger.TButton', font=('Helvetica', 10, 'bold'))
        self.style.configure('success.TButton', font=('Helvetica', 10, 'bold'))

    def create_widgets(self):
        """Create and arrange GUI components"""
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Control Panel
        control_frame = ttk.Labelframe(main_frame, text="Controls", bootstyle=INFO)
        control_frame.pack(fill=tk.X, pady=5)

        self.start_btn = ttk.Button(
            control_frame,
            text="Start Live Capture",
            command=self.start_live_capture,
            bootstyle=(SUCCESS, OUTLINE),
            width=20
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.test_btn = ttk.Button(
            control_frame,
            text="Run Test Mode",
            command=self.run_test_mode,
            bootstyle=(INFO, OUTLINE),
            width=15
        )
        self.test_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(
            control_frame,
            text="Stop",
            command=self.stop_capture,
            bootstyle=(DANGER, OUTLINE),
            width=10,
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # Statistics Panel
        stats_frame = ttk.Labelframe(main_frame, text="Real-time Statistics", bootstyle=INFO)
        stats_frame.pack(fill=tk.X, pady=5)

        self.stats_labels = {
            'total': ttk.Label(stats_frame, text="Total Packets: 0", bootstyle=INVERSE),
            'high': ttk.Label(stats_frame, text="High Risk: 0", bootstyle=(INVERSE, DANGER)),
            'medium': ttk.Label(stats_frame, text="Medium Risk: 0", bootstyle=(INVERSE, WARNING)),
            'low': ttk.Label(stats_frame, text="Low Risk: 0", bootstyle=(INVERSE, SUCCESS))
        }

        for label in self.stats_labels.values():
            label.pack(side=tk.LEFT, padx=15, pady=3)

        # Packet List
        list_frame = ttk.Labelframe(main_frame, text="Packet Analysis", bootstyle=INFO)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        columns = ('time', 'source', 'destination', 'size', 'score', 'flags')
        self.packet_list = ttk.Treeview(
            list_frame,
            columns=columns,
            show='headings',
            bootstyle=INFO,
            selectmode='none'
        )

        self.packet_list.heading('time', text='Timestamp')
        self.packet_list.heading('source', text='Source')
        self.packet_list.heading('destination', text='Destination')
        self.packet_list.heading('size', text='Size (bytes)')
        self.packet_list.heading('score', text='Risk Score')
        self.packet_list.heading('flags', text='TCP Flags')

        self.packet_list.column('time', width=180, anchor=tk.W)
        self.packet_list.column('source', width=200, anchor=tk.W)
        self.packet_list.column('destination', width=200, anchor=tk.W)
        self.packet_list.column('size', width=100, anchor=tk.CENTER)
        self.packet_list.column('score', width=100, anchor=tk.CENTER)
        self.packet_list.column('flags', width=150, anchor=tk.W)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.packet_list.yview)
        self.packet_list.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_list.pack(fill=tk.BOTH, expand=True)

        # Alert Console
        alert_frame = ttk.Labelframe(main_frame, text="Security Alerts", bootstyle=DANGER)
        alert_frame.pack(fill=tk.BOTH, pady=5)

        self.alert_console = scrolledtext.ScrolledText(
            alert_frame,
            height=8,
            font=('Consolas', 9),
            wrap=tk.WORD
        )
        self.alert_console.pack(fill=tk.BOTH, expand=True)
        self.alert_console.tag_config('HIGH', foreground='red')
        self.alert_console.tag_config('MEDIUM', foreground='orange')
        self.alert_console.tag_config('LOW', foreground='green')

    def start_live_capture(self):
        """Start live network capture"""
        interface = self.select_interface()
        if interface is None:
            return

        self.running = True
        self.test_mode = False
        self.toggle_buttons(False)
        self.clear_displays()

        capture_thread = threading.Thread(target=self.run_capture, args=(interface,))
        capture_thread.daemon = True
        capture_thread.start()

        # Start update timer
        self.after(100, self.update_display)

    def run_capture(self, interface):
        """Capture network traffic"""
        try:
            self.ids.packet_processor.start()
            sniff(
                iface=interface,
                prn=self.ids.packet_handler,
                store=0,
                filter="tcp",
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            self.show_error(f"Capture Error: {str(e)}")
        finally:
            self.stop_capture()

    def run_test_mode(self):
        """Execute test mode with simulated packets"""
        self.running = True
        self.test_mode = True
        self.toggle_buttons(False)
        self.clear_displays()

        test_thread = threading.Thread(target=self.execute_test)
        test_thread.daemon = True
        test_thread.start()

        # Start update timer
        self.after(100, self.update_display)

    def execute_test(self):
        """Generate test packets"""
        test_packets = [
            IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=1234, dport=80, flags="S")/Raw(b"Normal packet"),
            IP(src="10.0.0.1", dst="192.168.1.1")/TCP(sport=80, dport=1234, flags="SA"),
            IP(src="192.168.1.100", dst="8.8.8.8")/TCP(sport=54321, dport=53, flags="PA")/Raw(b"Malicious\x00\x01\x02\x03"),
            IP(src="192.168.1.1", dst="192.168.1.255")/TCP(sport=9999, dport=8080, flags="FA"),
            IP(src="203.0.113.5", dst="198.51.100.10")/TCP(sport=443, dport=65432, flags="UAPRSF")/Raw(b"\x00\x01\x02\x03")
        ]

        try:
            self.ids.packet_processor.start()
            for packet in test_packets:
                if not self.running:
                    break
                self.ids.packet_handler(packet)
                time.sleep(0.5)
        except Exception as e:
            self.show_error(f"Test Error: {str(e)}")
        finally:
            self.stop_capture()

    def update_display(self):
        """Update GUI components with new data"""
        if not self.running:
            return

        while not self.ids.packet_processor.result_queue.empty():
            try:
                features = self.ids.packet_processor.result_queue.get_nowait()
                score = self.ids.calculate_anomaly_score(features)
                self.update_stats(score)
                self.add_packet_entry(features, score)
                if score >= 0.4:  # Only add alerts for medium and high risk
                    self.add_alert(features, score)
            except queue.Empty:
                break

        # Schedule next update
        self.after(100, self.update_display)

    def update_stats(self, score):
        """Update statistics panel"""
        total = int(self.stats_labels['total']['text'].split(': ')[-1]) + 1
        self.stats_labels['total'].configure(text=f"Total Packets: {total}")

        if score > 0.7:
            key = 'high'
        elif score > 0.4:
            key = 'medium'
        else:
            key = 'low'

        current = int(self.stats_labels[key]['text'].split(': ')[-1]) + 1
        self.stats_labels[key].configure(text=f"{key.capitalize()} Risk: {current}")

    def add_packet_entry(self, features, score):
        """Add entry to packet list with ML information"""
        flags = ', '.join([k for k, v in features.get('flags', {}).items() if v])
        ml_score = self.ids.ml_detector.predict(features)
        values = (
            features['timestamp'],
            f"{features['source_ip']}:{features['source_port']}",
            f"{features['dest_ip']}:{features['dest_port']}",
            features['packet_size'],
            f"{score:.2f} (ML: {ml_score:.2f})",
            flags
        )
        self.packet_list.insert('', tk.END, values=values)
        
        # Keep only last 1000 entries
        children = self.packet_list.get_children()
        if len(children) > 1000:
            self.packet_list.delete(children[0])

    def add_alert(self, features, score):
        """Add alert to console with ML analysis"""
        report = self.ids.generate_report(features, score)
        tag = 'HIGH' if score > 0.7 else 'MEDIUM'
        
        self.alert_console.configure(state=tk.NORMAL)
        self.alert_console.insert(tk.END, report + "\n", tag)
        self.alert_console.configure(state=tk.DISABLED)
        self.alert_console.see(tk.END)

    def select_interface(self):
        """Show interface selection dialog"""
        interfaces = psutil.net_if_addrs().keys()
        return simpledialog.askstring(
            "Interface Selection",
            "Enter network interface (blank for all):\n\nAvailable interfaces:\n" + 
            '\n'.join(interfaces)
        )

    def toggle_buttons(self, enable):
        """Toggle button states"""
        state = tk.NORMAL if enable else tk.DISABLED
        self.start_btn['state'] = state
        self.test_btn['state'] = state
        self.stop_btn['state'] = tk.DISABLED if enable else tk.NORMAL

    def clear_displays(self):
        """Clear all displays"""
        for label in self.stats_labels.values():
            label.configure(text=label['text'].split(': ')[0] + ": 0")
        self.packet_list.delete(*self.packet_list.get_children())
        self.alert_console.configure(state=tk.NORMAL)
        self.alert_console.delete(1.0, tk.END)
        self.alert_console.configure(state=tk.DISABLED)

    def stop_capture(self):
        """Stop current capture"""
        self.running = False
        self.ids.packet_processor.stop()
        self.toggle_buttons(True)

    def show_error(self, message):
        """Show error message dialog"""
        messagebox.showerror("Error", message, parent=self)

    def on_close(self):
        """Handle window close event"""
        if messagebox.askokcancel("Quit", "Do you want to exit the application?"):
            self.stop_capture()
            self.destroy()

if __name__ == "__main__":
    try:
        app = IDSGUI()
        app.mainloop()
    except Exception as e:
        logging.error(f"Application error: {str(e)}")
        sys.exit(1)