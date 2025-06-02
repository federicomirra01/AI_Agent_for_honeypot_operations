#!/usr/bin/env python3
"""
Packet Monitor API Service
Captures packets from attacker network and provides REST API for AI agent access
Listens on agent_net (192.168.200.0/30) and monitors attacker_net (192.168.100.0/24)
"""

import json
import subprocess
import threading
import time
import logging
import re
from datetime import datetime, timedelta
from collections import defaultdict, deque
import os
import sys
import signal
from flask import Flask, request, jsonify

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/firewall/logs/packet_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class PacketMonitorAPI:
    def __init__(self, max_packets_memory=10000):
        self.running = False
        self.packet_count = 0
        self.stats = defaultdict(int)
        self.tcpdump_process = None
        
        # In-memory packet storage (circular buffer)
        self.packets = deque(maxlen=max_packets_memory)
        self.packets_lock = threading.Lock()
        
        # Output files
        self.json_file = '/firewall/logs/packets.json'
        self.stats_file = '/firewall/logs/packet_stats.json'
        
        # Network configuration
        self.attacker_network = "192.168.100.0/24"
        self.agent_api_host = "192.168.200.2"  # Listen on agent network
        self.agent_api_port = 6000
        
    def build_tcpdump_command(self):
        """Build tcpdump command to capture attacker network traffic"""
        # Focus on attacker network traffic (192.168.100.0/24)
        # Capture TCP, UDP, ICMP, and HTTP protocols
        filter_parts = [
            # Traffic from attacker network
            f"(src net {self.attacker_network} and (tcp or udp or icmp))",
            # Traffic to attacker network  
            f"(dst net {self.attacker_network} and (tcp or udp or icmp))",
            # HTTP/HTTPS traffic involving attacker network
            f"(net {self.attacker_network} and (port 80 or port 443 or port 8080))"
        ]
        
        filter_expr = " or ".join(filter_parts)
        
        cmd = [
            'tcpdump',
            '-i', 'any',              # Capture on all interfaces
            '-n',                     # Don't resolve hostnames
            '-q',                     # Quiet output
            '-t',                     # Don't print timestamps
            '-l',                     # Line buffered output
            '-s', '0',                # Capture full packets
            filter_expr
        ]
        
        return cmd
    
    def parse_packet_line(self, line):
        """Parse tcpdump output line into structured packet data"""
        try:
            if not line.strip():
                return None
                
            self.packet_count += 1
            timestamp = datetime.now()
            
            packet_info = {
                'timestamp': timestamp.isoformat(),
                'packet_id': self.packet_count,
                'raw_line': line.strip(),
                'capture_time': timestamp.timestamp()
            }
            
            # Parse TCP packets
            tcp_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): (.+)', line)
            if tcp_match:
                source_ip = tcp_match.group(1)
                source_port = int(tcp_match.group(2))
                dest_ip = tcp_match.group(3)
                dest_port = int(tcp_match.group(4))
                flags_info = tcp_match.group(5).strip()
                
                packet_info.update({
                    'protocol': 'TCP',
                    'source_ip': source_ip,
                    'source_port': source_port,
                    'dest_ip': dest_ip,
                    'dest_port': dest_port,
                    'flags_info': flags_info,
                    'direction': self.get_traffic_direction(source_ip, dest_ip)
                })
                
                # Classify application protocols
                if dest_port in [80, 8080] or source_port in [80, 8080]:
                    packet_info['application'] = 'HTTP'
                elif dest_port == 443 or source_port == 443:
                    packet_info['application'] = 'HTTPS'
                elif dest_port == 22 or source_port == 22:
                    packet_info['application'] = 'SSH'
                elif dest_port == 21 or source_port == 21:
                    packet_info['application'] = 'FTP'
                elif dest_port == 23 or source_port == 23:
                    packet_info['application'] = 'TELNET'
                elif dest_port == 25 or source_port == 25:
                    packet_info['application'] = 'SMTP'
                
                return packet_info
            
            # Parse UDP packets
            udp_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): UDP', line)
            if udp_match:
                source_ip = udp_match.group(1)
                dest_ip = udp_match.group(3)
                
                packet_info.update({
                    'protocol': 'UDP',
                    'source_ip': source_ip,
                    'source_port': int(udp_match.group(2)),
                    'dest_ip': dest_ip,
                    'dest_port': int(udp_match.group(4)),
                    'direction': self.get_traffic_direction(source_ip, dest_ip)
                })
                
                # Classify UDP applications
                dest_port = int(udp_match.group(4))
                if dest_port == 53:
                    packet_info['application'] = 'DNS'
                elif dest_port in [67, 68]:
                    packet_info['application'] = 'DHCP'
                elif dest_port == 123:
                    packet_info['application'] = 'NTP'
                
                return packet_info
            
            # Parse ICMP packets
            icmp_match = re.search(r'(\d+\.\d+\.\d+\.\d+) > (\d+\.\d+\.\d+\.\d+): ICMP (.+)', line)
            if icmp_match:
                source_ip = icmp_match.group(1)
                dest_ip = icmp_match.group(2)
                
                packet_info.update({
                    'protocol': 'ICMP',
                    'source_ip': source_ip,
                    'dest_ip': dest_ip,
                    'icmp_info': icmp_match.group(3).strip(),
                    'direction': self.get_traffic_direction(source_ip, dest_ip)
                })
                return packet_info
                
            return None
            
        except Exception as e:
            logger.debug(f"Error parsing line: {line[:50]}... Error: {e}")
            return None
    
    def get_traffic_direction(self, source_ip, dest_ip):
        """Determine traffic direction relative to attacker network"""
        attacker_prefix = "192.168.100"
        
        source_is_attacker = source_ip.startswith(attacker_prefix)
        dest_is_attacker = dest_ip.startswith(attacker_prefix)
        
        if source_is_attacker and not dest_is_attacker:
            return "outbound"  # From attacker to external
        elif not source_is_attacker and dest_is_attacker:
            return "inbound"   # From external to attacker
        elif source_is_attacker and dest_is_attacker:
            return "internal"  # Within attacker network
        else:
            return "external"  # Neither source nor dest is attacker
    
    def process_tcpdump_output(self):
        """Process tcpdump output and store packets"""
        logger.info("Starting packet capture processing...")
        
        try:
            while self.running and self.tcpdump_process:
                line = self.tcpdump_process.stdout.readline()
                if not line:
                    if self.tcpdump_process.poll() is not None:
                        break
                    continue
                    
                try:
                    line_str = line.decode('utf-8', errors='ignore').strip()
                    if not line_str:
                        continue
                    
                    packet_info = self.parse_packet_line(line_str)
                    if packet_info:
                        # Store packet in memory and file
                        with self.packets_lock:
                            self.packets.append(packet_info)
                        
                        # Update statistics
                        self.update_stats(packet_info)
                        
                        # Write to file
                        self.write_packet_to_file(packet_info)
                        
                        # Log progress
                        if self.packet_count % 100 == 0:
                            logger.info(f"Captured {self.packet_count} packets")
                
                except Exception as e:
                    logger.error(f"Error processing packet line: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error in packet processing: {e}")
        finally:
            logger.info("Packet processing stopped")
    
    def update_stats(self, packet_info):
        """Update packet statistics"""
        if 'protocol' in packet_info:
            self.stats[f"protocol_{packet_info['protocol']}"] += 1
        
        if 'direction' in packet_info:
            self.stats[f"direction_{packet_info['direction']}"] += 1
        
        if 'application' in packet_info:
            self.stats[f"app_{packet_info['application']}"] += 1
        
        if 'source_ip' in packet_info and 'dest_ip' in packet_info:
            flow = f"{packet_info['source_ip']} -> {packet_info['dest_ip']}"
            self.stats[f"flow_{flow}"] += 1
    
    def write_packet_to_file(self, packet_info):
        """Write packet to JSON file"""
        try:
            with open(self.json_file, 'a') as f:
                json.dump(packet_info, f, separators=(',', ':'))
                f.write('\n')
        except Exception as e:
            logger.error(f"Error writing packet to file: {e}")
    
    def start_capture(self):
        """Start packet capture with tcpdump"""
        try:
            # Check if tcpdump is available
            subprocess.run(['which', 'tcpdump'], check=True, capture_output=True)
            
            # Build and start tcpdump command
            cmd = self.build_tcpdump_command()
            logger.info(f"Starting tcpdump: {' '.join(cmd)}")
            
            self.tcpdump_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1
            )
            
            self.running = True
            
            # Start processing thread
            process_thread = threading.Thread(target=self.process_tcpdump_output)
            process_thread.daemon = True
            process_thread.start()
            
            logger.info("Packet capture started successfully")
            return True
            
        except subprocess.CalledProcessError:
            logger.error("tcpdump not found - install tcpdump package")
            return False
        except Exception as e:
            logger.error(f"Failed to start packet capture: {e}")
            return False
    
    def stop_capture(self):
        """Stop packet capture"""
        logger.info("Stopping packet capture...")
        self.running = False
        
        if self.tcpdump_process:
            try:
                self.tcpdump_process.terminate()
                self.tcpdump_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning("tcpdump didn't terminate gracefully, killing...")
                self.tcpdump_process.kill()
                self.tcpdump_process.wait()
            except Exception as e:
                logger.error(f"Error stopping tcpdump: {e}")
        
        logger.info("Packet capture stopped")
    
    def get_packets(self, limit=100, since_timestamp=None, protocol_filter=None, direction_filter=None):
        """Get packets with optional filtering"""
        with self.packets_lock:
            packets = list(self.packets)
        
        # Apply filters
        if since_timestamp:
            packets = [p for p in packets if p['capture_time'] >= since_timestamp]
        
        if protocol_filter:
            packets = [p for p in packets if p.get('protocol', '').upper() == protocol_filter.upper()]
        
        if direction_filter:
            packets = [p for p in packets if p.get('direction') == direction_filter]
        
        # Return most recent packets first, limited to specified count
        return packets[-limit:] if limit else packets
    
    def get_stats(self):
        """Get current statistics"""
        return {
            'total_packets': self.packet_count,
            'memory_packets': len(self.packets),
            'stats': dict(self.stats),
            'timestamp': datetime.now().isoformat(),
            'running': self.running
        }

# Initialize packet monitor
packet_monitor = PacketMonitorAPI()

# Create Flask app for API
app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'packet-monitor',
        'running': packet_monitor.running,
        'total_packets': packet_monitor.packet_count,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/packets', methods=['GET'])
def get_packets():
    """Get captured packets with optional filtering"""
    try:
        # Parse query parameters
        limit = request.args.get('limit', 100, type=int)
        since = request.args.get('since')  # ISO timestamp
        protocol = request.args.get('protocol')
        direction = request.args.get('direction')
        
        # Convert since timestamp if provided
        since_timestamp = None
        if since:
            try:
                since_dt = datetime.fromisoformat(since.replace('Z', '+00:00'))
                since_timestamp = since_dt.timestamp()
            except ValueError:
                return jsonify({'error': 'Invalid timestamp format'}), 400
        
        # Get filtered packets
        packets = packet_monitor.get_packets(
            limit=limit,
            since_timestamp=since_timestamp,
            protocol_filter=protocol,
            direction_filter=direction
        )
        
        return jsonify({
            'packets': packets,
            'count': len(packets),
            'total_captured': packet_monitor.packet_count,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting packets: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/packets/recent', methods=['GET'])
def get_recent_packets():
    """Get most recent packets (last 5 minutes)"""
    try:
        # Get packets from last 5 minutes
        five_minutes_ago = (datetime.now() - timedelta(minutes=5)).timestamp()
        packets = packet_monitor.get_packets(since_timestamp=five_minutes_ago)
        
        return jsonify({
            'packets': packets,
            'count': len(packets),
            'period': '5 minutes',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting recent packets: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/stats', methods=['GET'])
def get_statistics():
    """Get packet capture statistics"""
    try:
        stats = packet_monitor.get_stats()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/packets/protocols', methods=['GET'])
def get_protocols():
    """Get packets by protocol"""
    try:
        protocols = {}
        with packet_monitor.packets_lock:
            for packet in packet_monitor.packets:
                proto = packet.get('protocol', 'UNKNOWN')
                if proto not in protocols:
                    protocols[proto] = []
                protocols[proto].append(packet)
        
        return jsonify({
            'protocols': {k: len(v) for k, v in protocols.items()},
            'details': protocols,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting protocols: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/packets/flows', methods=['GET'])
def get_flows():
    """Get traffic flows summary"""
    try:
        flows = defaultdict(int)
        with packet_monitor.packets_lock:
            for packet in packet_monitor.packets:
                if 'source_ip' in packet and 'dest_ip' in packet:
                    flow = f"{packet['source_ip']} -> {packet['dest_ip']}"
                    flows[flow] += 1
        
        return jsonify({
            'flows': dict(flows),
            'total_flows': len(flows),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting flows: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/control/start', methods=['POST'])
def start_monitoring():
    """Start packet monitoring"""
    try:
        if packet_monitor.running:
            return jsonify({'message': 'Monitoring already running'}), 200
        
        if packet_monitor.start_capture():
            return jsonify({'message': 'Monitoring started successfully'})
        else:
            return jsonify({'error': 'Failed to start monitoring'}), 500
            
    except Exception as e:
        logger.error(f"Error starting monitoring: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/control/stop', methods=['POST'])
def stop_monitoring():
    """Stop packet monitoring"""
    try:
        packet_monitor.stop_capture()
        return jsonify({'message': 'Monitoring stopped'})
    except Exception as e:
        logger.error(f"Error stopping monitoring: {e}")
        return jsonify({'error': 'Internal server error'}), 500

def main():
    """Main function"""
    logger.info("=== Packet Monitor API Service Starting ===")
    
    # Create output directory
    os.makedirs('/firewall/logs', exist_ok=True)
    
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}")
        packet_monitor.stop_capture()
        sys.exit(0)
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Start packet capture
        if packet_monitor.start_capture():
            logger.info("Starting API server...")
            
            # Start Flask API server
            app.run(
                host=packet_monitor.agent_api_host,
                port=packet_monitor.agent_api_port,
                debug=False,
                threaded=True
            )
        else:
            logger.error("Failed to start packet capture")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        packet_monitor.stop_capture()
        logger.info("=== Packet Monitor API Service Stopped ===")

if __name__ == '__main__':
    main()