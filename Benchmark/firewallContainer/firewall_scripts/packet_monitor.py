#!/usr/bin/env python3
"""
Packet Monitor API Service - Enhanced with HTTP Payload Analysis
Captures packets from attacker network and provides REST API for AI agent access
Listens on agent_net (192.168.200.0/30) and monitors attacker_net (192.168.100.0/24)

Enhanced Features:
- HTTP payload capture and parsing for security analysis
- Automatic detection of command injection, SQL injection, XSS, reverse shells
- Deep packet inspection for HTTP traffic from attacker network
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
        """Build tcpdump command to capture attacker network traffic with payload"""
        # Focus on attacker network traffic (192.168.100.0/24)
        # Capture TCP, UDP, ICMP, and HTTP protocols with full payload
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
            '-A',                     # Print packet payload in ASCII (for HTTP content)
            '-s', '65535',            # Capture full packets (max size)
            '-l',                     # Line buffered output
            filter_expr
        ]

        return cmd

    def is_packet_header(self, line):
        """Check if line is a packet header (contains timestamp and IPs)"""
        # Look for timestamp pattern and IP addresses
        return (re.search(r'\d{2}:\d{2}:\d{2}\.\d+', line) and
                re.search(r'\d+\.\d+\.\d+\.\d+', line) and
                ('>' in line))

    def process_tcpdump_output(self):
        """Process tcpdump output and store packets with payload analysis"""
        logger.info("Starting packet capture processing with HTTP payload analysis...")

        try:
            packet_buffer = []
            current_packet_header = None

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

                    # Check if this is a new packet header (contains timestamp and IP addresses)
                    if self.is_packet_header(line_str):
                        # Process previous packet if exists
                        if current_packet_header and packet_buffer:
                            packet_info = self.parse_complete_packet(current_packet_header, packet_buffer)
                            if packet_info:
                                self.store_packet(packet_info)

                        # Start new packet
                        current_packet_header = line_str
                        packet_buffer = []
                    else:
                        # This is packet payload data
                        packet_buffer.append(line_str)

                except Exception as e:
                    logger.error(f"Error processing packet line: {e}")
                    continue

            # Process final packet if exists
            if current_packet_header and packet_buffer:
                packet_info = self.parse_complete_packet(current_packet_header, packet_buffer)
                if packet_info:
                    self.store_packet(packet_info)

        except Exception as e:
            logger.error(f"Error in packet processing: {e}")
        finally:
            logger.info("Packet processing stopped")

    def store_packet(self, packet_info):
        """Store packet in memory and file"""
        # Store packet in memory
        with self.packets_lock:
            self.packets.append(packet_info)

        # Update statistics
        self.update_stats(packet_info)

        # Write to file
        self.write_packet_to_file(packet_info)

        # Log progress and security alerts
        if self.packet_count % 100 == 0:
            logger.info(f"Captured {self.packet_count} packets")

        # Log security alerts for suspicious HTTP traffic
        if 'suspicious_patterns' in packet_info:
            logger.warning(f"SECURITY ALERT: Suspicious HTTP traffic detected from {packet_info.get('source_ip')} to {packet_info.get('dest_ip')}")
            logger.warning(f"  Method: {packet_info.get('http_method', 'N/A')} URI: {packet_info.get('http_uri', 'N/A')}")
            logger.warning(f"  Threats: {packet_info['suspicious_patterns']}")

    def parse_complete_packet(self, header_line, payload_lines):
        """Parse complete packet with header and payload"""
        try:
            self.packet_count += 1
            timestamp = datetime.now()

            packet_info = {
                'timestamp': timestamp.isoformat(),
                'packet_id': self.packet_count,
                'raw_header': header_line.strip(),
                'capture_time': timestamp.timestamp()
            }

            # Parse the header line for basic packet info
            basic_info = self.parse_packet_header(header_line)
            if not basic_info:
                return None

            packet_info.update(basic_info)

            # Add raw payload if present
            if payload_lines:
                packet_info['raw_payload'] = '\n'.join(payload_lines)

                # Parse HTTP payload if this is HTTP traffic from attacker network
                if self.should_parse_http_payload(packet_info):
                    http_info = self.parse_http_payload(payload_lines)
                    if http_info:
                        packet_info.update(http_info)

            return packet_info

        except Exception as e:
            logger.debug(f"Error parsing complete packet: {header_line[:50]}... Error: {e}")
            return None

    def parse_packet_header(self, header_line):
        """Parse tcpdump packet header line into structured data"""
        try:
            # Example: 10:30:45.123456 IP 192.168.100.10.54321 > 172.20.0.2.80: Flags [P.]

            # Parse TCP packets
            tcp_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): (.+)', header_line)
            if tcp_match:
                source_ip = tcp_match.group(1)
                source_port = int(tcp_match.group(2))
                dest_ip = tcp_match.group(3)
                dest_port = int(tcp_match.group(4))
                flags_info = tcp_match.group(5).strip()

                packet_info = {
                    'protocol': 'TCP',
                    'source_ip': source_ip,
                    'source_port': source_port,
                    'dest_ip': dest_ip,
                    'dest_port': dest_port,
                    'flags_info': flags_info,
                    'direction': self.get_traffic_direction(source_ip, dest_ip)
                }

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
            udp_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): UDP', header_line)
            if udp_match:
                source_ip = udp_match.group(1)
                dest_ip = udp_match.group(3)

                packet_info = {
                    'protocol': 'UDP',
                    'source_ip': source_ip,
                    'source_port': int(udp_match.group(2)),
                    'dest_ip': dest_ip,
                    'dest_port': int(udp_match.group(4)),
                    'direction': self.get_traffic_direction(source_ip, dest_ip)
                }

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
            icmp_match = re.search(r'(\d+\.\d+\.\d+\.\d+) > (\d+\.\d+\.\d+\.\d+): ICMP (.+)', header_line)
            if icmp_match:
                source_ip = icmp_match.group(1)
                dest_ip = icmp_match.group(2)

                packet_info = {
                    'protocol': 'ICMP',
                    'source_ip': source_ip,
                    'dest_ip': dest_ip,
                    'icmp_info': icmp_match.group(3).strip(),
                    'direction': self.get_traffic_direction(source_ip, dest_ip)
                }
                return packet_info

            return None

        except Exception as e:
            logger.debug(f"Error parsing header: {header_line[:50]}... Error: {e}")
            return None

    def should_parse_http_payload(self, packet_info):
        """Determine if we should parse HTTP payload for this packet"""
        # Only parse HTTP payload for:
        # 1. TCP traffic on HTTP ports (80, 8080)
        # 2. Traffic from attacker network (outbound or internal)
        return (packet_info.get('protocol') == 'TCP' and
                packet_info.get('application') == 'HTTP' and
                packet_info.get('direction') in ['outbound', 'internal'] and
                packet_info.get('source_ip', '').startswith('192.168.100'))

    def parse_http_payload(self, payload_lines):
        """Parse HTTP request/response from payload lines"""
        try:
            if not payload_lines:
                return None

            # Join all payload lines
            payload_text = '\n'.join(payload_lines)

            # Remove hex dump formatting and extract ASCII content
            ascii_lines = []
            for line in payload_lines:
                # Skip hex offset lines and extract ASCII content
                if not line.startswith('\t0x'):
                    ascii_lines.append(line)
                else:
                    # Extract ASCII part from hex dump line (after the hex bytes)
                    # Format: "\t0x0000:  4745 5420 2f20 4854  GET / HT"
                    ascii_part = line.split('  ')[-1] if '  ' in line else ''
                    if ascii_part.strip():
                        ascii_lines.append(ascii_part.strip())

            payload_text = '\n'.join(ascii_lines)

            # Look for HTTP request patterns
            http_info = {}

            # Parse HTTP request line (GET, POST, etc.)
            request_match = re.search(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)\s+HTTP/([0-9.]+)', payload_text, re.MULTILINE)
            if request_match:
                http_info.update({
                    'http_type': 'request',
                    'http_method': request_match.group(1),
                    'http_uri': request_match.group(2),
                    'http_version': request_match.group(3)
                })

                # Parse HTTP headers
                headers = self.extract_http_headers(payload_text)
                if headers:
                    http_info['http_headers'] = headers

                # Parse POST data if present
                if request_match.group(1) == 'POST':
                    post_data = self.extract_http_body(payload_text)
                    if post_data:
                        http_info['http_body'] = post_data

                        # Look for suspicious patterns in POST data
                        suspicious_patterns = self.detect_suspicious_patterns(post_data)
                        if suspicious_patterns:
                            http_info['suspicious_patterns'] = suspicious_patterns

                # Look for suspicious patterns in URI
                uri_patterns = self.detect_suspicious_patterns(request_match.group(2))
                if uri_patterns:
                    http_info['suspicious_uri_patterns'] = uri_patterns

            # Parse HTTP response
            response_match = re.search(r'^HTTP/([0-9.]+)\s+(\d+)\s+([^\r\n]+)', payload_text, re.MULTILINE)
            if response_match:
                http_info.update({
                    'http_type': 'response',
                    'http_version': response_match.group(1),
                    'http_status_code': int(response_match.group(2)),
                    'http_status_message': response_match.group(3).strip()
                })

                # Parse response headers
                headers = self.extract_http_headers(payload_text)
                if headers:
                    http_info['http_headers'] = headers

                # Parse response body
                response_body = self.extract_http_body(payload_text)
                if response_body:
                    http_info['http_body'] = response_body[:1000]  # Limit size

            return http_info if http_info else None

        except Exception as e:
            logger.debug(f"Error parsing HTTP payload: {e}")
            return None

    def extract_http_headers(self, payload_text):
        """Extract HTTP headers from payload"""
        try:
            headers = {}
            lines = payload_text.split('\n')

            # Find header section (after request/response line, before empty line)
            in_headers = False
            for line in lines:
                line = line.strip()
                if not line:
                    break

                # Skip request/response line
                if (line.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH')) or
                    line.startswith('HTTP/')):
                    in_headers = True
                    continue

                if in_headers and ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()

            return headers if headers else None
        except:
            return None

    def extract_http_body(self, payload_text):
        """Extract HTTP body from payload"""
        try:
            # Find empty line that separates headers from body
            lines = payload_text.split('\n')
            body_start = -1

            for i, line in enumerate(lines):
                if not line.strip():
                    body_start = i + 1
                    break

            if body_start >= 0 and body_start < len(lines):
                body_lines = lines[body_start:]
                body = '\n'.join(body_lines).strip()
                return body if body else None

            return None
        except:
            return None

    def detect_suspicious_patterns(self, text):
        """Detect suspicious patterns in HTTP content for security analysis"""
        if not text:
            return None

        text_lower = text.lower()
        suspicious = []

        # Command injection patterns
        cmd_patterns = [
            r'(;|\||&|`|\$\()\s*(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig)',
            r'(nc|netcat|bash|sh|cmd|powershell)\s+.*\s+\d+',
            r'/bin/(bash|sh|cat|ls|ps)',
            r'(wget|curl)\s+http',
            r'(chmod|chown)\s+\d+',
            r'(rm|del)\s+-rf?',
            r'echo\s+.*\s*>\s*/tmp/',
        ]

        for pattern in cmd_patterns:
            if re.search(pattern, text_lower):
                suspicious.append(f"Command injection pattern: {pattern}")

        # SQL injection patterns
        sql_patterns = [
            r"(union|select|insert|update|delete|drop|create|alter)\s+.*\s+(from|into|table|database)",
            r"('|\")\s*(or|and)\s*('|\")?.*('|\")\s*=\s*('|\")",
            r"(or|and)\s+\d+\s*=\s*\d+",
            r";\s*(select|insert|update|delete|drop)",
        ]

        for pattern in sql_patterns:
            if re.search(pattern, text_lower):
                suspicious.append(f"SQL injection pattern: {pattern}")

        # XSS patterns
        xss_patterns = [
            r"<script[^>]*>.*</script>",
            r"javascript:",
            r"on(load|click|error|focus|blur)\s*=",
            r"(alert|confirm|prompt)\s*\(",
        ]

        for pattern in xss_patterns:
            if re.search(pattern, text_lower):
                suspicious.append(f"XSS pattern: {pattern}")

        # Path traversal
        if '../' in text or '..\\' in text:
            suspicious.append("Path traversal pattern")

        # Reverse shell indicators
        reverse_shell_patterns = [
            r"(nc|netcat|bash|sh)\s+.*\s+\d+\s*-e",
            r"(python|perl|ruby|php)\s+.*socket",
            r"/dev/tcp/.*:\d+",
            r"exec\s*\(.*socket",
        ]

        for pattern in reverse_shell_patterns:
            if re.search(pattern, text_lower):
                suspicious.append(f"Reverse shell pattern: {pattern}")

        return suspicious if suspicious else None

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

        # Track security threats
        if 'suspicious_patterns' in packet_info:
            self.stats['security_threats'] += 1
            for pattern in packet_info['suspicious_patterns']:
                if 'command injection' in pattern.lower():
                    self.stats['threat_command_injection'] += 1
                elif 'sql injection' in pattern.lower():
                    self.stats['threat_sql_injection'] += 1
                elif 'xss' in pattern.lower():
                    self.stats['threat_xss'] += 1
                elif 'reverse shell' in pattern.lower():
                    self.stats['threat_reverse_shell'] += 1
                elif 'path traversal' in pattern.lower():
                    self.stats['threat_path_traversal'] += 1

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
            logger.info(f"Starting tcpdump with HTTP payload analysis: {' '.join(cmd)}")

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

            logger.info("Packet capture with HTTP analysis started successfully")
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

    def get_packets(self, limit=100, since_timestamp=None, protocol_filter=None, direction_filter=None, recent_minutes=None):
        """Get packets with optional filtering"""
        with self.packets_lock:
            packets = list(self.packets)

        # Apply recent filter first if specified
        if recent_minutes:
            recent_timestamp = (datetime.now() - timedelta(minutes=recent_minutes)).timestamp()
            packets = [p for p in packets if p['capture_time'] >= recent_timestamp]

        # Apply other filters
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
            'running': self.running,
            'stats': dict(self.stats)
        }

    def get_protocol_summary(self):
        """Get protocol distribution"""
        protocols = defaultdict(int)
        with self.packets_lock:
            for packet in self.packets:
                proto = packet.get('protocol', 'UNKNOWN')
                protocols[proto] += 1
        return dict(protocols)

    def get_top_flows(self, limit=10):
        """Get top traffic flows"""
        flows = defaultdict(int)
        with self.packets_lock:
            for packet in self.packets:
                if 'source_ip' in packet and 'dest_ip' in packet:
                    flow = f"{packet['source_ip']} -> {packet['dest_ip']}"
                    flows[flow] += 1

        # Return top flows sorted by count
        sorted_flows = sorted(flows.items(), key=lambda x: x[1], reverse=True)
        return dict(sorted_flows[:limit])

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
    """Enhanced packets endpoint with optional statistics and raw format"""
    try:
        # Parse query parameters
        limit = request.args.get('limit', 100, type=int)
        since = request.args.get('since')  # ISO timestamp
        protocol = request.args.get('protocol')
        direction = request.args.get('direction')
        recent = request.args.get('recent', type=int)  # Recent X minutes

        # New optional parameters
        include_stats = request.args.get('stats', 'false').lower() == 'true'
        include_protocols = request.args.get('protocols', 'false').lower() == 'true'
        include_flows = request.args.get('flows', 'false').lower() == 'true'
        raw_only = request.args.get('raw_only', 'false').lower() == 'true'

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
            direction_filter=direction,
            recent_minutes=recent
        )

        # Build response
        response = {
            'timestamp': datetime.now().isoformat(),
            'count': len(packets),
            'total_captured': packet_monitor.packet_count,
        }

        # Add packets data
        if raw_only:
            # Return only raw tcpdump header lines for minimal processing
            response['raw_lines'] = [p.get('raw_header', '') for p in packets]
        else:
            # Return full structured packet data
            response['packets'] = packets

        # Optionally include statistics
        if include_stats:
            response['statistics'] = packet_monitor.get_stats()

        # Optionally include protocol summary
        if include_protocols:
            response['protocol_summary'] = packet_monitor.get_protocol_summary()

        # Optionally include top flows
        if include_flows:
            response['top_flows'] = packet_monitor.get_top_flows()

        return jsonify(response)

    except Exception as e:
        logger.error(f"Error getting packets: {e}")
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
    logger.info("=== Enhanced Packet Monitor API Service Starting ===")
    logger.info("Features: HTTP payload analysis, threat detection, security monitoring")

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
        logger.info("=== Enhanced Packet Monitor API Service Stopped ===")

if __name__ == '__main__':
    main()
