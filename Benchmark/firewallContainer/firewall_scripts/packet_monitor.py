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
        if 'suspicious_patterns' in packet_info or 'suspicious_uri_patterns' in packet_info:
            logger.warning(f"SECURITY ALERT: Suspicious HTTP traffic detected from {packet_info.get('source_ip')} to {packet_info.get('dest_ip')}")
            logger.warning(f"  Method: {packet_info.get('http_method', 'N/A')} URI: {packet_info.get('http_uri', 'N/A')}")
            if 'suspicious_patterns' in packet_info:
                logger.warning(f"  Body Threats: {packet_info['suspicious_patterns']}")
            if 'suspicious_uri_patterns' in packet_info:
                logger.warning(f"  URI Threats: {packet_info['suspicious_uri_patterns']}")

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

                # Also check for threats in all TCP traffic, not just HTTP
                elif packet_info.get('protocol') == 'TCP':
                    # Look for command patterns in any TCP payload
                    payload_text = '\n'.join(payload_lines)
                    threats = self.detect_suspicious_patterns(payload_text)
                    if threats:
                        packet_info['suspicious_patterns'] = threats

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
        # Parse HTTP payload for HTTP traffic from attacker network
        return (packet_info.get('protocol') == 'TCP' and
                packet_info.get('application') == 'HTTP' and
                packet_info.get('source_ip', '').startswith('192.168.100'))

    def parse_http_payload(self, payload_lines):
        """Parse HTTP request/response from payload lines with enhanced threat detection"""
        try:
            if not payload_lines:
                return None

            # Extract ASCII content from tcpdump -A output
            payload_text = self.extract_ascii_from_tcpdump(payload_lines)
            
            if not payload_text:
                return None

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
                        http_info['http_body'] = post_data[:2000]  # Limit size but keep more data

                        # Look for suspicious patterns in POST data
                        suspicious_patterns = self.detect_suspicious_patterns(post_data)
                        if suspicious_patterns:
                            http_info['suspicious_patterns'] = suspicious_patterns

                # Look for suspicious patterns in URI
                uri_patterns = self.detect_suspicious_patterns(request_match.group(2))
                if uri_patterns:
                    http_info['suspicious_uri_patterns'] = uri_patterns

                # Also check the entire payload for threats
                payload_threats = self.detect_suspicious_patterns(payload_text)
                if payload_threats:
                    if 'suspicious_patterns' in http_info:
                        http_info['suspicious_patterns'].extend(payload_threats)
                    else:
                        http_info['suspicious_patterns'] = payload_threats

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

    def extract_ascii_from_tcpdump(self, payload_lines):
        """Extract ASCII content from tcpdump -A output"""
        try:
            ascii_content = []
            
            for line in payload_lines:
                # Skip empty lines
                if not line.strip():
                    continue
                    
                # Handle hex dump lines (format: "\t0x0000:  4745 5420 2f20 4854  GET / HT")
                if line.startswith('\t0x') and '  ' in line:
                    # Extract ASCII part (after the double space)
                    parts = line.split('  ')
                    if len(parts) >= 2:
                        ascii_part = '  '.join(parts[1:]).strip()
                        if ascii_part and not ascii_part.startswith('.'):
                            ascii_content.append(ascii_part)
                else:
                    # Direct ASCII line
                    ascii_content.append(line.strip())
            
            full_content = '\n'.join(ascii_content)
            
            # Clean up common tcpdump artifacts
            full_content = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', full_content)  # Remove control chars
            full_content = re.sub(r'\.+$', '', full_content, flags=re.MULTILINE)  # Remove trailing dots
            
            return full_content.strip()
            
        except Exception as e:
            logger.debug(f"Error extracting ASCII from tcpdump: {e}")
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
                    try:
                        key, value = line.split(':', 1)
                        headers[key.strip().lower()] = value.strip()
                    except:
                        continue

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
        """Enhanced suspicious pattern detection for security analysis"""
        if not text:
            return None

        text_lower = text.lower()
        suspicious = []

        # Enhanced command injection patterns - more specific for reverse shell commands
        cmd_patterns = [
            # Specific reverse shell commands mentioned by user
            (r'/bin/bash', 'Command execution: /bin/bash'),
            (r'find\s+/.*-perm\s+4000', 'SUID binary enumeration: find with -perm 4000'),
            (r'cat\s+/root/.*\.txt', 'Privilege escalation: accessing root files'),
            (r'cat\s+/etc/passwd', 'System enumeration: reading passwd file'),
            (r'cat\s+/etc/shadow', 'Privilege escalation: reading shadow file'),
            
            # Common reverse shell patterns
            (r'(;|\||&|`|\$\()\s*(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig)', 'Command injection via shell metacharacters'),
            (r'(nc|netcat|bash|sh|cmd|powershell)\s+.*\s+\d+', 'Reverse shell attempt with netcat/bash'),
            (r'/bin/(bash|sh|cat|ls|ps|whoami|id)', 'Direct system command execution'),
            (r'(wget|curl)\s+http.*\|(bash|sh)', 'Remote script execution'),
            (r'(chmod|chown)\s+[0-7]{3,4}', 'File permission modification'),
            (r'(rm|del)\s+-rf?', 'Dangerous file deletion'),
            (r'echo\s+.*\s*>\s*/tmp/', 'File creation in tmp directory'),
            (r'python.*socket.*connect', 'Python reverse shell'),
            (r'perl.*socket.*connect', 'Perl reverse shell'),
            (r'ruby.*socket.*connect', 'Ruby reverse shell'),
            (r'php.*fsockopen', 'PHP reverse shell'),
            
            # Base64 encoded commands (common in attacks)
            (r'echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+-d', 'Base64 encoded command execution'),
            (r'base64\s+-d.*\|\s*(bash|sh)', 'Base64 decoded shell execution'),
            
            # Privilege escalation
            (r'sudo\s+-l', 'Sudo privilege enumeration'),
            (r'su\s+-', 'User switching attempt'),
            (r'passwd\s+root', 'Root password change attempt'),
            
            # Network reconnaissance
            (r'nmap\s+.*', 'Network scanning with nmap'),
            (r'ping\s+-c\s+\d+', 'Network ping reconnaissance'),
            (r'(arp|route|ifconfig|ip\s+addr)', 'Network interface enumeration'),
        ]

        for pattern, description in cmd_patterns:
            if re.search(pattern, text_lower):
                suspicious.append(description)

        # SQL injection patterns
        sql_patterns = [
            (r"(union|select|insert|update|delete|drop|create|alter)\s+.*\s+(from|into|table|database)", 'SQL injection: database manipulation'),
            (r"('|\")\s*(or|and)\s*('|\")?.*('|\")\s*=\s*('|\")", 'SQL injection: quote manipulation'),
            (r"(or|and)\s+\d+\s*=\s*\d+", 'SQL injection: numeric comparison'),
            (r";\s*(select|insert|update|delete|drop)", 'SQL injection: statement chaining'),
        ]

        for pattern, description in sql_patterns:
            if re.search(pattern, text_lower):
                suspicious.append(description)

        # XSS patterns
        xss_patterns = [
            (r"<script[^>]*>.*</script>", 'XSS: script tag injection'),
            (r"javascript:", 'XSS: javascript protocol'),
            (r"on(load|click|error|focus|blur)\s*=", 'XSS: event handler injection'),
            (r"(alert|confirm|prompt)\s*\(", 'XSS: popup function call'),
        ]

        for pattern, description in xss_patterns:
            if re.search(pattern, text_lower):
                suspicious.append(description)

        # Path traversal
        if '../' in text or '..\\' in text:
            suspicious.append("Path traversal: directory traversal attempt")

        # Reverse shell indicators
        reverse_shell_patterns = [
            (r"(nc|netcat|bash|sh)\s+.*\s+\d+\s*-e", 'Reverse shell: netcat with execute flag'),
            (r"(python|perl|ruby|php)\s+.*socket", 'Reverse shell: scripting language socket'),
            (r"/dev/tcp/.*:\d+", 'Reverse shell: bash TCP redirection'),
            (r"exec\s*\(.*socket", 'Reverse shell: exec with socket'),
        ]

        for pattern, description in reverse_shell_patterns:
            if re.search(pattern, text_lower):
                suspicious.append(description)

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

        # Track security threats with more granular counting
        if 'suspicious_patterns' in packet_info or 'suspicious_uri_patterns' in packet_info:
            self.stats['security_threats'] += 1
            
            all_patterns = []
            if 'suspicious_patterns' in packet_info:
                all_patterns.extend(packet_info['suspicious_patterns'])
            if 'suspicious_uri_patterns' in packet_info:
                all_patterns.extend(packet_info['suspicious_uri_patterns'])
                
            for pattern in all_patterns:
                pattern_lower = pattern.lower()
                if 'command' in pattern_lower or '/bin/bash' in pattern_lower or 'find' in pattern_lower:
                    self.stats['threat_command_injection'] += 1
                elif 'sql injection' in pattern_lower:
                    self.stats['threat_sql_injection'] += 1
                elif 'xss' in pattern_lower:
                    self.stats['threat_xss'] += 1
                elif 'reverse shell' in pattern_lower:
                    self.stats['threat_reverse_shell'] += 1
                elif 'path traversal' in pattern_lower:
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
    
    def create_compressed_packet(self, packet_info):
        """Create compressed packet with only essential information for agent analysis"""
        compressed = {
            'timestamp': packet_info.get('capture_time', 0),
            'src_ip': packet_info.get('source_ip'),
            'dst_ip': packet_info.get('dest_ip'),
            'src_port': packet_info.get('source_port'),
            'dst_port': packet_info.get('dest_port'),
            'protocol': packet_info.get('protocol'),
            'direction': packet_info.get('direction'),
            'application': packet_info.get('application')
        }
        
        # Add HTTP-specific data if available and relevant
        if packet_info.get('application') == 'HTTP':
            http_data = {}
            if packet_info.get('http_method'):
                http_data['method'] = packet_info['http_method']
            if packet_info.get('http_uri'):
                http_data['uri'] = packet_info['http_uri'][:200]  # Increased URI length
            
            # Include HTTP body snippet if it contains threats
            if packet_info.get('http_body') and (packet_info.get('suspicious_patterns') or packet_info.get('suspicious_uri_patterns')):
                http_data['body_snippet'] = packet_info['http_body'][:300]  # First 300 chars
            
            # Combine all HTTP threats
            all_threats = []
            if packet_info.get('suspicious_patterns'):
                all_threats.extend(packet_info['suspicious_patterns'])
            if packet_info.get('suspicious_uri_patterns'):
                all_threats.extend(packet_info['suspicious_uri_patterns'])
                
            if all_threats:
                http_data['threats'] = all_threats
            
            if http_data:
                compressed['http'] = http_data
        
        # Add threat indicators for any protocol
        all_threats = []
        if packet_info.get('suspicious_patterns'):
            all_threats.extend(packet_info['suspicious_patterns'])
        if packet_info.get('suspicious_uri_patterns'):
            all_threats.extend(packet_info['suspicious_uri_patterns'])
            
        if all_threats:
            compressed['threats'] = all_threats
            if packet_info.get('raw_payload'):
            # Limit raw payload size to prevent context window overflow
                raw_payload = packet_info['raw_payload']
                if len(raw_payload) > 1000:  # Limit to 1000 chars
                    compressed['raw_payload'] = raw_payload[:1000] + "... [TRUNCATED]"
                else:
                    compressed['raw_payload'] = raw_payload
        return compressed

    def get_flow_summary(self, time_window_minutes=5):
        """Get aggregated flow summary for firewall decision making"""
        current_time = time.time()
        window_start = current_time - (time_window_minutes * 60)
        
        flows = {}
        threat_ips = set()
        protocol_stats = {}
        port_stats = {}
        threat_details = {}  # Track specific threats per IP
        
        with self.packets_lock:
            for packet in self.packets:
                # Only analyze recent packets
                if packet.get('capture_time', 0) < window_start:
                    continue
                    
                src_ip = packet.get('source_ip')
                dst_ip = packet.get('dest_ip')
                if not src_ip or not dst_ip:
                    continue
                    
                # Create flow key
                flow_key = f"{src_ip}->{dst_ip}"
                
                if flow_key not in flows:
                    flows[flow_key] = {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'packet_count': 0,
                        'protocols': set(),
                        'ports_accessed': set(),
                        'first_seen': packet.get('capture_time', 0),
                        'last_seen': packet.get('capture_time', 0),
                        'has_threats': False,
                        'applications': set(),
                        'threat_types': set()
                    }
                
                # Update flow statistics
                flow = flows[flow_key]
                flow['packet_count'] += 1
                flow['last_seen'] = max(flow['last_seen'], packet.get('capture_time', 0))
                
                if packet.get('protocol'):
                    flow['protocols'].add(packet['protocol'])
                    protocol_stats[packet['protocol']] = protocol_stats.get(packet['protocol'], 0) + 1
                    
                if packet.get('dest_port'):
                    flow['ports_accessed'].add(packet['dest_port'])
                    port_stats[packet['dest_port']] = port_stats.get(packet['dest_port'], 0) + 1
                    
                if packet.get('application'):
                    flow['applications'].add(packet['application'])
                    
                # Track threats
                has_threats = False
                all_threats = []
                if packet.get('suspicious_patterns'):
                    all_threats.extend(packet['suspicious_patterns'])
                    has_threats = True
                if packet.get('suspicious_uri_patterns'):
                    all_threats.extend(packet['suspicious_uri_patterns'])
                    has_threats = True
                    
                if has_threats:
                    flow['has_threats'] = True
                    threat_ips.add(src_ip)
                    
                    # Track threat details per IP
                    if src_ip not in threat_details:
                        threat_details[src_ip] = []
                    threat_details[src_ip].extend(all_threats)
                    
                    # Add threat types to flow
                    for threat in all_threats:
                        if 'command' in threat.lower() or '/bin/bash' in threat.lower():
                            flow['threat_types'].add('command_execution')
                        elif 'reverse shell' in threat.lower():
                            flow['threat_types'].add('reverse_shell')
                        elif 'sql injection' in threat.lower():
                            flow['threat_types'].add('sql_injection')
                        elif 'xss' in threat.lower():
                            flow['threat_types'].add('xss')
                        elif 'privilege' in threat.lower() or 'root' in threat.lower():
                            flow['threat_types'].add('privilege_escalation')
        
        # Convert sets to lists for JSON serialization
        for flow in flows.values():
            flow['protocols'] = list(flow['protocols'])
            flow['ports_accessed'] = list(flow['ports_accessed'])
            flow['applications'] = list(flow['applications'])
            flow['threat_types'] = list(flow['threat_types'])
            flow['duration'] = flow['last_seen'] - flow['first_seen']
        
        return {
            'time_window_minutes': time_window_minutes,
            'total_flows': len(flows),
            'flows': list(flows.values()),
            'threat_ips': list(threat_ips),
            'threat_details': threat_details,  # Specific threats per IP
            'protocol_distribution': protocol_stats,
            'port_distribution': port_stats,
            'analysis_timestamp': current_time
        }

    def get_security_summary(self, time_window_minutes=5):
        """Get security-focused summary for agent analysis"""
        current_time = time.time()
        window_start = current_time - (time_window_minutes * 60)
        
        security_events = []
        ip_activity = {}
        suspicious_patterns = {}
        command_executions = []  # Track specific command executions
        
        with self.packets_lock:
            for packet in self.packets:
                if packet.get('capture_time', 0) < window_start:
                    continue
                    
                src_ip = packet.get('source_ip')
                if not src_ip:
                    continue
                    
                # Track IP activity
                if src_ip not in ip_activity:
                    ip_activity[src_ip] = {
                        'packet_count': 0,
                        'unique_ports': set(),
                        'protocols': set(),
                        'has_threats': False,
                        'threat_count': 0,
                        'first_seen': packet.get('capture_time', 0),
                        'last_seen': packet.get('capture_time', 0),
                        'threat_types': set()
                    }
                
                activity = ip_activity[src_ip]
                activity['packet_count'] += 1
                activity['last_seen'] = max(activity['last_seen'], packet.get('capture_time', 0))
                
                if packet.get('dest_port'):
                    activity['unique_ports'].add(packet['dest_port'])
                if packet.get('protocol'):
                    activity['protocols'].add(packet['protocol'])
                
                # Track security events with more detail
                all_threats = []
                if packet.get('suspicious_patterns'):
                    all_threats.extend(packet['suspicious_patterns'])
                if packet.get('suspicious_uri_patterns'):
                    all_threats.extend(packet['suspicious_uri_patterns'])
                    
                if all_threats:
                    activity['has_threats'] = True
                    activity['threat_count'] += len(all_threats)
                    
                    for pattern in all_threats:
                        # Categorize threats
                        if 'command' in pattern.lower() or '/bin/bash' in pattern.lower() or 'find' in pattern.lower():
                            activity['threat_types'].add('command_execution')
                            command_executions.append({
                                'src_ip': src_ip,
                                'dst_ip': packet.get('dest_ip'),
                                'timestamp': packet.get('capture_time', 0),
                                'command_pattern': pattern,
                                'http_method': packet.get('http_method'),
                                'http_uri': packet.get('http_uri')
                            })
                        elif 'reverse shell' in pattern.lower():
                            activity['threat_types'].add('reverse_shell')
                        elif 'privilege' in pattern.lower() or 'root' in pattern.lower():
                            activity['threat_types'].add('privilege_escalation')
                            
                        if pattern not in suspicious_patterns:
                            suspicious_patterns[pattern] = []
                        suspicious_patterns[pattern].append({
                            'src_ip': src_ip,
                            'dst_ip': packet.get('dest_ip'),
                            'timestamp': packet.get('capture_time', 0),
                            'application': packet.get('application'),
                            'port': packet.get('dest_port')
                        })
        
        # Convert to analysis format
        high_activity_ips = []
        scanning_ips = []
        threat_ips = []
        
        for ip, activity in ip_activity.items():
            activity['unique_ports'] = list(activity['unique_ports'])
            activity['protocols'] = list(activity['protocols'])
            activity['threat_types'] = list(activity['threat_types'])
            
            # Identify high activity (potential threats)
            if activity['packet_count'] > 50:  # Threshold for high activity
                high_activity_ips.append({
                    'ip': ip,
                    'packet_count': activity['packet_count'],
                    'unique_ports_count': len(activity['unique_ports']),
                    'has_threats': activity['has_threats'],
                    'threat_count': activity['threat_count'],
                    'threat_types': activity['threat_types']
                })
            
            # Identify scanning behavior
            if len(activity['unique_ports']) > 5:  # Threshold for port scanning
                scanning_ips.append({
                    'ip': ip,
                    'ports_scanned': len(activity['unique_ports']),
                    'packet_count': activity['packet_count'],
                    'scan_duration': activity['last_seen'] - activity['first_seen'],
                    'has_threats': activity['has_threats']
                })
            
            # Identify IPs with threats
            if activity['has_threats']:
                threat_ips.append({
                    'ip': ip,
                    'threat_count': activity['threat_count'],
                    'threat_types': activity['threat_types'],
                    'packet_count': activity['packet_count']
                })
        
        return {
            'time_window_minutes': time_window_minutes,
            'high_activity_ips': high_activity_ips,
            'scanning_ips': scanning_ips,
            'threat_ips': threat_ips,  # New: IPs with actual threats
            'command_executions': command_executions,  # New: Specific command execution attempts
            'threat_patterns': suspicious_patterns,
            'total_unique_ips': len(ip_activity),
            'total_threats_detected': len(command_executions),
            'analysis_timestamp': current_time
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
        return jsonify({'error': f'Internal server error\n{e}'}), 500

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
    
@app.route('/packets/compressed', methods=['GET'])
def get_compressed_packets():
    """Get compressed packets with essential data only"""
    try:
        limit = request.args.get('limit', 100, type=int)
        limit = min(limit, 500)  # Cap at 500 to prevent context overflow
        
        recent = request.args.get('recent', 5, type=int)  # Default to 5 minutes
        protocol = request.args.get('protocol')
        direction = request.args.get('direction')
        
        # Get filtered packets
        packets = packet_monitor.get_packets(
            limit=limit,
            protocol_filter=protocol,
            direction_filter=direction,
            recent_minutes=recent
        )
        
        # Compress packets
        compressed_packets = []
        for packet in packets:
            compressed = packet_monitor.create_compressed_packet(packet)
            compressed_packets.append(compressed)
        
        return jsonify({
            'timestamp': datetime.now().isoformat(),
            'count': len(compressed_packets),
            'packets': compressed_packets,
            'time_window_minutes': recent
        })
        
    except Exception as e:
        logger.error(f"Error getting compressed packets: {e}")
        return jsonify({'error': f'Internal server error\n{e}'}), 500

@app.route('/analysis/flows', methods=['GET'])
def get_flow_analysis():
    """Get flow-based analysis for firewall decisions"""
    try:
        time_window = request.args.get('window', 5, type=int)
        time_window = min(time_window, 30)  # Cap at 30 minutes
        
        summary = packet_monitor.get_flow_summary(time_window)
        return jsonify(summary)
        
    except Exception as e:
        logger.error(f"Error getting flow analysis: {e}")
        return jsonify({'error': f'Internal server error\n{e}'}), 500

@app.route('/analysis/security', methods=['GET'])
def get_security_analysis():
    """Get security-focused analysis for threat detection"""
    try:
        time_window = request.args.get('window', 5, type=int)
        time_window = min(time_window, 30)  # Cap at 30 minutes
        
        summary = packet_monitor.get_security_summary(time_window)
        return jsonify(summary)
        
    except Exception as e:
        logger.error(f"Error getting security analysis: {e}")
        return jsonify({'error': f'Internal server error\n{e}' }), 500


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