#!/usr/bin/env python3
"""
Firewall Management API
Provides REST API for AI agent to control firewall rules dynamically
"""

from flask import Flask, request, jsonify
import subprocess
import json
import logging
import os
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/firewall/logs/firewall.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

class FirewallManager:
    def __init__(self):
        self.rules_file = '/firewall/rules/current_rules.txt'
        self.log_file = '/firewall/logs/firewall.log'
        
    def execute_command(self, command):
        """Execute shell command and return result"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            return result.returncode == 0, result.stdout, result.stderr
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return False, "", str(e)
    
    def add_allow_rule(self, source_ip, dest_ip, port=None, protocol='tcp'):
        """Add rule to allow traffic"""
        if port:
            rule = f"iptables -I FORWARD -s {source_ip} -d {dest_ip} -p {protocol} --dport {port} -j ACCEPT"
        else:
            rule = f"iptables -I FORWARD -s {source_ip} -d {dest_ip} -j ACCEPT"
        
        success, stdout, stderr = self.execute_command(rule)
        if success:
            logger.info(f"Added ALLOW rule: {source_ip} -> {dest_ip}:{port}")
            self.save_rules()
        else:
            logger.error(f"Failed to add ALLOW rule: {stderr}")
        
        return success
    
    def add_block_rule(self, source_ip, dest_ip, port=None, protocol='tcp'):
        """Add rule to block traffic"""
        if port:
            rule = f"iptables -I FORWARD -s {source_ip} -d {dest_ip} -p {protocol} --dport {port} -j DROP"
        else:
            rule = f"iptables -I FORWARD -s {source_ip} -d {dest_ip} -j DROP"
        
        success, stdout, stderr = self.execute_command(rule)
        if success:
            logger.info(f"Added BLOCK rule: {source_ip} -> {dest_ip}:{port}")
            self.save_rules()
        else:
            logger.error(f"Failed to add BLOCK rule: {stderr}")
        
        return success
    
    def remove_rule(self, rule_number):
        """Remove rule by number"""
        rule = f"iptables -D FORWARD {rule_number}"
        success, stdout, stderr = self.execute_command(rule)
        if success:
            logger.info(f"Removed rule number: {rule_number}")
            self.save_rules()
        else:
            logger.error(f"Failed to remove rule: {stderr}")
        
        return success
    
    def list_rules(self):
        """List current iptables rules"""
        success, stdout, stderr = self.execute_command("iptables -L FORWARD -n --line-numbers")
        if success:
            return stdout
        else:
            logger.error(f"Failed to list rules: {stderr}")
            return ""
    
    def save_rules(self):
        """Save current rules to file"""
        success, stdout, stderr = self.execute_command(f"iptables-save > {self.rules_file}")
        if not success:
            logger.error(f"Failed to save rules: {stderr}")
    
    def get_traffic_stats(self):
        """Get traffic statistics"""
        success, stdout, stderr = self.execute_command("iptables -L FORWARD -n -v")
        if success:
            return stdout
        else:
            return ""

# Initialize firewall manager
firewall = FirewallManager()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'firewall-manager'
    })

@app.route('/rules', methods=['GET'])
def get_rules():
    """Get current firewall rules"""
    rules = firewall.list_rules()
    return jsonify({
        'rules': rules,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/rules/allow', methods=['POST'])
def add_allow_rule():
    """Add allow rule"""
    data = request.get_json()
    
    required_fields = ['source_ip', 'dest_ip']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    source_ip = data['source_ip']
    dest_ip = data['dest_ip']
    port = data.get('port')
    protocol = data.get('protocol', 'tcp')
    
    success = firewall.add_allow_rule(source_ip, dest_ip, port, protocol)
    
    if success:
        return jsonify({
            'status': 'success',
            'message': f'Allow rule added: {source_ip} -> {dest_ip}:{port}',
            'timestamp': datetime.now().isoformat()
        })
    else:
        return jsonify({
            'status': 'error',
            'message': 'Failed to add allow rule'
        }), 500

@app.route('/rules/block', methods=['POST'])
def add_block_rule():
    """Add block rule"""
    data = request.get_json()
    
    required_fields = ['source_ip', 'dest_ip']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    source_ip = data['source_ip']
    dest_ip = data['dest_ip']
    port = data.get('port')
    protocol = data.get('protocol', 'tcp')
    
    success = firewall.add_block_rule(source_ip, dest_ip, port, protocol)
    
    if success:
        return jsonify({
            'status': 'success',
            'message': f'Block rule added: {source_ip} -> {dest_ip}:{port}',
            'timestamp': datetime.now().isoformat()
        })
    else:
        return jsonify({
            'status': 'error',
            'message': 'Failed to add block rule'
        }), 500

@app.route('/rules/<int:rule_number>', methods=['DELETE'])
def remove_rule(rule_number):
    """Remove rule by number"""
    success = firewall.remove_rule(rule_number)
    
    if success:
        return jsonify({
            'status': 'success',
            'message': f'Rule {rule_number} removed',
            'timestamp': datetime.now().isoformat()
        })
    else:
        return jsonify({
            'status': 'error',
            'message': f'Failed to remove rule {rule_number}'
        }), 500

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get traffic statistics"""
    stats = firewall.get_traffic_stats()
    return jsonify({
        'stats': stats,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/reset', methods=['POST'])
def reset_firewall():
    """Reset firewall to initial state"""
    # Re-initialize firewall rules
    success, stdout, stderr = firewall.execute_command('/firewall/scripts/init_firewall.sh')
    
    if success:
        return jsonify({
            'status': 'success',
            'message': 'Firewall reset to initial state',
            'timestamp': datetime.now().isoformat()
        })
    else:
        return jsonify({
            'status': 'error',
            'message': 'Failed to reset firewall'
        }), 500

if __name__ == '__main__':
    logger.info("Starting Firewall Management API...")
    app.run(host='0.0.0.0', port=5000, debug=False)
