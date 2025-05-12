import json 
import docker


def getNetworkStatus(file_path="/home/c0ff3k1ll3r/Desktop/Thesis/AI_Agent_for_honeypot_operations/logsSSH/tshark_pcap/ssh_traffic.json") -> dict:
    """
    Retrieve current network activity from parsed logs.
    
    Parameters:
    - file_path (str): Path to the JSON file containing tshark output
    
    Returns:
    - dict: network activity
    """
    
    
    try:
        # Load the JSON data from tshark output
        with open(file_path, 'r') as file:
            raw_data = json.load(file)
        
        
    except Exception as e:
        return {
            "error": "Processing error",
            "details": str(e)
        }
    return json.dumps(raw_data)

rules = [
    "iptables -P INPUT DROP",
    "iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
    "iptables -A INPUT -p tcp --dport 2222 -j ACCEPT",
    "iptables -A INPUT -p tcp --sport 2222 -j ACCEPT",
    "iptables -A INPUT -s 172.17.0.1 -j DROP",
    "iptables -A INPUT -s 172.17.0.2 -j DROP",
    "iptables -A INPUT -p tcp --dport 2222 -m limit --limit 10/minute --limit-burst 3 -j ACCEPT",
    "iptables -I INPUT -p tcp --match multiport --dports 45502:45630 -j DROP"
]

def getFirewallConfiguration():
    """Retrieve the list of current firewall rules."""
    return {
        "firewall_rules": []
        }

def getDockerContainers():
    """
    Returns information about running Docker containers using the Docker API,
    including their internal private IP addresses.
    
    Returns:
        list: A list of dictionaries containing container information
    """
    try:
        # Initialize the Docker client
        client = docker.from_env()
        
        # Get list of running containers
        containers = client.containers.list()
        # Format container information similar to "docker ps" output
        container_info = []
        for container in containers:
            
            # Get container's IP address from network settings
            ip_address = None
            networks = container.attrs.get('NetworkSettings', {}).get('Networks', {})
            
            # Iterate through networks and get the first IP address found
            # (Most containers have a single network, but some might have multiple)
            for network_name, network_config in networks.items():
                if network_config.get('IPAddress'):
                    ip_address = network_config.get('IPAddress')
                    break
            
            info = {
                'id': container.id[:12],  # Short ID
                'name': container.name,
                'image': container.image.tags[0] if container.image.tags else container.image.id[:12],
                'status': container.status,
                'created': container.attrs['Created'],
                'ports': container.ports,
                'ip_address': ip_address
            }
            
        return container_info
        
    except docker.errors.DockerException as e:
        return {"error": f"Docker connection error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}


def getPastRules():
    """Retrieve past rules from the database."""
    pass

def firwallUpdate():
    """Update the firewall rules using system commands based on the analysis of network traffic logs."""
    pass