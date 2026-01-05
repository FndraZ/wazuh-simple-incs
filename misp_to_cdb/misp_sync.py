#!/usr/bin/env python3

import yaml
import os
import subprocess
import socket
from urllib.parse import urlparse
from pymisp import PyMISP
import urllib3

urllib3.disable_warnings()

WAZUH_LISTS_PATH = "/var/ossec/etc/lists"
RESTART_COMMAND = "/var/ossec/bin/wazuh-control restart"

def is_ip(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
        return True
    except:
        try:
            socket.inet_pton(socket.AF_INET6, address)
            return True
        except:
            return False

def extract_domain(url):
    try:
        host = urlparse(url).hostname
        if host and not is_ip(host):
            return host.lower()
    except:
        pass
    return None

def process_list(misp, list_config):
    name = list_config['name']
    event_id = list_config['event_id']
    filename = list_config['file']
    format_str = list_config['format']
    
    print(f"\n{name} (Event #{event_id}):")
    
    try:
        event = misp.get_event(event_id, pythonify=True)
        print(f"  Event: {event.info}")
        values = []
        
        for attr in event.attributes:
            if filename.endswith("domains"):  # URL список
                if attr.type == 'url':
                    domain = extract_domain(attr.value)
                    if domain:
                        values.append(domain)
            else:  # IP список
                if attr.type in ['ip-src', 'ip-dst']:
                    values.append(attr.value)
        
        unique_values = list(set(values))
        print(f"  Found: {len(unique_values)}")
        
        if not unique_values:
            print("  Empty list")
            return None
        
        cdb_lines = []
        for value in sorted(unique_values):
            line = format_str.replace('{value}', value)
            cdb_lines.append(line)
        
        print(f"  First 10 records:")
        for i, line in enumerate(cdb_lines[:10]):
            print(f"    {i+1}. {line}")
        
        temp_file = f"/tmp/{filename}"
        with open(temp_file, 'w') as f:
            f.write('\n'.join(cdb_lines))
        
        print(f"  File: {temp_file}")
        return temp_file
        
    except Exception as e:
        print(f"  Error: {e}")
        return None

def fetch_attributes(misp, attr_type, tags=None):
    params = {
        'type_attribute': attr_type,
        'pythonify': True
    }
    if tags:
        params['tags'] = tags
    
    return misp.search(controller='attributes', **params)

def process_attribute_list(misp, list_config):
    name = list_config['name']
    attr_type = list_config['attribute_type']
    filename = list_config['file']
    format_str = list_config['format']
    tags = list_config.get('tags')
    
    print(f"\n{name} (Type: {attr_type}):")
    
    try:
        attributes = fetch_attributes(misp, attr_type, tags)
        print(f"  Attributes found: {len(attributes)}")
        
        if not attributes:
            print("  Empty list")
            return None
        
        values = [attr.value for attr in attributes]
        unique_values = list(set(values))
        print(f"  Unique values: {len(unique_values)}")
        
        cdb_lines = []
        for value in sorted(unique_values):
            line = format_str.replace('{value}', value)
            cdb_lines.append(line)
        
        # Примеры
        print(f"  Примеры:")
        for i, line in enumerate(cdb_lines[:5]):
            print(f"    {i+1}. {line}")
        
        temp_file = f"/tmp/{filename}"
        with open(temp_file, 'w') as f:
            f.write('\n'.join(cdb_lines))
        
        print(f"  File: {temp_file}")
        return temp_file
        
    except Exception as e:
        print(f"  Error: {e}")
        return None

def deploy_files(files, target, container=None):
    if not files:
        print("\nNo files for deployment")
        return
    
    print(f"\nDeploy ({target}):")
    
    for filepath in files:
        filename = os.path.basename(filepath)
        
        if target == "docker":
            docker_cmd = ["docker", "cp", filepath, f"{container}:{WAZUH_LISTS_PATH}/{filename}"]
            print(f"  docker cp {filename} -> {container}")
            subprocess.run(docker_cmd, check=True)
        else:
            local_cmd = ["cp", filepath, f"{WAZUH_LISTS_PATH}/{filename}"]
            print(f"  cp {filename} -> {WAZUH_LISTS_PATH}")
            subprocess.run(local_cmd, check=True)

def restart_wazuh(target, container=None):
    print(f"\nRestart Wazuh ({target}):")
    
    if target == "docker":
        cmd = ["docker", "exec", container, "bash", "-c", "/var/ossec/bin/wazuh-control restart"]
    else:
        cmd = ["bash", "-c", "/var/ossec/bin/wazuh-control restart"]
    
    try:
        subprocess.run(cmd, check=True, timeout=60)
        print("  Success")
    except subprocess.TimeoutExpired:
        print("  Timeout")
    except Exception as e:
        print(f"  Error: {e}")

def main():
    print("=" * 60)
    print("MISP -> Wazuh sync")
    print("=" * 60)
    
    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    misp = PyMISP(config['misp_url'], config['misp_key'], False)
    print(f"MISP: {config['misp_url']}")
    
    target = config.get('deployment_target', 'local')
    container = config.get('docker_container')
    
    files_to_deploy = []
    
    for lst in config['lists']:
        temp_file = process_attribute_list(misp, lst)
        if temp_file:
            files_to_deploy.append(temp_file)

    # deploy_files(files_to_deploy, target, container)
    # restart_wazuh(target, container)
    
    print(f"\nDone!")

if __name__ == "__main__":
    main()