#!/var/ossec/framework/python/bin/python3
"""
custom-exceptions.py - проверка исключений для Wazuh
"""
import sys
import os
import json
import hashlib
import yaml
from datetime import datetime
from socket import socket, AF_UNIX, SOCK_DGRAM

SOCKET_PATH = "/var/ossec/queue/sockets/queue"
CONFIGS_DIR = "/var/ossec/etc/custom-exceptions"

def get_nested(data, path):
    keys = path.split('.')
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key)
        else:
            return ''
    return data or ''

def main():
    if len(sys.argv) < 2:
        sys.exit(1)
    
    alert_file = sys.argv[1]
    
    try:
        with open(alert_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    alert = json.loads(line)
                    break
            else:
                sys.exit(1)
    except Exception:
        sys.exit(1)
    
    try:
        rule_id = str(alert.get('rule', {}).get('id', ''))
        if not rule_id:
            sys.exit(1)
        
        config_path = f"{CONFIGS_DIR}/rules/{rule_id}.yaml"
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f)
        except:
            sys.exit(1)
        
        try:
            with open(f"{CONFIGS_DIR}/exceptions/{rule_id}.json") as f:
                exceptions = set(json.load(f))
        except:
            exceptions = set()
        
        fields = {}
        for field_name in config['field_order']:
            path = config.get('extract_rules', {}).get(field_name, f"data.{field_name}")
            fields[field_name] = str(get_nested(alert, path))
        
        hash_str = '|'.join(fields.get(f, '') for f in config['field_order'])
        event_hash = hashlib.md5(hash_str.encode()).hexdigest()
        
        if event_hash in exceptions:
            sys.exit(0)
        
        event = {
            "integration": "custom-exceptions",
            "rule_id": rule_id,
            "timestamp": datetime.now().isoformat(),
            "original_alert_id": alert.get('id'),
        }
        event.update(fields)
        
        json_str = json.dumps(event, separators=(',', ':'))
        agent = alert.get('agent', {})
        
        if agent.get('id') != '000':
            msg = f"1:[{agent['id']}] ({agent.get('name', 'unknown')}) {agent.get('ip', 'any')}->custom-exceptions:{json_str}"
        else:
            msg = f"1:custom-exceptions:{json_str}"
        
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_PATH)
        sock.send(msg.encode())
        sock.close()
        
        sys.exit(0)
        
    except Exception:
        sys.exit(1)

if __name__ == "__main__":
    main()