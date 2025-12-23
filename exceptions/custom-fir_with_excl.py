#!/var/ossec/framework/python/bin/python3

import sys
import os
import json
import hashlib
import yaml
import requests
from datetime import datetime
from socket import socket, AF_UNIX, SOCK_DGRAM

EXIT_SUCCESS = 0
EXIT_INVALID_ALERT = 1
EXIT_NO_CONFIG = 2
EXIT_FIR_ERROR = 3
EXIT_UNKNOWN_ERROR = 4

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

def extract_notification_fields(config, alert):
    notification_fields = {}
    
    if 'notification_extract_rules' in config:
        for field_name, path in config['notification_extract_rules'].items():
            notification_fields[field_name] = str(get_nested(alert, path))
    
    notification_fields['timestamp'] = datetime.now().isoformat()
    notification_fields['alert_id'] = str(alert.get('id', ''))
    
    return notification_fields

def send_to_fir(config, alert, FIR_URL, FIR_TOKEN):
    fir_config = config.get('fir')
    
    notification_fields = extract_notification_fields(config, alert)
    
    subject = fir_config.get('subject', 'Alert')
    for field_name, value in notification_fields.items():
        subject = subject.replace(f"{{{field_name}}}", str(value))
    
    description = fir_config.get('description_template', '')
    for field_name, value in notification_fields.items():
        description = description.replace(f"{{{field_name}}}", str(value))
        
    fir_data = {
        "subject": subject,
        "description": description,
        "severity": fir_config.get('severity', 3),
        "category": fir_config.get('category', 'wazuh_alert'),
        "is_incident": fir_config.get('is_incident', True),
        "detection": fir_config.get('detection', 'Wazuh'),
        "confidentiality": fir_config.get('confidentiality', "C1")
    }
    
    try:
        headers = {
            "X-API": f"Token {FIR_TOKEN}",
            "Content-Type": "application/json"
        }
        
        response = requests.post(
            FIR_URL,
            json=fir_data,
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 201:
            result = response.json()
            return True
        else:
            return False
            
    except Exception as e:
        return False

def main():

    # CLI args
    if len(sys.argv) < 2:
        sys.exit(EXIT_INVALID_ALERT)
    
    alert_file = sys.argv[1]
    FIR_TOKEN = sys.argv[2]
    FIR_URL = sys.argv[3]
    
    # parse alert
    try:
        with open(alert_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    alert = json.loads(line)
                    break
            else:
                sys.exit(EXIT_INVALID_ALERT)
    except Exception:
        sys.exit(EXIT_INVALID_ALERT)
    
    try:
        # parse rule id
        rule_id = str(alert.get('rule', {}).get('id', ''))
        if not rule_id:
            sys.exit(EXIT_INVALID_ALERT)
        # load config
        config_path = f"{CONFIGS_DIR}/rules/{rule_id}.yaml"
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f)
        except:
            sys.exit(EXIT_NO_CONFIG)
        # load exception file
        exceptions_file = f"{CONFIGS_DIR}/exceptions/{rule_id}.json"
        exceptions = set()

        if os.path.exists(exceptions_file):
            try:
                with open(exceptions_file) as f:
                    exceptions = set(json.load(f))
            except:
                pass
        # check exception
        if exceptions and 'field_order' in config:
            exception_fields = {}
            for field_name in config['field_order']:
                path = config.get('extract_rules', {}).get(field_name, f"data.{field_name}")
                exception_fields[field_name] = str(get_nested(alert, path))
            
            hash_str = '|'.join(exception_fields.get(f, '') for f in config['field_order'])
            event_hash = hashlib.md5(hash_str.encode()).hexdigest()
            
            if event_hash in exceptions:
                sys.exit(EXIT_SUCCESS)  # excl, nothing to do
        # send to fir
        if 'fir' in config:
            if send_to_fir(config, alert, FIR_URL, FIR_TOKEN):
                sys.exit(EXIT_SUCCESS)
            else:
                sys.exit(EXIT_FIR_ERROR)
        
        """
        # send to wazuh
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
        """

        sys.exit(EXIT_SUCCESS)
        
    except Exception as e:
        sys.exit(EXIT_UNKNOWN_ERROR)

if __name__ == "__main__":
    main()