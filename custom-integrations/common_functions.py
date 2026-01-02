#!/var/ossec/framework/python/bin/python3

import os
import json
import yaml
import hashlib
import redis
import requests

CONFIGS_DIR = "/var/ossec/etc/custom-exceptions"

def get_nested(data, path):
    keys = path.split('.')
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key)
        else:
            return default
    return str(data) if data is not None else default

def extract_fields(alert, config):
    fields = {}
    for field_name in config.get('field_order'):
        path = config.get('extract_rules', {}).get(field_name, f"data.{field_name}")
        fields[field_name] = get_nested(alert, path)
    return fields

def load_rule_config(rule_id):
    config_path = f"{CONFIGS_DIR}/rules/{rule_id}.yaml"
    try:
        with open(config_path) as f:
            return yaml.safe_load(f)
    except:
        return None

def load_exceptions(rule_id):
    excl_file = f"{CONFIGS_DIR}/exceptions/{rule_id}.json"
    if os.path.exists(excl_file):
        try:
            with open(excl_file) as f:
                return set(json.load(f))
        except:
            pass
    return set()

def init_redis(options_path):
    try:
        if os.path.isfile(options_path):
            with open(options_path, "r", encoding="utf-8") as f:
                options = json.load(f)
                
                redis_host = options.get("redis_host", "localhost")
                redis_port = int(options.get("redis_port", 6379))
                redis_db = int(options.get("redis_db", 0))
                redis_ttl = int(options.get("redis_ttl", 3600))
                
                r = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    db=redis_db,
                    socket_connect_timeout=2,
                    socket_timeout=2,
                    decode_responses=True
                )
                r.ping()
                return r, redis_ttl
        return "error", 0
    except:
        return "error", 0

def check_event_exclusion(event_hash, rule_id):
    exceptions = load_exceptions(rule_id)
    return event_hash in exceptions if exceptions else False

def generate_event_hash(fields, field_order):
    hash_str = '|'.join(fields.get(f, '') for f in field_order)
    return hashlib.md5(hash_str.encode()).hexdigest()

def check_event_exclusion(fields_dict, rule_id):
    exceptions = load_exceptions(rule_id)
    if not exceptions:
        return False
    
    for exclusion in exceptions:
        match = True
        
        for field, excl_value in exclusion.items():
            event_value = fields_dict.get(field, '')
            
            if excl_value == '*':
                continue
                
            if str(event_value) != str(excl_value):
                match = False
                break
        
        if match:
            return True
    
    return False

def send_alert_to_fir(alert, config, fir_url, fir_token):
    notification_fields = {}
    
    for field_name, path in config['notification_extract_rules'].items():
        notification_fields[field_name] = str(get_nested(alert, path))
    
    notification_fields['timestamp'] = str(alert.get('timestamp'))
    notification_fields['alert_id'] = str(alert.get('id'))
    
    fir_config = config.get('fir')
    
    subject = fir_config.get('subject').format(**notification_fields)
    description = fir_config.get('description_template').format(**notification_fields)
    
    fir_payload = {
        "subject": subject,
        "description": description,
        "severity": fir_config.get('severity', 3),
        "category": fir_config.get('category', 'wazuh_alert'),
        "is_incident": True,
        "detection": 'Wazuh',
        "confidentiality": fir_config.get('confidentiality', "C1")
    }
    
    try:
        headers = {
            "X-API": f"Token {fir_token}",
            "Content-Type": "application/json"
        }
        
        response = requests.post(
            fir_url,
            json=fir_payload,
            headers=headers,
            timeout=10
        )
        
        return response.status_code == 201
    except:
        return False