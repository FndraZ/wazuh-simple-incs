#!/var/ossec/framework/python/bin/python3

import sys
import os
import json
import hashlib
import yaml
import requests
import redis
from socket import socket, AF_UNIX, SOCK_DGRAM

EXIT_SUCCESS = 0
EXIT_INVALID_ALERT = 1
EXIT_NO_CONFIG = 2
EXIT_FIR_ERROR = 3
EXIT_REDIS_ERROR = 5
EXIT_UNKNOWN_ERROR = 4

SOCKET_PATH = "/var/ossec/queue/sockets/queue"
CONFIGS_DIR = "/var/ossec/etc/custom-exceptions"

def init_redis_from_args():
    try:
        options_path = sys.argv[5]
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
        else:
            return "error", 0
    except Exception:
        return "error", 0

def check_redis_duplicate(redis_conn, rule_id, event_hash, ttl):
    try:
        key = f"w:{rule_id}:{event_hash}"
        result = redis_conn.set(key, "1", ex=ttl, nx=True)
        return result is None   
    except Exception:
        return False

def get_nested(data, path):
    keys = path.split('.')
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key)
        else:
            return ''
    return data or ''

def send_to_fir(config, alert, FIR_URL, FIR_TOKEN):
    notification_fields = {}
    
    for field_name, path in config['notification_extract_rules'].items():
        notification_fields[field_name] = str(get_nested(alert, path))
    
    notification_fields['timestamp'] = str(alert.get('timestamp'))
    notification_fields['alert_id'] = str(alert.get('id'))
    
    fir_config = config.get('fir')

    subject = fir_config.get('subject').format(**notification_fields)
    description = fir_config.get('description_template').format(**notification_fields)
        
    fir_data = {
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
    redis_error_exit = False
    
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
        # parse fields
        exception_fields = {}
        for field_name in config['field_order']:
            path = config.get('extract_rules', {}).get(field_name, f"data.{field_name}")
            exception_fields[field_name] = str(get_nested(alert, path))
        # get event hash
        hash_str = '|'.join(exception_fields.get(f, '') for f in config['field_order'])
        event_hash = hashlib.md5(hash_str.encode()).hexdigest()

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
        if exceptions:
            if event_hash in exceptions:
                sys.exit(EXIT_SUCCESS)  # excl, nothing to do
        # check flood
        redis_conn, redis_ttl = init_redis_from_args()
        if redis_conn and redis_conn != "error":
            is_duplicate = check_redis_duplicate(redis_conn, rule_id, event_hash, redis_ttl)
            if is_duplicate:
                sys.exit(EXIT_SUCCESS)  # flood, nothing to do
        # redis connection failed
        if redis_conn == "error":
            redis_error_exit = True
        # send to fir
        if 'fir' in config:
            if send_to_fir(config, alert, FIR_URL, FIR_TOKEN):
                if redis_error_exit:
                    sys.exit(EXIT_REDIS_ERROR)
                sys.exit(EXIT_SUCCESS)
            else:
                sys.exit(EXIT_FIR_ERROR)
        
        sys.exit(EXIT_UNKNOWN_ERROR)
        
    except Exception as e:
        sys.exit(EXIT_UNKNOWN_ERROR)

if __name__ == "__main__":
    main()