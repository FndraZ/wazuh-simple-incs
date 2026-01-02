#!/var/ossec/framework/python/bin/python3

import sys
from common_functions import *

EXIT_SUCCESS = 0
EXIT_INVALID_ALERT = 1
EXIT_NO_CONFIG = 2
EXIT_FIR_ERROR = 3
EXIT_REDIS_ERROR = 4

def main():
    if len(sys.argv) < 6:
        sys.exit(EXIT_INVALID_ALERT)
    
    alert_file = sys.argv[1]
    FIR_TOKEN = sys.argv[2]
    FIR_URL = sys.argv[3]
    
    try:
        with open(alert_file, 'r') as f:
            alert = json.load(f)
    except:
        sys.exit(EXIT_INVALID_ALERT)
    if not alert:
        sys.exit(EXIT_INVALID_ALERT)
    
    rule_id = str(alert.get('rule').get('id'))
    config = load_rule_config(rule_id)
    if not config:
        sys.exit(EXIT_NO_CONFIG)
    
    fields = extract_fields(alert, config)
    
    if config.get('check_exclusions', False):
        if check_event_exclusion(fields, rule_id):
            sys.exit(EXIT_SUCCESS)

    redis_conn, redis_ttl = init_redis(sys.argv[5])
    if redis_conn == "error":
        sys.exit(EXIT_REDIS_ERROR)

    event_hash = generate_event_hash(fields, config['field_order'])
    creation_key = f"w:task_monitoring:{event_hash}"
    
    if rule_id == "67014": # CREATE
        timestamp = alert.get('timestamp', '')
        redis_conn.set(creation_key, timestamp, ex=86400) #24h
        sys.exit(EXIT_SUCCESS)
        
    elif rule_id == "67015": # DELETE
        deleted_count = redis_conn.delete(creation_key)
        if deleted_count > 0:
            key = f"w:{rule_id}:{event_hash}"
            result = redis_conn.set(key, "1", ex=redis_ttl, nx=True)
            if result is None:
                sys.exit(EXIT_SUCCESS)

            if send_alert_to_fir(alert, config, FIR_URL, FIR_TOKEN):
                sys.exit(EXIT_SUCCESS)
            else:
                sys.exit(EXIT_FIR_ERROR)
        
        sys.exit(EXIT_SUCCESS)
    
    sys.exit(EXIT_SUCCESS)

if __name__ == "__main__":
    main()