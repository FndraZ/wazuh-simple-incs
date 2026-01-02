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

    event_hash = generate_event_hash(fields, config['field_order'])    
    redis_conn, redis_ttl = init_redis(sys.argv[5])

    if redis_conn and redis_conn != "error":
        key = f"w:{rule_id}:{event_hash}"
        result = redis_conn.set(key, "1", ex=redis_ttl, nx=True)
        if result is None:
            sys.exit(EXIT_SUCCESS)
    
    if send_alert_to_fir(alert, config, FIR_URL, FIR_TOKEN):
        if redis_conn == "error":
            sys.exit(EXIT_REDIS_ERROR)
        sys.exit(EXIT_SUCCESS)
    else:
        sys.exit(EXIT_FIR_ERROR)

if __name__ == "__main__":
    main()