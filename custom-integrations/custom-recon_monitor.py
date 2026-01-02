#!/var/ossec/framework/python/bin/python3
# need test it
import sys
from common_functions import *
import time

EXIT_SUCCESS = 0
EXIT_INVALID_ALERT = 1
EXIT_NO_CONFIG = 2
EXIT_FIR_ERROR = 3
EXIT_REDIS_ERROR = 4

LUA_SCRIPT_SHA = "abc123..."

def process_recon_stats(redis_conn, hostname, event_hash, config):
    current_ts = int(time.time())
    result = redis_conn.evalsha(
        LUA_SCRIPT_SHA,
        2,
        f"recon:stats:{hostname}",
        f"recon:flood:{hostname}",
        event_hash,
        str(current_ts),
        str(config['window_hours'] * 3600),
        str(config.get('incident_flood_ttl', 3600)),
        str(config['threshold'])
    )
    return result == 1 # should_send

def main():
    if len(sys.argv) < 6:
        sys.exit(EXIT_INVALID_ALERT)
    
    alert_file   = sys.argv[1]
    FIR_TOKEN    = sys.argv[2]
    FIR_URL      = sys.argv[3]
    REDIS_CONFIG = sys.argv[5]
    
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
    event_hash = generate_event_hash(fields, config['field_order'])
    
    if check_event_exclusion(event_hash, rule_id):
        sys.exit(EXIT_SUCCESS)
        
    redis_conn, redis_ttl = init_redis(REDIS_CONFIG)
    
    if redis_conn == "error":
        sys.exit(EXIT_REDIS_ERROR)
    
    try:
        if not redis_conn.script_exists(LUA_SCRIPT_SHA)[0]:
            sys.exit(EXIT_REDIS_ERROR)
    except:
        sys.exit(EXIT_REDIS_ERROR)
        
    try:
        should_send = process_recon_stats(redis_conn, fields[hostname], event_hash, config)
    except redis.exceptions.NoScriptError:
        sys.exit(EXIT_REDIS_ERROR)
    except Exception as e:
        sys.exit(EXIT_REDIS_ERROR)
    
    if should_send:
        if send_alert_to_fir(alert, config, FIR_URL, FIR_TOKEN):
            sys.exit(EXIT_SUCCESS)
        else:
            sys.exit(EXIT_FIR_ERROR)
    
    sys.exit(EXIT_SUCCESS)

if __name__ == "__main__":
    main()