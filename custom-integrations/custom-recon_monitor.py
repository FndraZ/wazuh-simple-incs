#!/var/ossec/framework/python/bin/python3

import sys
import json
import hashlib
import time
from common_functions import *

EXIT_SUCCESS = 0
EXIT_INVALID_ALERT = 1
EXIT_NO_CONFIG = 2
EXIT_FIR_ERROR = 3
EXIT_REDIS_ERROR = 4
EXIT_SCRIPT_NOT_FOUND = 5

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
    
    if config.get('check_exclusions', False):
        if check_event_exclusion(fields, rule_id):
            sys.exit(EXIT_SUCCESS)
    
    redis_conn, redis_ttl = init_redis(REDIS_CONFIG)
    if redis_conn == "error":
        sys.exit(EXIT_REDIS_ERROR)
    
    lua_sha = config.get('lua_script_sha')
    if not lua_sha:
        sys.exit(EXIT_NO_CONFIG)
    
    try:
        if not redis_conn.script_exists(lua_sha)[0]:
            sys.exit(EXIT_SCRIPT_NOT_FOUND)
    except:
        sys.exit(EXIT_REDIS_ERROR)
    
    event_hash = generate_event_hash(fields, config.get('field_order', []))
    hostname = fields.get('hostname', '')
    current_ts = int(time.time())
    
    try:
        lua_result_raw = redis_conn.evalsha(
            lua_sha,
            1,
            f"recon:stats:{hostname}",
            event_hash,
            str(current_ts),
            str(config.get('window_hours', 1) * 3600),
            str(config.get('threshold', 10))
        )
        
        lua_result = json.loads(lua_result_raw)
        
    except redis.exceptions.NoScriptError:
        sys.exit(EXIT_SCRIPT_NOT_FOUND)
    except Exception as e:
        sys.exit(EXIT_REDIS_ERROR)
    
    if not lua_result.get('should_alert', False):
        sys.exit(EXIT_SUCCESS)
    
    flood_key = f"recon:flood:{hostname}"
    flood_result = redis_conn.set(flood_key, "1", ex=redis_ttl, nx=True)

    if flood_result is None:
        sys.exit(EXIT_SUCCESS)
    
    if not send_alert_to_fir(alert, config, FIR_URL, FIR_TOKEN):
        try:
            redis_conn.delete(flood_key)
        except:
            pass
        sys.exit(EXIT_FIR_ERROR)
    
    sys.exit(EXIT_SUCCESS)

if __name__ == "__main__":
    main()