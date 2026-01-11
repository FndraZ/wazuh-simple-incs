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
        
    source_ip = fields.get('source', '')
    target = fields.get('target', '')
    username = fields.get('username', '')
    login_type = fields.get('login_type', '')
    
    thresholds = config.get('thresholds', {})    
    
    try:
        lua_result_raw = redis_conn.evalsha(
            lua_sha,
            0,
            config.get('event_type'),
            source_ip,
            target,
            username,
            login_type,
            str(int(time.time())),
            str(redis_ttl),
            str(thresholds.get('regular', 10)),
            str(thresholds.get('multi_source', 5)),
            str(thresholds.get('multi_user', 3))
        )
        
        lua_result = json.loads(lua_result_raw)
        
    except redis.exceptions.NoScriptError:
        sys.exit(EXIT_SCRIPT_NOT_FOUND)
    except Exception as e:
        sys.exit(EXIT_REDIS_ERROR)
    
    if not lua_result.get('should_alert', False):
        sys.exit(EXIT_SUCCESS)
    
    dedup_string = f"{source_ip}|{target}|{username}|{login_type}|{rule_id}"
    dedup_string += f"|{lua_result.get('bruteforce_type', 'none')}"
    
    dedup_hash = hashlib.md5(dedup_string.encode()).hexdigest()
    event_dedup_key = f"bruteforce:event:{dedup_hash}"
    
    dedup_result = redis_conn.set(event_dedup_key, "1", ex=redis_ttl, nx=True)
    if dedup_result is None:
        sys.exit(EXIT_SUCCESS)
    
    extra_fields = {
        'bruteforce_detected': str(lua_result.get('is_bruteforce', False)),
        'bruteforce_type': lua_result.get('bruteforce_type', 'none'),
        'regular_attempts': str(lua_result.get('metrics', {}).get('regular_attempts', 0)),
        'unique_sources': str(lua_result.get('metrics', {}).get('unique_sources', 0)),
        'unique_targets': str(lua_result.get('metrics', {}).get('unique_targets', 0)),
        'unique_users': str(lua_result.get('metrics', {}).get('unique_users', 0))
    }

    if not send_alert_to_fir(alert, config, FIR_URL, FIR_TOKEN, extra_fields):
        try:
            redis_conn.delete(event_dedup_key)
        except:
            pass
        sys.exit(EXIT_FIR_ERROR)
    
    sys.exit(EXIT_SUCCESS)

if __name__ == "__main__":
    main()