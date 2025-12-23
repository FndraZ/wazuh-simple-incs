#!/usr/bin/env python3
"""
вторая версия для утилит разведки, трубуется загрузить луа скрипт в редис и записать хеш-сумму сюда
"""

import sys
import json
import time
import hashlib
import redis
from datetime import datetime
from socket import socket, AF_UNIX, SOCK_DGRAM
from io import StringIO

REDIS_HOST = '192.168.1.11'
REDIS_PORT = 6380
THRESHOLD = 10                    # порог уникальных утилит
WINDOW_HOURS = 1                  # временное окно
RECORD_TTL = 10800                # 3 часа
SOCKET_PATH = '/var/ossec/queue/sockets/integrations'
LUA_SCRIPT_SHA = "e0a3467a10fbf5d4521ee252661aa2e74a1b9ecb"

def send_error_alert(error_type, message):
    try:
        alert = {
            "integration": "recon_monitor",
            "timestamp": int(time.time()),
            "error_type": error_type,
            "message": message,
            "severity": "high"
        }
        
        socket_msg = f"1:recon_monitor_error:{json.dumps(alert)}"
        
        with socket(AF_UNIX, SOCK_DGRAM) as sock:
            sock.connect(SOCKET_PATH)
            sock.send(socket_msg.encode())
        
        print(f"ERROR [{error_type}]: {message}", file=sys.stderr)
        
    except Exception as e:
        print(f"CRITICAL: Failed to send error alert: {e}", file=sys.stderr)

def parse_event(input_str):
    try:
        alert = json.loads(input_str)
        
        rule_id = alert.get('rule', {}).get('id', '')
        
        hostname = ''
        username = ''
        util = ''
        cmdline = ''
        
        # Linux Sysmon
        if rule_id == '200300':
            data = alert.get('data', {})
            hostname = data.get('system', {}).get('computer', '')
            username = data.get('eventdata', {}).get('user', '')
            util = data.get('eventdata', {}).get('image', '')
            cmdline = data.get('eventdata', {}).get('commandLine', '')
        
        print(f"DEBUG: Parsed - hostname: '{hostname}', user: '{username}', cmdline: '{cmdline}'", file=sys.stderr)
        
        if not hostname or not cmdline:
            print(f"DEBUG: Missing required fields. Hostname: {hostname}, Cmdline: {cmdline}", file=sys.stderr)
            return None
        
        return {
            'hostname': hostname.strip(),
            'username': (username or 'unknown').strip(),
            'cmdline': cmdline.strip(),
            'timestamp': int(time.time())
        }
        
    except Exception as e:
        print(f"ERROR parsing event: {e}", file=sys.stderr)
        return None

def redis_connect():
    try:
        r = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            socket_connect_timeout=2,
            socket_keepalive=False,
            decode_responses=True
        )
        r.ping()
        print(f"DEBUG: Redis connected", file=sys.stderr)
        return r, None
        
    except redis.ConnectionError as e:
        error = f"Cannot connect to Redis: {e}"
        return None, error
    except Exception as e:
        error = f"Redis error: {e}"
        return None, error

def check_lua_script(r):
    try:
        exists = r.script_exists(LUA_SCRIPT_SHA)
        if exists[0]:
            print(f"DEBUG: Lua script found", file=sys.stderr)
            return True, None
        else:
            error = f"Lua script not found. SHA1: {LUA_SCRIPT_SHA[:12]}..."
            return False, error
            
    except Exception as e:
        error = f"Failed to check Lua script: {e}"
        return False, error

def update_record(r, event):
    hostname = event['hostname']
    username = event['username']
    cmdline = event['cmdline']
    current_ts = event['timestamp']
    
    util_hash = hashlib.md5(cmdline.encode()).hexdigest()
    main_key = f"recon:{hostname}:{util_hash}"
    index_key = f"recon:idx:{hostname}"
    
    print(f"DEBUG: Updating - Key: {main_key[:50]}..., Index: {index_key}", 
          file=sys.stderr)
    
    try:
        result = r.evalsha(
            LUA_SCRIPT_SHA,
            2,  # numkeys
            main_key,
            index_key,
            username,
            str(current_ts),
            str(RECORD_TTL)
        )
        print(f"DEBUG: Updated, count: {result}", file=sys.stderr)
        return True, None
        
    except redis.exceptions.NoScriptError:
        error = f"Lua script disappeared during execution"
        return False, error
    except Exception as e:
        error = f"Failed to update: {e}"
        return False, error

def check_threshold(r, hostname, current_ts):
    hour_ago = current_ts - (3600 * WINDOW_HOURS)
    index_key = f"recon:idx:{hostname}"
    
    try:
        count = r.zcount(index_key, hour_ago, '+inf')
        print(f"DEBUG: Unique in window: {count}", file=sys.stderr)
        return count
    except Exception as e:
        print(f"WARNING: Failed to check threshold: {e}", file=sys.stderr)
        return 0

def send_detection_alert(event, unique_count):
    try:
        alert = {
            "integration": "recon_monitor",
            "timestamp": int(time.time()),
            "hostname": event['hostname'],
            "username": event['username'],
            "last_command": event['cmdline'][:200],
            "unique_utilities_count": unique_count,
            "threshold": THRESHOLD,
            "time_window_hours": WINDOW_HOURS
        }
        
        socket_msg = f"1:recon_monitor:{json.dumps(alert)}"
        
        with socket(AF_UNIX, SOCK_DGRAM) as sock:
            sock.connect(SOCKET_PATH)
            sock.send(socket_msg.encode())
        
        print(f"ALERT: {event['hostname']} - {unique_count} utils", file=sys.stderr)
        
    except Exception as e:
        print(f"ERROR sending alert: {e}", file=sys.stderr)

def process_input(input_data):
    # Parse input event
    event = parse_event(input_data)
    if not event:
        print("DEBUG: No valid event parsed", file=sys.stderr)
        return
    
    print(f"DEBUG: Processing {event['hostname']}", file=sys.stderr)
    
    # Connect to Redis
    r, error = redis_connect()
    if error:
        print(f"ERROR: {error}", file=sys.stderr)
        send_error_alert("redis_connection", error)
        return
    
    # Check Lua in Redis
    ok, error = check_lua_script(r)
    if not ok:
        print(f"ERROR: {error}", file=sys.stderr)
        send_error_alert("lua_script_missing", error)
        return
    
    # Update record via Lua
    ok, error = update_record(r, event)
    if not ok:
        print(f"ERROR: {error}", file=sys.stderr)
        send_error_alert("update_failed", error)
        return
    
    # Check treshold and send alert
    try:
        unique_count = check_threshold(r, event['hostname'], event['timestamp'])
        
        if unique_count >= THRESHOLD:
            send_detection_alert(event, unique_count)
            
    except Exception as e:
        print(f"ERROR in threshold check: {e}", file=sys.stderr)
    
    print(f"DEBUG: Done", file=sys.stderr)

def main():
    try:
        input_str = sys.stdin.read()
        if not input_str:
            return
        
        process_input(input_str)
            
    except Exception as e:
        print(f"ERROR reading input: {e}", file=sys.stderr)

def manual_test():
    try:
        with open('test_alert.json', 'r') as f:
            test_data = f.read()
        
        print("=== MANUAL TEST START ===", file=sys.stderr)
        process_input(test_data)
        print("=== MANUAL TEST END ===", file=sys.stderr)
            
    except FileNotFoundError:
        print("ERROR: test_alert.json not found", file=sys.stderr)
        print("Create test_alert.json with your test data", file=sys.stderr)
        
        example_data = {
            "predecoder": {
                "hostname": "lubuntu"
            },
            "agent": {
                "name": "lubuntu"
            },
            "data": {
                "eventdata": {
                    "user": "user",
                    "commandLine": "nmap -sS 192.168.1.1"
                },
                "system": {
                    "computer": "lubuntu"
                }
            },
            "rule": {
                "id": "200300"
            }
        }
        
        print("\nExample test_alert.json:", file=sys.stderr)
        print(json.dumps(example_data, indent=2), file=sys.stderr)
        
    except Exception as e:
        print(f"ERROR in manual test: {e}", file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        manual_test()
    else:
        main()