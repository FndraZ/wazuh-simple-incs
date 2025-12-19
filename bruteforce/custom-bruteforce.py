#!/usr/bin/env python3
"""
Bruteforce detection integration for Wazuh
Processes failed/success authentication events and detects bruteforce attacks
"""

import sys
import json
import time
import hashlib
import redis
from datetime import datetime
from socket import socket, AF_UNIX, SOCK_DGRAM

# Configuration
REDIS_HOST = '192.168.1.11'
REDIS_PORT = 6380

# Thresholds
THRESHOLD_CLASSIC = 10          # failed attempts for classic bruteforce
THRESHOLD_DIST_TOTAL = 50       # total attempts for distributed
THRESHOLD_DIST_USERS = 5        # unique users for distributed
THRESHOLD_SOURCES = 3           # unique sources for multi-source

# Time windows (seconds)
TIME_WINDOW = 3600              # 1 hour exact window for classic
REDIS_TTL = 3900                # 1h5m for TTL-based counters

# Paths
SOCKET_PATH = '/var/ossec/queue/sockets/integrations'
LUA_SCRIPT_SHA = "SHA1"  # Replace with actual SHA1

# Rule IDs (adjust based on your Wazuh rules)
RULE_FAILED_AUTH = 100200
RULE_SUCCESS_AUTH = 100201

def send_error_alert(error_type, message):
    """Send error alert to Wazuh"""
    try:
        alert = {
            "integration": "bruteforce_detector",
            "timestamp": int(time.time()),
            "error_type": error_type,
            "message": message,
            "severity": "high"
        }
        
        socket_msg = f"1:bruteforce_error:{json.dumps(alert)}"
        
        with socket(AF_UNIX, SOCK_DGRAM) as sock:
            sock.connect(SOCKET_PATH)
            sock.send(socket_msg.encode())
        
        print(f"ERROR [{error_type}]: {message}", file=sys.stderr)
        
    except Exception as e:
        print(f"CRITICAL: Failed to send error alert: {e}", file=sys.stderr)

def parse_event(input_str):
    """
    Parse Wazuh event with strict field mapping
    Returns dict with required fields or None
    """
    try:
        alert = json.loads(input_str)
        rule_id = alert.get('rule', {}).get('id', '')
        
        # Extract fields based on rule ID
        if rule_id == str(RULE_FAILED_AUTH):
            # Failed authentication event
            src_ip = alert.get('data', {}).get('src_ip', '')
            src_hostname = alert.get('data', {}).get('src_hostname', '')
            username = alert.get('data', {}).get('username', '')
            dst_host = alert.get('agent', {}).get('name', '')
            auth_type = alert.get('data', {}).get('auth_type', '')
            timestamp_str = alert.get('timestamp', '')
            
            # Convert timestamp to UNIX timestamp
            try:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                timestamp = int(dt.timestamp())
            except:
                timestamp = int(time.time())
            
            return {
                'rule_id': rule_id,
                'src_ip': src_ip,
                'src_host': src_hostname or src_ip,  # prioritize hostname
                'username': username,
                'dst_host': dst_host,
                'auth_type': auth_type,
                'status': 'failed',
                'timestamp': timestamp,
                'raw': alert
            }
            
        elif rule_id == str(RULE_SUCCESS_AUTH):
            # Successful authentication event
            src_ip = alert.get('data', {}).get('src_ip', '')
            src_hostname = alert.get('data', {}).get('src_hostname', '')
            username = alert.get('data', {}).get('username', '')
            dst_host = alert.get('agent', {}).get('name', '')
            auth_type = alert.get('data', {}).get('auth_type', '')
            timestamp_str = alert.get('timestamp', '')
            
            try:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                timestamp = int(dt.timestamp())
            except:
                timestamp = int(time.time())
            
            return {
                'rule_id': rule_id,
                'src_ip': src_ip,
                'src_host': src_hostname or src_ip,
                'username': username,
                'dst_host': dst_host,
                'auth_type': auth_type,
                'status': 'success',
                'timestamp': timestamp,
                'raw': alert
            }
        
        print(f"DEBUG: Unknown rule ID: {rule_id}", file=sys.stderr)
        return None
        
    except Exception as e:
        print(f"ERROR parsing event: {e}", file=sys.stderr)
        return None

def redis_connect():
    """Connect to Redis with timeout"""
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
    """Verify Lua script exists in Redis"""
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

def update_counters(r, event):
    """Update counters in Redis using Lua script"""
    # Prepare keys
    classic_key = f"bf:classic:{event['src_ip']}:{event['username']}:{event['dst_host']}"
    dist_total_key = f"bf:dist:total:{event['src_ip']}:{event['dst_host']}"
    dist_users_key = f"bf:dist:users:{event['src_ip']}:{event['dst_host']}"
    multisrc_key = f"bf:multisrc:{event['username']}:{event['dst_host']}"
    
    print(f"DEBUG: Updating counters for {event['src_ip']}:{event['username']}", 
          file=sys.stderr)
    
    try:
        # Execute Lua script
        result = r.evalsha(
            LUA_SCRIPT_SHA,
            4,  # number of keys
            classic_key,
            dist_total_key,
            dist_users_key,
            multisrc_key,
            str(event['timestamp']),
            event['src_ip'],
            event['username'],
            event['dst_host'],
            str(TIME_WINDOW),
            str(REDIS_TTL)
        )
        
        # Parse results
        classic_count = int(result[0])
        dist_total = int(result[1])
        dist_unique_users = int(result[2])
        unique_sources = int(result[3])
        
        print(f"DEBUG: Counts - classic:{classic_count}, dist_total:{dist_total}, "
              f"dist_users:{dist_unique_users}, sources:{unique_sources}", 
              file=sys.stderr)
        
        return {
            'classic_count': classic_count,
            'dist_total': dist_total,
            'dist_unique_users': dist_unique_users,
            'unique_sources': unique_sources
        }, None
        
    except redis.exceptions.NoScriptError:
        error = f"Lua script disappeared during execution"
        return None, error
    except Exception as e:
        error = f"Failed to update counters: {e}"
        return None, error

def generate_alert(alert_type, event, stats):
    """Generate and send alert to Wazuh"""
    try:
        alert = {
            "integration": "bruteforce_detector",
            "timestamp": event['timestamp'],
            "rule_id": event['rule_id'],
            
            # Required fields for DB
            "source": event['src_host'],
            "source_ip": event['src_ip'],
            "username": event['username'],
            "destination": event['dst_host'],
            "auth_type": event['auth_type'],
            
            # Incident details
            "incident_type": alert_type,
            "attempt_count": stats.get('classic_count', 0),
            "unique_users": stats.get('dist_unique_users', 0),
            "unique_sources": stats.get('unique_sources', 0),
            "time_window_seconds": TIME_WINDOW,
            
            # Thresholds
            "threshold_classic": THRESHOLD_CLASSIC,
            "threshold_dist_total": THRESHOLD_DIST_TOTAL,
            "threshold_dist_users": THRESHOLD_DIST_USERS,
            "threshold_sources": THRESHOLD_SOURCES,
            
            # Context
            "first_attempt": event['timestamp'] - TIME_WINDOW,
            "last_attempt": event['timestamp'],
            "status": event['status']
        }
        
        socket_msg = f"1:bruteforce:{json.dumps(alert)}"
        
        with socket(AF_UNIX, SOCK_DGRAM) as sock:
            sock.connect(SOCKET_PATH)
            sock.send(socket_msg.encode())
        
        print(f"ALERT: {alert_type} detected for {event['src_ip']}", file=sys.stderr)
        
    except Exception as e:
        print(f"ERROR sending alert: {e}", file=sys.stderr)

def check_thresholds(event, stats):
    """Check all threshold conditions and generate alerts"""
    
    # 1. Classic bruteforce
    if stats['classic_count'] >= THRESHOLD_CLASSIC:
        generate_alert('bruteforce_classic', event, stats)
    
    # 2. Distributed bruteforce
    if (stats['dist_total'] >= THRESHOLD_DIST_TOTAL and 
        stats['dist_unique_users'] >= THRESHOLD_DIST_USERS):
        generate_alert('bruteforce_distributed', event, stats)
    
    # 3. Multi-source bruteforce
    if stats['unique_sources'] >= THRESHOLD_SOURCES:
        generate_alert('bruteforce_multi_source', event, stats)

def process_failed_auth(r, event):
    """Process failed authentication event"""
    print(f"DEBUG: Processing failed auth for {event['username']}", file=sys.stderr)
    
    # Update counters in Redis
    stats, error = update_counters(r, event)
    if error:
        send_error_alert("update_failed", error)
        return
    
    # Check all thresholds
    check_thresholds(event, stats)

def process_success_auth(r, event):
    """Process successful authentication event"""
    print(f"DEBUG: Processing success auth for {event['username']}", file=sys.stderr)
    
    # For successful auth, we only check classic bruteforce
    classic_key = f"bf:classic:{event['src_ip']}:{event['username']}:{event['dst_host']}"
    
    try:
        # Clean old attempts first
        window_start = event['timestamp'] - TIME_WINDOW
        r.zremrangebyscore(classic_key, '-inf', window_start)
        
        # Get count
        classic_count = r.zcard(classic_key)
        
        print(f"DEBUG: Success auth - classic attempts: {classic_count}", file=sys.stderr)
        
        if classic_count >= THRESHOLD_CLASSIC:
            # Successful bruteforce detected
            stats = {
                'classic_count': classic_count,
                'dist_total': 0,
                'dist_unique_users': 0,
                'unique_sources': 0
            }
            generate_alert('bruteforce_successful', event, stats)
            # DO NOT DELETE - leave for investigation
        else:
            # Normal login after few failures - clear attempts
            r.delete(classic_key)
            print(f"DEBUG: Cleared normal login attempts", file=sys.stderr)
            
    except Exception as e:
        error = f"Failed to process success auth: {e}"
        send_error_alert("success_auth_failed", error)

def process_input(input_data):
    """Main processing function"""
    # Parse event
    event = parse_event(input_data)
    if not event:
        print("DEBUG: No valid event parsed", file=sys.stderr)
        return
    
    print(f"DEBUG: Processing event - {event['status']} auth for {event['username']}", 
          file=sys.stderr)
    
    # Connect to Redis
    r, error = redis_connect()
    if error:
        print(f"ERROR: {error}", file=sys.stderr)
        send_error_alert("redis_connection", error)
        return
    
    # Check Lua script
    ok, error = check_lua_script(r)
    if not ok:
        print(f"ERROR: {error}", file=sys.stderr)
        send_error_alert("lua_script_missing", error)
        return
    
    # Process based on auth status
    if event['status'] == 'failed':
        process_failed_auth(r, event)
    else:  # success
        process_success_auth(r, event)
    
    print(f"DEBUG: Processing complete", file=sys.stderr)

def main():
    """Main entry point"""
    try:
        input_str = sys.stdin.read()
        if not input_str:
            return
        
        process_input(input_str)
            
    except Exception as e:
        print(f"ERROR in main: {e}", file=sys.stderr)

def manual_test():
    """Manual test function"""
    try:
        # Create test event
        test_data = {
            "rule": {
                "id": "100200",
                "description": "Failed authentication"
            },
            "agent": {
                "id": "001",
                "name": "server-01"
            },
            "data": {
                "src_ip": "192.168.1.100",
                "src_hostname": "test-attacker",
                "username": "admin",
                "auth_type": "10",
                "status": "failed"
            },
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        print("=== MANUAL TEST START ===", file=sys.stderr)
        process_input(json.dumps(test_data))
        print("=== MANUAL TEST END ===", file=sys.stderr)
            
    except Exception as e:
        print(f"ERROR in manual test: {e}", file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        manual_test()
    else:
        main()