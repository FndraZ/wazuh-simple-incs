#!/usr/bin/env python3
"""
lua_loader.py - Загрузка Lua скрипта в Redis
Возвращает SHA1 хеш или выходит с ошибкой
Использование: python3 lua_loader.py
"""

import sys
import hashlib
import redis

REDIS_HOST = '192.168.1.11'
REDIS_PORT = 6380

# Lua скрипт для обновления записей
LUA_SCRIPT = """
local main_key = KEYS[1]
local index_key = KEYS[2]
local username = ARGV[1]
local current_ts = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])

-- Извлекаем util_hash из ключа
local last_colon = 0
for i = #main_key, 1, -1 do
    if string.sub(main_key, i, i) == ':' then
        last_colon = i
        break
    end
end
local util_hash = string.sub(main_key, last_colon + 1)

-- Обновляем или создаём запись
local exists = redis.call('EXISTS', main_key)
if exists == 1 then
    redis.call('HINCRBY', main_key, 'c', 1)
    redis.call('HSET', main_key, 't', current_ts, 'u', username)
else
    redis.call('HSET', main_key, 'c', 1, 't', current_ts, 'u', username)
    redis.call('EXPIRE', main_key, ttl)
end

-- Обновляем индекс
redis.call('ZADD', index_key, current_ts, util_hash)

-- Обновляем TTL индекса если нужно
local index_ttl = redis.call('TTL', index_key)
if index_ttl < ttl then
    redis.call('EXPIRE', index_key, ttl)
end

return redis.call('HGET', main_key, 'c')
"""

def load_lua_script():
    """Загружает Lua скрипт в Redis и возвращает SHA1"""
    try:
        # Подключение к Redis
        r = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            socket_connect_timeout=5,
            socket_keepalive=True,
            decode_responses=True
        )
        
        # Проверка подключения
        r.ping()
        print(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}", file=sys.stderr)
        
        # Вычисляем ожидаемый SHA1
        expected_sha1 = hashlib.sha1(LUA_SCRIPT.encode()).hexdigest()
        
        # Проверяем, не загружен ли уже скрипт
        exists = r.script_exists(expected_sha1)
        if exists[0]:
            print(f"Script already loaded: {expected_sha1}", file=sys.stderr)
            return expected_sha1
        
        # Загружаем скрипт
        actual_sha1 = r.script_load(LUA_SCRIPT)
        
        if actual_sha1 == expected_sha1:
            print(f"Script loaded successfully: {actual_sha1}", file=sys.stderr)
        else:
            print(f"Warning: SHA1 mismatch. Expected: {expected_sha1}", file=sys.stderr)
            print(f"                      Got: {actual_sha1}", file=sys.stderr)
        
        # Выводим SHA1 в stdout для использования в других скриптах
        print(actual_sha1)
        return actual_sha1
        
    except redis.ConnectionError as e:
        print(f"ERROR: Cannot connect to Redis at {REDIS_HOST}:{REDIS_PORT}: {e}", 
              file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to load Lua script: {e}", file=sys.stderr)
        sys.exit(1)

def verify_script(sha1):
    """Проверяет, что скрипт действительно загружен"""
    try:
        r = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            socket_connect_timeout=3,
            decode_responses=True
        )
        
        exists = r.script_exists(sha1)
        if exists[0]:
            print(f"Verification PASSED: script {sha1[:12]}... exists", file=sys.stderr)
            return True
        else:
            print(f"Verification FAILED: script not found", file=sys.stderr)
            return False
            
    except Exception as e:
        print(f"Verification ERROR: {e}", file=sys.stderr)
        return False

if __name__ == "__main__":
    # Загружаем скрипт
    sha1 = load_lua_script()
    
    # Проверяем
    if verify_script(sha1):
        sys.exit(0)
    else:
        sys.exit(1)