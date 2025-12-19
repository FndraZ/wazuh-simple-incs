-- Lua script for bruteforce detection
-- KEYS[1] = classic_key (bf:classic:{src_ip}:{username}:{dst_host})
-- KEYS[2] = dist_total_key (bf:dist:total:{src_ip}:{dst_host})
-- KEYS[3] = dist_users_key (bf:dist:users:{src_ip}:{dst_host})
-- KEYS[4] = multisrc_key (bf:multisrc:{username}:{dst_host})
-- ARGV[1] = current_timestamp
-- ARGV[2] = src_ip
-- ARGV[3] = username
-- ARGV[4] = dst_host
-- ARGV[5] = window_seconds (3600)
-- ARGV[6] = ttl_seconds (3900)

local current_ts = tonumber(ARGV[1])
local window_start = current_ts - tonumber(ARGV[5])

-- 1. PROCESS CLASSIC BRUTEFORCE (exact 1-hour window)
-- Use sorted set to track attempts with timestamps
redis.call('ZADD', KEYS[1], current_ts, current_ts)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', window_start)
redis.call('EXPIRE', KEYS[1], ARGV[6])

local classic_count = redis.call('ZCARD', KEYS[1])

-- 2. PROCESS DISTRIBUTED BRUTEFORCE (TTL-based)
-- Total attempts counter
local total = redis.call('INCR', KEYS[2])
if total == 1 then
    redis.call('EXPIRE', KEYS[2], ARGV[6])
end

-- Unique users set
local added = redis.call('SADD', KEYS[3], ARGV[3])
if added == 1 then
    redis.call('EXPIRE', KEYS[3], ARGV[6])
end

local unique_users = redis.call('SCARD', KEYS[3])

-- 3. PROCESS MULTI-SOURCE BRUTEFORCE (TTL-based)
local sources_added = redis.call('SADD', KEYS[4], ARGV[2])
if sources_added == 1 then
    redis.call('EXPIRE', KEYS[4], ARGV[6])
end

local unique_sources = redis.call('SCARD', KEYS[4])

-- Return all counts for threshold checking
return {
    classic_count,          -- attempts for classic bruteforce
    total,                  -- total attempts for distributed
    unique_users,           -- unique users for distributed
    unique_sources          -- unique sources for multi-source
}