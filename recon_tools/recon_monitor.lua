-- KEYS[1] = recon:stats:{hostname}
-- KEYS[2] = recon:flood:{hostname}
-- ARGV[1] = event_hash (host|user|cmdline)
-- ARGV[2] = current_timestamp
-- ARGV[3] = window_seconds
-- ARGV[4] = flood_ttl
-- ARGV[5] = threshold

local stats_key = KEYS[1]
local flood_key = KEYS[2]
local event_hash = ARGV[1]
local current_ts = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
local flood_ttl = tonumber(ARGV[4])
local threshold = tonumber(ARGV[5])

-- 1. Очистка старых записей
local cutoff = current_ts - window
redis.call('ZREMRANGEBYSCORE', stats_key, 0, cutoff)

-- 2. Добавляем event_hash если его нет
if redis.call('ZSCORE', stats_key, event_hash) == false then
    redis.call('ZADD', stats_key, current_ts, event_hash)
end

-- 3. Обновляем timestamp
redis.call('ZADD', stats_key, current_ts, event_hash)

-- 4. Получаем количество уникальных event_hash'ей
local unique_count = redis.call('ZCARD', stats_key)

-- 5. Обновляем TTL
redis.call('EXPIRE', stats_key, window + 300)

-- 6. Проверяем антифлуд (уже после записи!)
local flood_exists = redis.call('EXISTS', flood_key)
if flood_exists == 1 then
    return 0  -- should_send
end

-- 7. Проверяем порог
if unique_count >= threshold then
    redis.call('SETEX', flood_key, flood_ttl, '1')
    return 1
end

return 0