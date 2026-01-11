-- KEYS[1] = recon:stats:{hostname}
-- ARGV[1] = event_hash
-- ARGV[2] = current_timestamp  
-- ARGV[3] = window_seconds
-- ARGV[4] = threshold

local stats_key = KEYS[1]
local event_hash = ARGV[1]
local current_ts = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
local threshold = tonumber(ARGV[4])

-- 1. Очистка старых записей
local cutoff = current_ts - window
redis.call('ZREMRANGEBYSCORE', stats_key, 0, cutoff)

-- 2. Добавляем/обновляем event_hash
redis.call('ZADD', stats_key, current_ts, event_hash)

-- 3. Устанавливаем TTL
redis.call('EXPIRE', stats_key, window + 300)

-- 4. Считаем и проверяем порог
local unique_count = redis.call('ZCARD', stats_key)

if unique_count >= threshold then
    -- Возвращаем метрики для FIR
    return cjson.encode({
        should_alert = true,
        unique_count = unique_count,
        threshold = threshold,
        window_hours = window / 3600
    })
end

return cjson.encode({should_alert = false})