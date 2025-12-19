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