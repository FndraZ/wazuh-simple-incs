local action = ARGV[1]
local source = ARGV[2]
local target = ARGV[3]
local user = ARGV[4]
local login_type = ARGV[5]
local timestamp = ARGV[6]
local ttl = tonumber(ARGV[7])
local regular_threshold = tonumber(ARGV[8])
local multi_source_threshold = tonumber(ARGV[9])
local multi_user_threshold = tonumber(ARGV[10])

local result = {
    action = action,
    is_bruteforce = false,
    bruteforce_type = "none",
    metrics = {
        regular_attempts = 0,
        unique_sources = 0,
        unique_targets = 0,
        unique_users = 0
    },
    thresholds_exceeded = {
        regular = false,
        multi_source = false,
        multi_target = false,
        multi_user = false
    },
    should_alert = false,
    cleaned = 0
}

local function generate_hash(src, tgt, usr, typ)
    return string.format("%s|%s|%s|%s", src, tgt, usr, typ)
end

local attempt_hash = generate_hash(source, target, user, login_type)
local attempt_key = "brute:attempt:" .. attempt_hash
local counter_key = "brute:counter:" .. attempt_hash
local target_sources_key = "brute:target:" .. target .. ":sources"
local target_users_key = "brute:target:" .. target .. ":users"
local source_targets_key = "brute:source:" .. source .. ":targets"
local source_users_key = "brute:source:" .. source .. ":users"

if action == "failed" then
    redis.call("SETEX", attempt_key, ttl, timestamp)
    
    local count = redis.call("INCR", counter_key)
    redis.call("EXPIRE", counter_key, ttl)
    result.metrics.regular_attempts = count
    
    redis.call("SADD", target_sources_key, source)
    redis.call("EXPIRE", target_sources_key, ttl)
    
    redis.call("SADD", target_users_key, user)
    redis.call("EXPIRE", target_users_key, ttl)
    
    redis.call("SADD", source_targets_key, target)
    redis.call("EXPIRE", source_targets_key, ttl)
    
    redis.call("SADD", source_users_key, user)
    redis.call("EXPIRE", source_users_key, ttl)
    
    -- Получаем метрики
    local unique_sources = redis.call("SCARD", target_sources_key)
    local unique_targets = redis.call("SCARD", source_targets_key)
    local unique_users_target = redis.call("SCARD", target_users_key)
    local unique_users_source = redis.call("SCARD", source_users_key)
    
    result.metrics.unique_sources = unique_sources
    result.metrics.unique_targets = unique_targets
    result.metrics.unique_users = math.max(unique_users_target, unique_users_source)
    
    -- Проверяем пороги
    result.thresholds_exceeded.regular = (count >= regular_threshold)
    result.thresholds_exceeded.multi_source = (unique_sources >= multi_source_threshold)
    result.thresholds_exceeded.multi_target = (unique_targets >= multi_source_threshold)
    result.thresholds_exceeded.multi_user = (result.metrics.unique_users >= multi_user_threshold)
    
    -- Определяем тип брутфорса
    local is_regular = result.thresholds_exceeded.regular
    local is_multi_source = result.thresholds_exceeded.multi_source
    local is_multi_target = result.thresholds_exceeded.multi_target
    local is_multi_user = result.thresholds_exceeded.multi_user
    
    if is_regular and (is_multi_source or is_multi_target or is_multi_user) then
        result.is_bruteforce = true
        result.bruteforce_type = "both"
        result.should_alert = true
    elseif is_regular then
        result.is_bruteforce = true
        result.bruteforce_type = "regular"
        result.should_alert = true
    elseif is_multi_source then
        result.is_bruteforce = true
        result.bruteforce_type = "multi_source"
        result.should_alert = true
    elseif is_multi_target then
        result.is_bruteforce = true
        result.bruteforce_type = "multi_target"
        result.should_alert = true
    elseif is_multi_user then
        result.is_bruteforce = true
        result.bruteforce_type = "multi_user"
        result.should_alert = true
    end

elseif action == "success" then
    local count = tonumber(redis.call("GET", counter_key) or 0)
    local unique_sources = redis.call("SCARD", target_sources_key) or 0
    local unique_targets = redis.call("SCARD", source_targets_key) or 0
    local unique_users_target = redis.call("SCARD", target_users_key) or 0
    local unique_users_source = redis.call("SCARD", source_users_key) or 0
    
    result.metrics.regular_attempts = count
    result.metrics.unique_sources = unique_sources
    result.metrics.unique_targets = unique_targets
    result.metrics.unique_users = math.max(unique_users_target, unique_users_source)
    
    local was_bruteforce = (count >= regular_threshold) or
                          (unique_sources >= multi_source_threshold) or
                          (unique_targets >= multi_source_threshold) or
                          (result.metrics.unique_users >= multi_user_threshold)
    
    if was_bruteforce then
        redis.call("DEL", attempt_key)
        redis.call("DEL", counter_key)
        redis.call("DEL", target_sources_key)
        redis.call("DEL", target_users_key)
        redis.call("DEL", source_targets_key)
        redis.call("DEL", source_users_key)
        
        result.cleaned = 6 
        result.is_bruteforce = true
        result.bruteforce_type = "success_after_bruteforce"
        result.should_alert = true
    end

elseif action == "check" then
    result.metrics.regular_attempts = tonumber(redis.call("GET", counter_key) or 0)
    result.metrics.unique_sources = redis.call("SCARD", target_sources_key) or 0
    result.metrics.unique_targets = redis.call("SCARD", source_targets_key) or 0
    result.metrics.unique_users = math.max(
        redis.call("SCARD", target_users_key) or 0,
        redis.call("SCARD", source_users_key) or 0
    )
    
    result.thresholds_exceeded.regular = (result.metrics.regular_attempts >= regular_threshold)
    result.thresholds_exceeded.multi_source = (result.metrics.unique_sources >= multi_source_threshold)
    result.thresholds_exceeded.multi_target = (result.metrics.unique_targets >= multi_source_threshold)
    result.thresholds_exceeded.multi_user = (result.metrics.unique_users >= multi_user_threshold)
    
    if result.thresholds_exceeded.regular or result.thresholds_exceeded.multi_source or 
       result.thresholds_exceeded.multi_target or result.thresholds_exceeded.multi_user then
        result.is_bruteforce = true
        result.should_alert = true
    end
end

return cjson.encode(result)