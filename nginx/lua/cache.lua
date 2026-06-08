local ngx_shared = ngx.shared
local db = require "db"

local CACHE_TTL = 60  -- кэшировать на 60 секунд

local function get_site_info(domain)
    local cache = ngx_shared.site_cache
    if not cache then
        cache = ngx.shared.site_cache
    end
    
    local cached = cache:get(domain)
    if cached then
        ngx.log(ngx.NOTICE, "Cache hit for domain: ", domain)
        return cached.target_ip, cached.is_protected, cached.traffic_limit_mb
    end
    
    ngx.log(ngx.NOTICE, "Cache miss for domain: ", domain)
    
    local target_ip, is_protected, traffic_limit_mb = db.get_site_info(domain)
    
    if target_ip then
        cache:set(domain, {
            target_ip = target_ip,
            is_protected = is_protected,
            traffic_limit_mb = traffic_limit_mb
        }, CACHE_TTL)
    end
    
    return target_ip, is_protected, traffic_limit_mb
end

return {
    get_site_info = get_site_info
}

