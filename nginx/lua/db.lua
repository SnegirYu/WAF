local pg = require "resty.postgres"

local function get_db_connection()
    local db, err = pg:new({
        host = "db",
        port = 5432,
        user = "waf_user",
        password = "secretpassword",
        database = "waf_db",
        ssl = false
    })
    
    if not db then
        ngx.log(ngx.ERR, "Failed to connect to DB: ", err)
        return nil, err
    end
    
    return db, nil
end

local function get_site_info(domain)
    local db, err = get_db_connection()
    if not db then
        return nil, nil, nil
    end
    
    local query = [[
        SELECT target_ip, is_protected, traffic_limit_mb 
        FROM accounts_protectedsite 
        WHERE domain = $1
    ]]
    
    local res, err = db:query(query, domain)
    db:close()
    
    if not res or #res == 0 then
        ngx.log(ngx.NOTICE, "Domain not found: ", domain)
        return nil, nil, nil
    end
    
    local target_ip = res[1]["target_ip"]
    local is_protected = res[1]["is_protected"]
    local traffic_limit_mb = res[1]["traffic_limit_mb"]
    
    return target_ip, is_protected, traffic_limit_mb
end

return {
    get_site_info = get_site_info
}
