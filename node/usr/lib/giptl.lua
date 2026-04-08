--- GIPTL - Global IPv3 Table Library
--- Utility functions for global tables of connected ips
--- ipv3s are stored as bytes, uuid are stored as strings
local ser=require("serialization")
local ipv3=require("ipv3")
local giptl={}
giptl.version="1.1"
giptl.t={
  nodes={}, -- ipv3=uuid
  clients={}, -- ipv3=uuid
  bans={}, -- uuid=true
  routes={} -- target_ipv3=next_ipv3
}
giptl.restore=false -- should file be restored? works only in file mode
giptl.filename="/etc/gipt.stbl" -- filename to write

function giptl.save()
  local file=io.open(giptl.filename,"w")
  if not file then
    error("[GIPTL]: Could not open "..tostring(giptl.filename).." to save",2)
  end
  file:write(ser.serialize(giptl.t))
  file:close()
end

function giptl.load()
  local file=io.open(giptl.filename,"r")
  if not file then return end --silently fail if no save file
  local tbl=ser.unserialize(file:read("*a"))
  if not tbl then
    error("[GIPTL]: Could not read save file "..giptl.filename,2)
  end
  giptl.t=tbl
end

giptl.set={}
---@param ip string
---@param uuid string
---@return boolean success
function giptl.set.node(ip,uuid)
  if not ipv3.isIPv3(ip) or not ipv3.isUUID(uuid) then return false end
  giptl.t.nodes[ip]=uuid
  return true
end
---@param ip string
---@param uuid string
---@return boolean success
function giptl.set.client(ip,uuid)
  if not ipv3.isIPv3(ip) or not ipv3.isUUID(uuid) then return false end
  giptl.t.clients[ip]=uuid
  return true
end
---@param uuid string
---@return boolean success
function giptl.set.banned(uuid)
  if not ipv3.isUUID(uuid) then return false end
  giptl.t.banned[uuid]=true
  return true
end
---@param target_ipv3 string
---@param next_ipv3 string
---@return boolean success
function giptl.set.route(target_ipv3,next_ipv3)
  if not ipv3.isIPv3(target_ipv3) or not ipv3.isIPv3(next_ipv3) then return false end
  giptl.t.routes[target_ipv3]=next_ipv3
  return true
end

giptl.get={}
---@param ip string
---@return string|nil
function giptl.get.nodeUUID(ip)
  local found=giptl.t.nodes[ip]
  return found
end
---@param ip string
---@return string|nil
function giptl.get.clientUUID(ip)
  local found=giptl.t.clients[ip]
  return found
end
---@param ip string target NODE ip
---@return string|nil next_ip next NODE ip
function giptl.get.route(ip)
  return giptl.t.routes[ip]
end
---@return table<string,string>
function giptl.get.nodes()
  return giptl.t.nodes
end
---@return table<string,string>
function giptl.get.clients()
  return giptl.t.clients
end
---@return table<string,string>
function giptl.get.banned()
  return giptl.t.bans
end
---@return table<string,string>
function giptl.get.routes()
  return giptl.t.routes
end

giptl.del={}
---@param ip string
---@return boolean success
function giptl.del.node(ip)
  if not ipv3.isIPv3(ip) then return false end
  giptl.t.nodes[ip]=nil
  return true
end
---@param ip string
---@return boolean success
function giptl.del.client(ip)
  if not ipv3.isIPv3(ip) then return false end
  giptl.t.client[ip]=nil
  return true
end
---@param target_ip string
---@return boolean success
function giptl.del.route(target_ip)
  if not ipv3.isIPv3(target_ip) then return false end
  giptl.t.routes[target_ip]=nil
  return true
end
---Delete all hops using the next_ip
---@param next_ip string
---@return boolean
function giptl.del.nextHop(next_ip)
  if not ipv3.isIPv3(next_ip) then return false end
  for target,next in pairs(giptl.t.routes) do
    if next==next_ip then
      giptl.t.routes[target]=nil
    end
  end
  return true
end

---@param uuid string
---@return boolean
function giptl.isBannedUUID(uuid)
  if giptl.t.bans[uuid] then return true end
  return false
end

function giptl.init()
  if giptl.restore==true then
    giptl.load()
  end
end

giptl.init()
return giptl