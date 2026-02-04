---IPv3 Protocol for MCNnet3
local ipv3={}
ipv3.ver="3.0"
ipv3.env={
  this_ip="this_ip",
  node_uuid="node_uuid",
  this_netid="this_netid"
}
---Checks if given string is UUID
---@param g_uuid string
---@return boolean
function ipv3.isUUID(g_uuid)
  if type(g_uuid)~="string" then return false end
  local pattern = "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$"
  if string.match(g_uuid, pattern) then return true
  else return false end
end
---Checks if given address is IPv3
---@param ip string
---@return boolean
function ipv3.isIPv3(ip)
  if type(ip)~="string" then return false end
  local colon_count=0
  for i=1,#ip do if ip:sub(i,i)==":" then colon_count=colon_count+1 end end
  if colon_count~=2 then return false
  else
    if ip:match("^:%x%x%x%x:%x%x%x%x$") then return true end
    if ip:match("^::%x%x%x%x$") then return true end
    if ip:match("^%x%x%x%x:%x%x%x%x:%x%x%x%x$") then return true end
    return false
  end
end
---Expands IPv3 into full form
---@param ip string
---@return string|nil
function ipv3.expand(ip)
  if not ipv3.isIPv3(ip) then return nil end
  local c_net=os.getenv(ipv3.env.this_netid) or "0000"
  local c_node=os.getenv(ipv3.env.node_uuid) or "0000"
  local c_ip=os.getenv(ipv3.env.this_ip) or "0000"
  if c_node:len()>4 then c_node=c_node:sub(-4) end
  if c_ip:len()>4 then c_ip=c_ip:sub(-4) end
  
  local parts={}
  for p in ip:gmatch("[^:]+") do parts[#parts+1]=p end
  
  if #parts==1 then return c_net..":"..c_node..":"..parts[1]
  elseif #parts==2 then return c_net..":"..parts[1]..":"..parts[2]
  else return ip end
end
---Separates IPv3 into parts
---@param ip string
---@return string|nil,string|nil,string|nil
function ipv3.getParts(ip)
  local full=ipv3.expand(ip)
  if not full then return nil,nil,nil end
  local net,node,client=full:match("^(%x+):(%x+):(%x+)$")
  return net,node,client
end
---Encodes ipv3 into bit form
---@param ip string
---@return string|nil
function ipv3.encode(ip)
  local full=ipv3.expand(ip)
  if not full then return nil end
  local net,node,client=ipv3.getParts(full)
  local result=""
  result=result..string.char(tonumber(net:sub(1,2),16))
  result=result..string.char(tonumber(net:sub(3,4),16))
  result=result..string.char(tonumber(node:sub(1,2),16))
  result=result..string.char(tonumber(node:sub(3,4),16))
  result=result..string.char(tonumber(client:sub(1,2),16))
  result=result..string.char(tonumber(client:sub(3,4),16))
  return result
end
---Decodes ipv3 from bit form
---@param c string
---@return string|nil
function ipv3.decode(c)
  if type(c)~="string" or #c~=6 then return nil end
  local parts={}
  for i=1,6,2 do
    local b1,b2=c:byte(i),c:byte(i+1)
    if not b1 or not b2 then return nil end
    parts[#parts+1]=string.format("%02x%02x",b1,b2)
  end
  return parts[1]..":"..parts[2]..":"..parts[3]
end
---Resets all env variables
function ipv3.reset()
  for _,v in pairs(ipv3.env) do os.setenv(v,nil) end
end
--Route tables

---Encodes routing table into string
---@param r string[] Table of IPv3
---@return string|nil
function ipv3.encodeRoute(r)
  if type(r)~="table" then return nil end
  local res=""
  for i=1,#r do
    local encoded=ipv3.encode(r[i])
    if not encoded then return nil end
    res=res..encoded..";"
  end
  return res:sub(1,#res-1)
end
---Decodes routing table from string
---@param s string
---@return string[]|nil
function ipv3.decodeRoute(s)
  if type(s)~="string" then return nil end
  if s=="" then return {} end
  local routes={}
  for encoded in s:gmatch("[^;]+") do
    if #encoded~=6 then return nil end
    local decoded=ipv3.decode(encoded)
    if not decoded then return nil end
    routes[#routes+1]=decoded
  end
  return routes
end

return ipv3
--[[
1234:5678:90ab
netid:node:client

full: 1234:5678:90ab
shortened net: :5678:90ab
shortened node: ::90ab

Encoding:
1234:5678:90ab -> 12 34 : 56 78 : 90 ab -ascii-> \12\34\56\78\90\ab (6 bytes total)
]]