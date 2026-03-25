--- NDP - Node Discovery Protocol
--- Handles initial node connections and basic routing update
local ipv3=require("ipv3")
local np=require("np")
local giptl=require("giptl")
local bit32=require("bit32")
local modem=require("component").modem
local event=require("event")
local computer=require("computer")
local ndp={}
ndp.modemPort=2000
ndp.virtualPort=1
ndp.nonceSecrets={} -- nonce=secret,ttl
ndp.secretTTL=120 --seconds
ndp.password=nil
ndp.logFunction=nil --if log, then use this function
function ndp.fnv1a(str)
  local hash=0x811c9dc5
  for i=1,#str do
    hash=bit32.bxor(hash,str:byte(i))
    hash=(hash*0x01000193)%2^32
  end
  return string.format("%08x",hash)
end
function ndp.randS(len)
  if not len then len=16 end
  local t={}
  for i=1,len do t[i]=string.char(math.random(0,255)) end
  return table.concat(t)
end
--crit: 0,1,2,3 debug,info,warn,err
function ndp.log(msg,crit)
  if not crit then crit=1 end
  if type(ndp.logFunction)=="function" then
    pcall(ndp.logFunction,"ndp",msg,crit)
  end
end
function ndp.updateSecrets()
  local outdated={}
  for n,t in pairs(ndp.nonceSecrets) do
    if t[2]<computer.uptime() then table.insert(outdated,n) end
  end
  for _,n in pairs(outdated) do ndp.nonceSecrets[n]=nil end
end
function ndp.getSecretForNonce(nonce)
  ndp.updateSecrets()
  local secret=ndp.randS(8)
  ndp.nonceSecrets[nonce]={secret,computer.uptime()+ndp.secretTTL}
  return secret
end
---Util receive with deadline
---@param from_uuid string UUID
---@param deadline any computer.uptime()
---@param nonce string Nonce
---@return string|nil payload
function ndp.receive(from_uuid,nonce,deadline)
  if not deadline then deadline=computer.uptime()+2 end
  while computer.uptime()<deadline do
    local _,_,from_uuid_p,from_port,from_dist,from_p=event.pull(2,"modem_message")
    if from_uuid_p and from_p and np.checkPacket(from_p) and from_port==ndp.modemPort then
      if from_uuid_p==from_uuid then
        local _,dest_ip=np.header.getRawIPs(from_p)
        if dest_ip==ipv3.this() then
          local payload=np.header.getPayload(from_p)
          if payload:sub(2,17)~=nonce then
            ndp.log("Wrong nonce! real={"..nonce.."}, got={"..payload:sub(2,17).."}",0)
          else
            return payload
          end
        end
      end
    end
  end
  return nil
end
function ndp.search()
  local this_ip=ipv3.this()
  modem.open(ndp.modemPort)
  ndp.log("Started search for nodes")
  local found={}--uuid,dist,ipv3,password?
  local nonce=ndp.randS()
  local p=np.newEncodedPacketHeader(this_ip,ipv3.nullIPv3,ndp.virtualPort,{broadcast=true})..string.char(1)..nonce
  modem.broadcast(ndp.modemPort,p)
  local deadline=computer.uptime()+2
  local replies={}
  local uniques={}
  while computer.uptime()<deadline do
    local _,_,from_uuid,from_port,from_dist,from_p=event.pull(2,"modem_message")
    if from_uuid and from_p and np.checkPacket(from_p) then
      table.insert(replies,{from_uuid,from_dist,from_p})
    end
  end
  for i,reply in pairs(replies) do
    local from_uuid=reply[1] local from_dist=reply[2] local from_p=reply[3]
    if not np.validatePacket(from_p) then
    elseif giptl.isBannedUUID(from_uuid) then --ignore: banned uuid
    elseif np.header.getPort(from_p)~=ndp.virtualPort then
    elseif uniques[from_uuid] then
    else
      uniques[from_uuid]=true
      local from_payload=np.header.getPayload(from_p)
      if not from_payload or from_payload:byte(1)~=2 or from_payload:sub(2,17)~=nonce then
      else
        local use_password=false
        if from_payload:byte(#from_payload)==1 then use_password=true end
        local dst_ip,_=np.header.getRawIPs(from_p)
        table.insert(found,{from_uuid,from_dist,dst_ip,use_password})
      end
    end
  end
  table.sort(found,function(a,b)return a[2]<b[2] end)
  ndp.log("Found "..#found.." nodes")
  return found
end

function ndp.broadcastNew(ip)
  local nonce=ndp.randS()
  local p=np.newEncodedPacketHeader(ipv3.this(),ipv3.nullIPv3(),ndp.virtualPort,{broadcast=true})
  p=p..string.char(10)..nonce..ip
  for node_ip,node_uuid in pairs(giptl.get.nodes()) do
    if node_ip~=ip then modem.send(node_uuid,ndp.modemPort,p) end
  end
end

function ndp.handlePacket(_,_,from_uuid,from_port,from_dist,from_p)
  if not from_uuid or not from_p then return end
  if from_port~=ndp.modemPort then return end
  if np.header.getPort(from_p)~=ndp.virtualPort then return end
  local src_ip=from_p:sub(2,7)
  if not ipv3.isNode(src_ip) then return end
  if giptl.isBannedUUID(from_uuid) then
    local p=np.newEncodedPacketHeader(ipv3.this(),src_ip,ndp.virtualPort,{})..string.char(7)..from_p:sub(18,33)
    modem.send(from_uuid,ndp.modemPort,p)
    return
  end
  local from_payload=np.header.getPayload(from_p)
  local from_ip,_=np.header.getRawIPs(from_p)
  local p=np.newEncodedPacketHeader(ipv3.this(),from_ip,ndp.virtualPort,{})
  local nonce=from_payload:sub(2,17)
  local flag=from_payload:byte(1)
  if flag==1 then
    local password_char=string.char(0)
    if ndp.password then
      password_char=string.char(1)
    end
    os.sleep(math.random()*0.5) --random delay
    p=p..string.char(2)..nonce..password_char
  elseif flag==3 then
    if ndp.password then
      local secret=ndp.getSecretForNonce(nonce)
      p=p..string.char(8)..nonce..secret
    else
      --connect
      giptl.set.node(from_ip,from_uuid)
      ndp.broadcastNew(from_ip)
      p=p..string.char(4)..nonce
    end
  elseif flag==9 then
    ndp.updateSecrets()
    local secret_data=ndp.nonceSecrets[nonce]
    if not secret_data then
      modem.send(from_uuid,ndp.modemPort,p..string.char(6)..nonce.."no_such_secret")
      return
    end
    local secret=secret_data[1]
    local check_passwd=ndp.fnv1a(secret..ndp.password)
    if check_passwd~=from_payload:sub(18,#from_payload) then
      p=p..string.char(5)..nonce
    else
      giptl.set.node(from_ip,from_uuid)
      ndp.broadcastNew(from_ip)
      p=p..string.char(4)..nonce
    end
    ndp.nonceSecrets[nonce]=nil
  elseif flag==10 then
    local new_ip=from_payload:sub(18,23)
    if not giptl.get.nodeUUID(new_ip) then
      --overwrite existing route anyways
      giptl.set.route(new_ip,from_ip)
      for node_ip,node_uuid in pairs(giptl.get.nodes()) do
        if node_ip~=from_ip then
          modem.send(node_uuid,ndp.modemPort,from_p)
        end
      end
    end
    return --we exit early without response
  end
  modem.send(from_uuid,ndp.modemPort,p)
end
function ndp.connect(node_uuid,node_ip,password)
  if giptl.get.nodeUUID(node_ip) then
    ndp.log("Attempting to connect to already connected node",2)
  end
  local nonce=ndp.randS()
  local p=np.newEncodedPacketHeader(ipv3.this(),node_ip,ndp.virtualPort,{})
  modem.send(node_uuid,ndp.modemPort,p..string.char(3)..nonce)
  local res_p=ndp.receive(node_uuid,nonce)
  if not res_p then return false,"timeout" end
  local flag=res_p:byte(1)
  if flag==4 then
    --
    return true,"success"
  elseif flag==6 then
    return false,"error:"..res_p:sub(18,#res_p)
  elseif flag==7 then
    return false,"banned"
  elseif flag==8 then
    local secret=res_p:sub(18,#res_p)
    if not password then
      return false,"need_password"
    end
    local encoded_pass=ndp.fnv1a(secret..password)
    modem.send(node_uuid,ndp.modemPort,p..string.char(9)..nonce..encoded_pass)
    res_p=ndp.receive(node_uuid,nonce)
    if not res_p then return false,"timeout" end
    flag=res_p:byte(1)
    if flag==4 then
      giptl.set.node(node_ip,node_uuid)
      return true,"success"
    elseif flag==5 then
      return false,"incorrect_password"
    elseif flag==6 then
      return false,"error:"..res_p:sub(18,#res_p)
    end
  else
    return false,"invalid_response: ("..flag.."): "..res_p:sub(18,#res_p)
  end
end

---auto connect via table(low distance preferred)
---@param found_table table Table provided by `ndp.search`
---@param connection_limit? integer
---@return integer nodes_connected Number of nodes connected
function ndp.autoConnect(found_table,connection_limit)
  if not found_table then return -1 end
  if not connection_limit then connection_limit=1000 end
  local nodes_connected=0
  for i,node in pairs(found_table) do
    if i>connection_limit then break end
    ndp.log("Connecting to "..node[3])
    local success,msg=ndp.connect(node[1],node[3],node[4])
    if success then
      nodes_connected=nodes_connected+1
      ndp.log("Successfully connected",1)
    else
      ndp.log("Failed to connect to "..node[3]..": "..msg,2)
    end
  end
  return nodes_connected
end
return ndp
--[[
global _G.banned -> uuid

real port=2000 default
vport=1
nonce = random string, 16 bytes
flags:
0x00 - unused
0x01 - broadcast
<0x01><nonce>
0x02 - broadcast response
<0x02><nonce><0x1/0x0>(password needed/not)
0x03 - connect request 
<0x03><nonce>
0x08 - connect challenge
<0x08><nonce><new_nonce>
0x09 - connect challenge response
<0x03><nonce><hash:new_nonce+password>
0x04 - connect success
<0x04><nonce>
0x05 - invalid password
<0x05><nonce>
0x06 - error
<0x06><nonce><error string/nil>
0x07 - banned
<0x07><nonce>
0x0A - new node broadcast
<0x0A><nonce><dst_ip>
]]