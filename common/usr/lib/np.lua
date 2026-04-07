---MCNnet3 NetworkPacket
local ipv3=require("ipv3")
local ser=require("serialization")
local np={}
np.version="3.0"
np.vernum=0xB0 --10110000 (176)
---@param n integer
---@return string
function np.encodeNum(n)
  if n==0 then return "\0" end
  local t={}
  while n>0 do
    t[#t+1]=string.char(n%256)
    n=math.floor(n/256)
  end
  for i=1,#t//2 do
    t[i],t[#t-i+1]=t[#t-i+1],t[i]
  end
  return table.concat(t)
end
---@param str string
---@return integer
function np.decodeNum(str)
  local n=0
  for i=1,#str do
    n=n*256+str:byte(i)
  end
  return n
end
function np.parseFlags(b)
  return {
    broadcast  = (b & 0x01) ~= 0,
    control    = (b & 0x02) ~= 0,
    fragment   = (b & 0x04) ~= 0,
    serialized = (b & 0x08) ~= 0,
  }
end
function np.buildFlags(t)
  local b = 0
  if t.broadcast  then b = b | 0x01 end
  if t.control    then b = b | 0x02 end
  if t.fragment   then b = b | 0x04 end
  if t.serialized then b = b | 0x08 end
  return b
end
---Make a new, not encoded packet table
---@param src_ip string non-encoded IPv3
---@param dest_ip string non-encoded IPv3
---@param port integer
---@param flags table<string,boolean>
---@param payload string|table
---@param ttl? integer
---@return table<string,string|integer>|nil
function np.newPacket(src_ip,dest_ip,port,flags,payload,ttl)
  if not ipv3.isIPv3(src_ip) or not ipv3.isIPv3(dest_ip) or type(port)~="number" then return nil end
  if port<0 or port>0xffff then return nil end
  if type(flags)~="table" then return nil end
  if not payload then return nil end
  if type(ttl)~="number" or ttl<0 or ttl>0xFF then ttl=0xFF end
  return {src=src_ip,dst=dest_ip,port=port,flags=flags,payload=payload,ttl=ttl}
end
---Make an encoded packet header
---@param src_ip string encoded IPv3
---@param dest_ip string encoded IPv3
---@param port integer
---@param flags table<string,boolean>
---@param ttl? integer
---@return string|nil
function np.newEncodedPacketHeader(src_ip,dest_ip,port,flags,ttl)
  if not ipv3.isIPv3(src_ip) or not ipv3.isIPv3(dest_ip) or type(port)~="number" then return nil end
  if port<0 or port>0xffff then return nil end
  if type(flags)~="table" then return nil end
  local eport=string.char(math.floor(port/256),port%256)
  local p=string.char(np.vernum+20/4)..src_ip..dest_ip..eport..string.char(np.buildFlags(flags))..string.char(ttl)
  return p..string.rep(string.char(0),20-#p)
end
---Encode a packet table
---@param p table<string,string|integer>
---@return string|nil
function np.encodePacket(p)
  if not p.src or not p.dst or not p.port or not p.flags or not p.payload or not p.ttl then return nil end
  local src_ip=ipv3.encode(p.src)
  local dest_ip=ipv3.encode(p.dst)
  local port=string.char(math.floor(p.port/256),p.port%256)
  local flags={}
  for k,v in pairs(p.flags) do flags[k]=v end
  local payload
  if type(p.payload)=="table" then
    payload=ser.serialize(p.payload)
    flags.serialized=true
  elseif type(p.payload)=="string" then payload=p.payload
  else payload=tostring(p.payload) end
  local ttl=string.char(p.ttl)
  local ep=string.char(np.vernum+20/4)..src_ip..dest_ip..port..string.char(np.buildFlags(flags))..ttl
  return ep..string.rep(string.char(0),20-#ep)..payload
end
---Decode a packet table
---@param raw string
---@return table|nil
function np.decodePacket(raw)
  local version=raw:byte(1)&0xF0
  local header_len=(raw:byte(1)&0xF)*4
  if version~=np.vernum then return nil end
  local src_ip=ipv3.decode(raw:sub(2,7))
  local dst_ip=ipv3.decode(raw:sub(8,13))
  local port=raw:byte(14)*256+raw:byte(15)
  local flags=np.parseFlags(raw:byte(16))
  local ttl=raw:byte(17)
  local payload
  if flags.serialized then
    payload=ser.unserialize(raw:sub(header_len+1,#raw))
  else payload=raw:sub(header_len+1,#raw) end
  if not src_ip or not dst_ip or not port or not flags then return nil end
  return {src=src_ip,dst=dst_ip,port=port,flags=flags,payload=payload,ttl=ttl}
end
function np.checkPacket(p)
  return type(p)=="string"
  and (p:byte(1)&0xF)*4>=20
  and #p>=(p:byte(1)&0xF)*4
  and p:byte(1)&0xF0>0x80
end
function np.validatePacket(p)
  if not np.checkPacket(p) then return false end
  if not ipv3.checkIPv3(ipv3.decode(p:sub(2,7)))
  or not ipv3.checkIPv3(ipv3.decode(p:sub(8,13))) then return false end
  return true
end
function np.splitPacket(p)
  if not np.checkPacket(p) then return nil,nil end
  local hl=np.header.getLength(p)
  return p:sub(1,hl),p:sub(hl+1,#p)
end
np.header={}
---@param p string
---@return integer
function np.header.getVersion(p)
  if not np.checkPacket(p) then return nil end
  return p:byte(1)&0xF0
end
---@param p string
---@return integer
function np.header.getLength(p)
  if not np.checkPacket(p) then return nil end
  return (p:byte(1)&0xF)*4
end
function np.header.getIPs(p)
  if not np.checkPacket(p) then return nil end
  return ipv3.decode(p:sub(2,7)),ipv3.decode(p:sub(8,13))
end
---@param p string
---@return string,string
function np.header.getRawIPs(p)
  if not np.checkPacket(p) then return nil,nil end
  return p:sub(2,7),p:sub(8,13)
end
---@param p string
---@return integer
function np.header.getPort(p)
  if not np.checkPacket(p) then return nil end
  return p:byte(14)*256+p:byte(15)
end
function np.header.getFlags(p)
  if not np.checkPacket(p) then return nil end
  return np.parseFlags(p:byte(16))
end
---@param p string
---@return integer
function np.header.getTTL(p)
  if not np.checkPacket(p) then return nil end
  return p:byte(17)
end
---@param p string
---@return string
function np.header.getPayload(p)
  return p:sub(np.header.getLength(p)+1,#p)
end

return np
--[[
version 1011(0000)=np 3.x
netpacket:
1                2          7  8      13  14        15  16     17   18-20
<ver:4bi+len:4bi><source_ipv3><dest_ipv3><virtual-port><flags><TTL><padding><data>
1 byte           6 bytes       6 bytes.    2 bytes      1byte  1b
flags:
0x01=BROADCAST(for search)
0x02=CONTROL
0x04=FRAGMENT
0x08=SERIALIZED
first byte: version+header_length/4
version(mask 11110000): 8+version num
header_len(mask 00001111): header length/4, at least 20
]]