-- *********************************************
-- SuperData Protocol Client for GrandMA2
-- Version: 1.0.0
-- Author: Yunsio SuperStage Team
-- *********************************************

local internal_name = select(1, ...)
local visible_name = select(2, ...)

-- ===========================================
-- 协议常量定义
-- ===========================================
local SUPERDATA = {
    -- 协议标识
    MAGIC = "SPDT",
    VERSION = 1,
    HEADER_SIZE = 24,
    
    -- 端口
    DISCOVERY_PORT = 5965,
    DATA_PORT = 5966,
    
    -- 时间间隔 (秒)
    BROADCAST_INTERVAL = 1.0,
    HEARTBEAT_INTERVAL = 3.0,
    TIMEOUT = 10.0,
    
    -- 平台代码
    PLATFORM = {
        UNKNOWN = 0,
        UNITY = 1,
        UNREAL = 2,
        VECTORWORKS = 3,
        GRANDMA = 4,
        CUSTOM = 255
    },
    
    -- 数据包类型
    PKT = {
        SERVICE_ANNOUNCE    = 0x0001,
        SERVICE_QUERY       = 0x0002,
        SERVICE_RESPONSE    = 0x0003,
        CONNECT             = 0x0010,
        CONNECT_ACK         = 0x0011,
        DISCONNECT          = 0x0012,
        HEARTBEAT           = 0x0013,
        FIXTURE_LIST_REQ    = 0x0020,
        FIXTURE_LIST_RESP   = 0x0021,
        FIXTURE_UPDATE      = 0x0022,
        FIXTURE_CREATE      = 0x0023,
        FIXTURE_DELETE      = 0x0024,
        FIXTURE_SYNC_DONE   = 0x0025,
        TYPE_LIST_REQ       = 0x0030,
        TYPE_LIST_RESP      = 0x0031,
        TYPE_MAPPING_UPDATE = 0x0032,
        ERROR               = 0xFF00
    },
    
    -- 同步模式
    SYNC_MODE = {
        IMPORT_ONLY = 0,
        EXPORT_ONLY = 1,
        BIDIRECTIONAL = 2
    },
    
    -- 角色
    ROLE = {
        SERVER = 0,
        CLIENT = 1,
        BIDIRECTIONAL = 2
    }
}

-- ===========================================
-- JSON 序列化/反序列化模块
-- ===========================================
local JSON = {}

function JSON.encode(val)
    local t = type(val)
    if t == "nil" then
        return "null"
    elseif t == "boolean" then
        return val and "true" or "false"
    elseif t == "number" then
        if val ~= val then return "null" end -- NaN
        if val >= math.huge then return "1e999" end
        if val <= -math.huge then return "-1e999" end
        return tostring(val)
    elseif t == "string" then
        local s = val:gsub('[\\"\x00-\x1f]', function(c)
            local codes = {
                ['\\'] = '\\\\', ['"'] = '\\"', ['\n'] = '\\n',
                ['\r'] = '\\r', ['\t'] = '\\t'
            }
            return codes[c] or string.format('\\u%04x', c:byte())
        end)
        return '"' .. s .. '"'
    elseif t == "table" then
        local isArray = #val > 0 or next(val) == nil
        -- 检查是否为纯数组
        if isArray then
            for k, _ in pairs(val) do
                if type(k) ~= "number" then
                    isArray = false
                    break
                end
            end
        end
        
        local parts = {}
        if isArray then
            for i, v in ipairs(val) do
                parts[i] = JSON.encode(v)
            end
            return "[" .. table.concat(parts, ",") .. "]"
        else
            local i = 1
            for k, v in pairs(val) do
                if type(k) == "string" then
                    parts[i] = JSON.encode(k) .. ":" .. JSON.encode(v)
                    i = i + 1
                end
            end
            return "{" .. table.concat(parts, ",") .. "}"
        end
    end
    return "null"
end

function JSON.decode(str)
    if not str or str == "" then return nil end
    local pos = 1
    local char = function() return str:sub(pos, pos) end
    local skip_ws = function()
        while char():match("[ \t\n\r]") do pos = pos + 1 end
    end
    
    local parse_value, parse_string, parse_number, parse_array, parse_object
    
    parse_string = function()
        pos = pos + 1 -- skip opening "
        local start = pos
        local result = ""
        while pos <= #str do
            local c = char()
            if c == '"' then
                pos = pos + 1
                return result
            elseif c == '\\' then
                pos = pos + 1
                local esc = char()
                if esc == 'n' then result = result .. '\n'
                elseif esc == 'r' then result = result .. '\r'
                elseif esc == 't' then result = result .. '\t'
                elseif esc == '"' then result = result .. '"'
                elseif esc == '\\' then result = result .. '\\'
                elseif esc == 'u' then
                    local hex = str:sub(pos+1, pos+4)
                    result = result .. string.char(tonumber(hex, 16))
                    pos = pos + 4
                end
            else
                result = result .. c
            end
            pos = pos + 1
        end
        return result
    end
    
    parse_number = function()
        local start = pos
        if char() == '-' then pos = pos + 1 end
        while char():match("[0-9]") do pos = pos + 1 end
        if char() == '.' then
            pos = pos + 1
            while char():match("[0-9]") do pos = pos + 1 end
        end
        if char():lower() == 'e' then
            pos = pos + 1
            if char():match("[+-]") then pos = pos + 1 end
            while char():match("[0-9]") do pos = pos + 1 end
        end
        return tonumber(str:sub(start, pos-1))
    end
    
    parse_array = function()
        local arr = {}
        pos = pos + 1 -- skip [
        skip_ws()
        if char() == ']' then
            pos = pos + 1
            return arr
        end
        while true do
            skip_ws()
            arr[#arr + 1] = parse_value()
            skip_ws()
            if char() == ']' then
                pos = pos + 1
                return arr
            elseif char() == ',' then
                pos = pos + 1
            else
                break
            end
        end
        return arr
    end
    
    parse_object = function()
        local obj = {}
        pos = pos + 1 -- skip {
        skip_ws()
        if char() == '}' then
            pos = pos + 1
            return obj
        end
        while true do
            skip_ws()
            if char() ~= '"' then break end
            local key = parse_string()
            skip_ws()
            if char() ~= ':' then break end
            pos = pos + 1
            skip_ws()
            obj[key] = parse_value()
            skip_ws()
            if char() == '}' then
                pos = pos + 1
                return obj
            elseif char() == ',' then
                pos = pos + 1
            else
                break
            end
        end
        return obj
    end
    
    parse_value = function()
        skip_ws()
        local c = char()
        if c == '"' then return parse_string()
        elseif c == '{' then return parse_object()
        elseif c == '[' then return parse_array()
        elseif c == 't' then pos = pos + 4; return true
        elseif c == 'f' then pos = pos + 5; return false
        elseif c == 'n' then pos = pos + 4; return nil
        elseif c:match("[%-0-9]") then return parse_number()
        end
        return nil
    end
    
    return parse_value()
end

-- ===========================================
-- 二进制数据处理模块
-- ===========================================
local Binary = {}

-- 写入 Little Endian uint16
function Binary.writeUInt16LE(value)
    return string.char(
        value % 256,
        math.floor(value / 256) % 256
    )
end

-- 写入 Little Endian uint32
function Binary.writeUInt32LE(value)
    return string.char(
        value % 256,
        math.floor(value / 256) % 256,
        math.floor(value / 65536) % 256,
        math.floor(value / 16777216) % 256
    )
end

-- 写入 Little Endian int64
function Binary.writeInt64LE(value)
    local low = value % 4294967296
    local high = math.floor(value / 4294967296)
    return Binary.writeUInt32LE(low) .. Binary.writeUInt32LE(high)
end

-- 读取 Little Endian uint16
function Binary.readUInt16LE(data, offset)
    offset = offset or 1
    local b1, b2 = data:byte(offset, offset + 1)
    return b1 + b2 * 256
end

-- 读取 Little Endian uint32
function Binary.readUInt32LE(data, offset)
    offset = offset or 1
    local b1, b2, b3, b4 = data:byte(offset, offset + 3)
    return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
end

-- 读取 Little Endian int64
function Binary.readInt64LE(data, offset)
    offset = offset or 1
    local low = Binary.readUInt32LE(data, offset)
    local high = Binary.readUInt32LE(data, offset + 4)
    return low + high * 4294967296
end

-- ===========================================
-- SuperData 客户端类
-- ===========================================
local SuperDataClient = {
    -- 状态
    connected = false,
    sessionId = nil,
    sequenceNumber = 0,
    
    -- Socket
    tcpSocket = nil,
    udpSocket = nil,
    
    -- 服务器信息
    serverInfo = nil,
    discoveredServices = {},
    
    -- 灯具数据
    fixtures = {},
    fixtureTypes = {},
    
    -- 本地信息
    localInfo = nil,
    
    -- 回调
    onConnected = nil,
    onDisconnected = nil,
    onFixturesReceived = nil,
    onError = nil,
    
    -- 计时器
    lastHeartbeat = 0,
    lastServerHeartbeat = 0
}

-- 生成唯一ID
function SuperDataClient:generateServiceId()
    local chars = "0123456789abcdef"
    local id = ""
    for i = 1, 32 do
        local idx = math.random(1, 16)
        id = id .. chars:sub(idx, idx)
    end
    return id
end

-- 获取当前时间戳 (毫秒)
function SuperDataClient:getTimestamp()
    return math.floor(gma.gettime() * 1000)
end

-- 初始化
function SuperDataClient:init()
    -- 设置随机种子
    math.randomseed(os.time())
    
    -- 初始化本地信息
    self.localInfo = {
        serviceId = self:generateServiceId(),
        serviceName = "GrandMA2 SuperData Client",
        platform = SUPERDATA.PLATFORM.GRANDMA,
        platformVersion = gma.git_version() or "3.3.4",
        superStageVersion = "1.0.0",
        ipAddress = gma.network.getprimaryip() or "0.0.0.0",
        dataPort = SUPERDATA.DATA_PORT,
        role = SUPERDATA.ROLE.CLIENT,
        fixtureCount = 0,
        requiresAuth = false,
        projectName = gma.network.getsessionname() or "MA2 Project"
    }
    
    gma.echo("[SuperData] Initialized - ID: " .. self.localInfo.serviceId:sub(1, 8) .. "...")
    return true
end

-- 构建数据包
function SuperDataClient:buildPacket(packetType, payload)
    self.sequenceNumber = self.sequenceNumber + 1
    
    local payloadStr = ""
    if payload then
        payloadStr = JSON.encode(payload)
    else
        payloadStr = "{}"
    end
    
    local header = SUPERDATA.MAGIC
        .. Binary.writeUInt16LE(SUPERDATA.VERSION)
        .. Binary.writeUInt16LE(packetType)
        .. Binary.writeUInt32LE(self.sequenceNumber)
        .. Binary.writeInt64LE(self:getTimestamp())
        .. Binary.writeUInt32LE(#payloadStr)
    
    return header .. payloadStr
end

-- 解析数据包
function SuperDataClient:parsePacket(data)
    if #data < SUPERDATA.HEADER_SIZE then
        return nil, "Packet too short: " .. #data .. " bytes (need " .. SUPERDATA.HEADER_SIZE .. ")"
    end
    
    -- 验证魔数
    local magic = data:sub(1, 4)
    if magic ~= SUPERDATA.MAGIC then
        return nil, "Invalid magic: '" .. magic .. "' (expected 'SPDT')"
    end
    
    local packet = {
        version = Binary.readUInt16LE(data, 5),
        packetType = Binary.readUInt16LE(data, 7),
        sequenceNumber = Binary.readUInt32LE(data, 9),
        timestamp = Binary.readInt64LE(data, 13),
        payloadLength = Binary.readUInt32LE(data, 21)
    }
    
    -- 读取负载
    if #data >= SUPERDATA.HEADER_SIZE + packet.payloadLength then
        local payloadStr = data:sub(SUPERDATA.HEADER_SIZE + 1, SUPERDATA.HEADER_SIZE + packet.payloadLength)
        
        -- 调试：显示 JSON 字符串
        if #payloadStr > 0 then
            gma.echo("[SuperData] JSON payload (" .. #payloadStr .. " bytes): " .. payloadStr:sub(1, 200))
        end
        
        -- 安全解析 JSON
        local ok, result = pcall(function()
            return JSON.decode(payloadStr)
        end)
        
        if ok then
            packet.payload = result
        else
            gma.echo("[SuperData] JSON parse error: " .. tostring(result))
            packet.payload = {}
        end
    else
        gma.echo("[SuperData] Incomplete payload: have " .. (#data - SUPERDATA.HEADER_SIZE) .. ", need " .. packet.payloadLength)
        packet.payload = {}
    end
    
    return packet
end

-- 加载 Socket 库
function SuperDataClient:loadSocket()
    gma.echo("[SuperData] Attempting to load socket library...")
    
    -- 尝试多种路径
    local paths = {
        "./plugins/requirements/?.lua",
        "./plugins/?.lua",
        "./?.lua"
    }
    
    for _, path in ipairs(paths) do
        package.path = package.path .. ";" .. path
    end
    
    -- 尝试方式1: socket.socket
    local ok, socket = pcall(function()
        return require("socket.socket")
    end)
    if ok and socket then
        self.socket = socket
        gma.echo("[SuperData] Socket loaded via 'socket.socket'")
        return true
    else
        gma.echo("[SuperData] socket.socket failed: " .. tostring(socket))
    end
    
    -- 尝试方式2: socket.core
        ok, socket = pcall(function()
            return require("socket.core")
        end)
    if ok and socket then
        self.socket = socket
        gma.echo("[SuperData] Socket loaded via 'socket.core'")
        return true
    else
        gma.echo("[SuperData] socket.core failed: " .. tostring(socket))
    end
    
    -- 尝试方式3: socket
        ok, socket = pcall(function()
            return require("socket")
        end)
    if ok and socket then
        self.socket = socket
        gma.echo("[SuperData] Socket loaded via 'socket'")
        return true
    else
        gma.echo("[SuperData] socket failed: " .. tostring(socket))
    end
    
    gma.echo("[SuperData] ERROR: All socket loading methods failed!")
    gma.echo("[SuperData] Please install LuaSocket in ./plugins/requirements/")
        return false
end

-- 启动 UDP 服务发现
function SuperDataClient:startDiscovery()
    if not self.socket then
        if not self:loadSocket() then
            return false
        end
    end
    
    -- 创建 UDP socket
    local udp, err = self.socket.udp()
    if not udp then
        gma.echo("[SuperData] Failed to create UDP socket: " .. (err or "unknown"))
        return false
    end
    
    -- 设置广播和非阻塞
    udp:setsockname("*", SUPERDATA.DISCOVERY_PORT)
    udp:settimeout(0)
    
    -- 允许广播
    local ok, err = pcall(function()
        udp:setoption("broadcast", true)
    end)
    
    self.udpSocket = udp
    self.discoveredServices = {}
    
    gma.echo("[SuperData] Discovery started on port " .. SUPERDATA.DISCOVERY_PORT)
    return true
end

-- 发送服务查询
function SuperDataClient:sendServiceQuery()
    if not self.udpSocket then return false end
    
    local packet = self:buildPacket(SUPERDATA.PKT.SERVICE_QUERY, {})
    
    -- 广播查询
    local ok, err = self.udpSocket:sendto(packet, "255.255.255.255", SUPERDATA.DISCOVERY_PORT)
    if not ok then
        gma.echo("[SuperData] Failed to send query: " .. (err or "unknown"))
        return false
    end
    
    gma.echo("[SuperData] Service query sent")
    return true
end

-- 检查服务发现响应
function SuperDataClient:checkDiscovery()
    if not self.udpSocket then return end
    
    while true do
        local data, ip, port = self.udpSocket:receivefrom()
        if not data then break end
        
        -- 调试：显示收到的原始数据
        gma.echo("[SuperData] UDP received " .. #data .. " bytes from " .. (ip or "?") .. ":" .. (port or "?"))
        
        -- 显示前几个字节用于调试
        if #data >= 4 then
            local magic = data:sub(1, 4)
            gma.echo("[SuperData] Magic bytes: " .. magic .. " (expected: SPDT)")
        end
        
        local packet, err = self:parsePacket(data)
        if packet then
            gma.echo("[SuperData] Packet type: 0x" .. string.format("%04X", packet.packetType))
            gma.echo("[SuperData] Payload length: " .. (packet.payloadLength or 0))
            
            if packet.packetType == SUPERDATA.PKT.SERVICE_ANNOUNCE or 
               packet.packetType == SUPERDATA.PKT.SERVICE_RESPONSE then
                local info = packet.payload
                
                -- 调试：显示 payload 内容
                if info then
                    gma.echo("[SuperData] Payload has serviceId: " .. (info.serviceId and "YES" or "NO"))
                    gma.echo("[SuperData] Payload has serviceName: " .. (info.serviceName or "nil"))
                else
                    gma.echo("[SuperData] WARNING: Payload is nil or empty!")
                end
                
                if info and info.serviceId then
                    self.discoveredServices[info.serviceId] = {
                        info = info,
                        ip = info.ipAddress or ip,  -- 优先使用 payload 中的 IP
                        port = info.dataPort or SUPERDATA.DATA_PORT,
                        lastSeen = gma.gettime()
                    }
                    gma.echo("[SuperData] Discovered: " .. (info.serviceName or "Unknown") .. " @ " .. (info.ipAddress or ip))
                else
                    gma.echo("[SuperData] WARNING: No serviceId in payload!")
                end
            else
                gma.echo("[SuperData] Ignoring packet type: 0x" .. string.format("%04X", packet.packetType))
            end
        else
            gma.echo("[SuperData] Parse error: " .. (err or "unknown"))
            -- 尝试显示原始数据的十六进制
            local hex = ""
            for i = 1, math.min(32, #data) do
                hex = hex .. string.format("%02X ", data:byte(i))
            end
            gma.echo("[SuperData] Raw data (first 32 bytes): " .. hex)
        end
    end
end

-- 获取发现的服务列表
function SuperDataClient:getDiscoveredServices()
    local services = {}
    for id, service in pairs(self.discoveredServices) do
        table.insert(services, {
            id = id,
            name = service.info.serviceName,
            ip = service.info.ipAddress or service.ip,
            port = service.info.dataPort or SUPERDATA.DATA_PORT,
            platform = service.info.platform,
            fixtureCount = service.info.fixtureCount
        })
    end
    return services
end

-- 连接到服务器
function SuperDataClient:connect(serverIP, serverPort)
    if not self.socket then
        if not self:loadSocket() then
            return false, "Socket library not available"
        end
    end
    
    serverPort = serverPort or SUPERDATA.DATA_PORT
    
    gma.echo("[SuperData] Connecting to " .. serverIP .. ":" .. serverPort .. "...")
    
    -- 创建 TCP socket
    local tcp, err = self.socket.tcp()
    if not tcp then
        return false, "Failed to create TCP socket: " .. (err or "unknown")
    end
    
    -- 设置超时
    tcp:settimeout(5)
    
    -- 连接
    local ok, err = tcp:connect(serverIP, serverPort)
    if not ok then
        tcp:close()
        return false, "Connection failed: " .. (err or "unknown")
    end
    
    -- 设置非阻塞
    tcp:settimeout(0)
    
    self.tcpSocket = tcp
    self.serverIP = serverIP
    self.serverPort = serverPort
    
    -- 发送连接请求
    local connectPayload = {
        clientInfo = self.localInfo,
        syncMode = SUPERDATA.SYNC_MODE.IMPORT_ONLY,
        authToken = ""
    }
    
    local packet = self:buildPacket(SUPERDATA.PKT.CONNECT, connectPayload)
    local sent, err = tcp:send(packet)
    
    if not sent then
        tcp:close()
        self.tcpSocket = nil
        return false, "Failed to send connect: " .. (err or "unknown")
    end
    
    -- 等待响应
    tcp:settimeout(5)
    local response = self:receivePacket()
    tcp:settimeout(0)
    
    if response and response.packetType == SUPERDATA.PKT.CONNECT_ACK then
        if response.payload and response.payload.accepted then
            self.connected = true
            self.sessionId = response.payload.sessionId
            self.serverInfo = response.payload.serverInfo
            self.lastHeartbeat = gma.gettime()
            self.lastServerHeartbeat = gma.gettime()
            
            gma.echo("[SuperData] Connected! Session: " .. (self.sessionId or "none"):sub(1, 8) .. "...")
            
            if self.onConnected then
                self.onConnected(self.serverInfo)
            end
            
            return true
        else
            local errMsg = response.payload and response.payload.errorMessage or "Connection rejected"
            tcp:close()
            self.tcpSocket = nil
            return false, errMsg
        end
    else
        tcp:close()
        self.tcpSocket = nil
        return false, "No valid response from server"
    end
end

-- 接收数据包
function SuperDataClient:receivePacket()
    if not self.tcpSocket then return nil end
    
    -- 先读取头部
    local header, err = self.tcpSocket:receive(SUPERDATA.HEADER_SIZE)
    if not header then
        if err ~= "timeout" then
            gma.echo("[SuperData] Receive error: " .. (err or "unknown"))
        end
        return nil
    end
    
    -- 解析头部获取负载长度
    local payloadLength = Binary.readUInt32LE(header, 21)
    
    -- 读取负载
    local payload = ""
    if payloadLength > 0 then
        payload, err = self.tcpSocket:receive(payloadLength)
        if not payload then
            return nil
        end
    end
    
    return self:parsePacket(header .. payload)
end

-- 发送数据包
function SuperDataClient:sendPacket(packetType, payload)
    if not self.tcpSocket then return false end
    
    local packet = self:buildPacket(packetType, payload)
    local sent, err = self.tcpSocket:send(packet)
    
    if not sent then
        gma.echo("[SuperData] Send error: " .. (err or "unknown"))
        return false
    end
    
    return true
end

-- 发送心跳
function SuperDataClient:sendHeartbeat()
    if not self.connected then return end
    
    local now = gma.gettime()
    if now - self.lastHeartbeat >= SUPERDATA.HEARTBEAT_INTERVAL then
        self:sendPacket(SUPERDATA.PKT.HEARTBEAT, {})
        self.lastHeartbeat = now
    end
end

-- 检查连接超时
function SuperDataClient:checkTimeout()
    if not self.connected then return end
    
    local now = gma.gettime()
    if now - self.lastServerHeartbeat > SUPERDATA.TIMEOUT then
        gma.echo("[SuperData] Connection timeout!")
        self:disconnect()
        return true
    end
    return false
end

-- 请求灯具列表
function SuperDataClient:requestFixtureList()
    if not self.connected then
        gma.echo("[SuperData] Not connected")
        return false
    end
    
    gma.echo("[SuperData] Requesting fixture list...")
    return self:sendPacket(SUPERDATA.PKT.FIXTURE_LIST_REQ, {})
end

-- 请求类型列表
function SuperDataClient:requestTypeList()
    if not self.connected then return false end
    
    gma.echo("[SuperData] Requesting type list...")
    return self:sendPacket(SUPERDATA.PKT.TYPE_LIST_REQ, {})
end

-- 处理接收到的数据包
function SuperDataClient:processPackets()
    if not self.tcpSocket then return end
    
    while true do
        local packet = self:receivePacket()
        if not packet then break end
        
        self.lastServerHeartbeat = gma.gettime()
        
        local pktType = packet.packetType
        
        if pktType == SUPERDATA.PKT.HEARTBEAT then
            -- 心跳响应
        elseif pktType == SUPERDATA.PKT.FIXTURE_LIST_RESP then
            self:handleFixtureListResponse(packet.payload)
        elseif pktType == SUPERDATA.PKT.FIXTURE_UPDATE then
            self:handleFixtureUpdate(packet.payload)
        elseif pktType == SUPERDATA.PKT.FIXTURE_SYNC_DONE then
            self:handleSyncComplete(packet.payload)
        elseif pktType == SUPERDATA.PKT.TYPE_LIST_RESP then
            self:handleTypeListResponse(packet.payload)
        elseif pktType == SUPERDATA.PKT.DISCONNECT then
            gma.echo("[SuperData] Server disconnected")
            self:disconnect()
            break
        elseif pktType == SUPERDATA.PKT.ERROR then
            local errMsg = packet.payload and packet.payload.errorMessage or "Unknown error"
            gma.echo("[SuperData] Error: " .. errMsg)
            if self.onError then
                self.onError(packet.payload)
            end
        end
    end
end

-- 处理灯具列表响应
function SuperDataClient:handleFixtureListResponse(payload)
    if not payload then return end
    
    self.fixtures = payload.fixtures or {}
    self.fixtureTypes = payload.fixtureTypes or {}
    
    gma.echo("[SuperData] Received " .. #self.fixtures .. " fixtures")
    
    -- 调试：显示每个灯具的原始数据
    for i, f in ipairs(self.fixtures) do
        if i <= 5 then  -- 只显示前5个
            local fid = f.fixtureID or f.fixtureId or "NIL"
            local u = f.universe or "NIL"
            local a = f.startAddress or "NIL"
            local name = f.name or "NIL"
            gma.echo(string.format("[DEBUG] Fixture %d: fixtureID=%s, universe=%s, addr=%s, name=%s", 
                i, tostring(fid), tostring(u), tostring(a), tostring(name)))
        end
    end
    
    if self.onFixturesReceived then
        self.onFixturesReceived(self.fixtures)
    end
end

-- 处理灯具更新
function SuperDataClient:handleFixtureUpdate(payload)
    if not payload or not payload.uuid then return end
    
    -- 查找并更新灯具
    for i, fixture in ipairs(self.fixtures) do
        if fixture.uuid == payload.uuid then
            if payload.changes then
                for key, value in pairs(payload.changes) do
                    fixture[key] = value
                end
            end
            gma.echo("[SuperData] Fixture updated: " .. fixture.name)
            break
        end
    end
end

-- 处理同步完成
function SuperDataClient:handleSyncComplete(payload)
    gma.echo("[SuperData] Sync complete - " .. (payload.syncedCount or 0) .. " fixtures")
end

-- 处理类型列表响应
function SuperDataClient:handleTypeListResponse(payload)
    if payload and payload.types then
        self.fixtureTypes = payload.types
        gma.echo("[SuperData] Received " .. #self.fixtureTypes .. " fixture types")
    end
end

-- 断开连接
function SuperDataClient:disconnect()
    if self.tcpSocket then
        if self.connected then
            self:sendPacket(SUPERDATA.PKT.DISCONNECT, {})
        end
        self.tcpSocket:close()
        self.tcpSocket = nil
    end
    
    if self.udpSocket then
        self.udpSocket:close()
        self.udpSocket = nil
    end
    
    local wasConnected = self.connected
    self.connected = false
    self.sessionId = nil
    
    if wasConnected then
        gma.echo("[SuperData] Disconnected")
        if self.onDisconnected then
            self.onDisconnected()
        end
    end
end

-- 更新循环
function SuperDataClient:update()
    -- 检查服务发现
    self:checkDiscovery()
    
    -- 如果已连接
    if self.connected then
        -- 发送心跳
        self:sendHeartbeat()
        
        -- 检查超时
        if self:checkTimeout() then
            return
        end
        
        -- 处理接收的数据包
        self:processPackets()
    end
end

-- 获取灯具数据
function SuperDataClient:getFixtures()
    return self.fixtures
end

-- ===========================================
-- MA2 灯具数据导出
-- ===========================================
local MA2Export = {}

-- 获取所有 Fixture
function MA2Export.getFixtures()
    local fixtures = {}
    local O = gma.show.getobj
    
    -- 遍历 Fixture 池
    local fixturePoolHandle = O.handle("Fixture")
    if not fixturePoolHandle then
        gma.echo("[SuperData] Fixture pool not found")
        return fixtures
    end
    
    local count = O.amount(fixturePoolHandle)
    gma.echo("[SuperData] Found " .. count .. " fixtures in pool")
    
    for i = 0, count - 1 do
        local fixtureHandle = O.child(fixturePoolHandle, i)
        if fixtureHandle and O.verify(fixtureHandle) then
            local fixture = MA2Export.extractFixtureData(fixtureHandle, O)
            if fixture then
                table.insert(fixtures, fixture)
            end
        end
    end
    
    return fixtures
end

-- 提取单个灯具数据
function MA2Export.extractFixtureData(handle, O)
    O = O or gma.show.getobj
    
    local name = O.name(handle)
    local fixtureId = O.number(handle)
    
    if not name or not fixtureId then return nil end
    
    local fixture = {
        uuid = "ma2_fixture_" .. fixtureId,
        name = name,
        fixtureType = O.class(handle) or "Unknown",
        universe = 1,
        startAddress = 1,
        fixtureID = fixtureId,
        position = {0, 0, 0},
        rotation = {0, 0, 0},
        scale = {1, 1, 1},
        channelSpan = 0,
        customProperties = {}
    }
    
    -- 尝试获取属性
    local propCount = gma.show.property.amount(handle)
    if propCount then
        for j = 0, propCount - 1 do
            local propName = gma.show.property.name(handle, j)
            local propValue = gma.show.property.get(handle, j)
            
            if propName then
                propName = propName:lower()
                if propName:find("universe") or propName:find("uni") then
                    fixture.universe = tonumber(propValue) or 1
                elseif propName:find("address") or propName:find("addr") then
                    fixture.startAddress = tonumber(propValue) or 1
                elseif propName:find("channel") then
                    fixture.channelSpan = tonumber(propValue) or 0
                end
            end
        end
    end
    
    return fixture
end

-- ===========================================
-- MA2 灯具导入模块
-- ===========================================
local MA2Import = {}

-- 默认灯具类型（固定为 3，用户导入后自行替换）
-- 用 "List FixtureType" 命令查看你的类型 ID
MA2Import.fixtureTypeId = 3  -- FixtureType 编号（固定）
MA2Import.fixtureTypeName = "Generic"  -- FixtureType 名称（固定）

-- 检查 FixtureID 是否有重复
function MA2Import.checkDuplicateIDs(fixtures)
    local idMap = {}
    local duplicates = {}
    
    for i, f in ipairs(fixtures) do
        local id = f.fixtureID or f.fixtureId or i
        if idMap[id] then
            -- 记录重复
            table.insert(duplicates, id)
        else
            idMap[id] = true
        end
    end
    
    return duplicates
end

-- 生成 VectorWorks 风格的 Layers XML 用于导入灯具
-- 参考格式：fz2.xml (MA VectorWorks Exporter)
function MA2Import.generateLayersXML(fixtures, fixtureTypeName, fixtureTypeNo)
    local fixtureXMLs = {}
    
    for i, f in ipairs(fixtures) do
        -- 获取 fixtureID（协议中是 fixtureID，注意大小写）
        local fixtureId = f.fixtureID or f.fixtureId or i
        -- 协议规范：universe 范围 1-256，address 范围 1-512
        -- 但 Unity 可能发送 0-based 的 universe，必须确保 >= 1
        local universe = f.universe or 1
        if universe < 1 then universe = 1 end  -- 确保 universe >= 1
        local address = f.startAddress or 1
        if address < 1 then address = 1 end    -- 确保 address >= 1
        local name = f.name or ("Fixture_" .. fixtureId)
        -- 清理名称中的特殊字符
        name = name:gsub('"', ''):gsub('<', ''):gsub('>', ''):gsub('&', 'and')
        
        -- 调试输出（显示原始值和修正后的值）
        local rawUniverse = f.universe or "nil"
        local rawAddress = f.startAddress or "nil"
        gma.echo(string.format("[XML] Fixture %d: ID=%d, rawU=%s, rawA=%s -> U=%d, A=%d", 
            i, fixtureId, tostring(rawUniverse), tostring(rawAddress), universe, address))
        
        -- 计算绝对 DMX 地址: (universe-1)*512 + address
        local absoluteAddress = ((universe - 1) * 512) + address
        
        -- 获取位置信息（协议中是数组 [X, Y, Z]，单位是厘米 cm）
        -- MA2 使用米 m，需要 cm → m（÷100）
        -- 整体绕 Z 轴旋转 180 度后，X 和 Y 不再取反
        local posX, posY, posZ = 0, 0, 0
        if f.position then
            if type(f.position) == "table" then
                if f.position[1] then
                    -- 数组格式 [X, Y, Z]，cm → m
                    posX = (f.position[1] or 0) / 100
                    posY = (f.position[2] or 0) / 100
                    posZ = (f.position[3] or 0) / 100
                else
                    -- 对象格式 {x, y, z}，cm → m
                    posX = (f.position.x or 0) / 100
                    posY = (f.position.y or 0) / 100
                    posZ = (f.position.z or 0) / 100
                end
            end
        end
        
        -- 旋转
        local rotX, rotY, rotZ = 0, 0, 0
        if f.rotation then
            if type(f.rotation) == "table" then
                if f.rotation[1] then
                    -- 数组格式 [X, Y, Z]
                    rotX = f.rotation[1] or 0
                    rotY = f.rotation[2] or 0
                    rotZ = f.rotation[3] or 0
                else
                    -- 对象格式 {x, y, z}
                    rotX = f.rotation.x or 0
                    rotY = f.rotation.y or 0
                    rotZ = f.rotation.z or 0
                end
            end
        end
        
        -- SuperData → MA2 旋转修正（根据实测）
        -- Y轴 +180, Z轴 +90
        rotY = rotY + 180

        rotZ = rotZ + 90
        
        -- 使用正确的 3 个 Tab 缩进（与 fz2.xml 保持一致）
        local fixtureXML = string.format([[
			<Fixture name="%s" fixture_id="%d" channel_id="">
				<FixtureType name="%s">
					<No>
							%d
					</No>
				</FixtureType>
				<SubFixture index="0" react_to_grandmaster="true" color="FFFFFF">
					<Patch>
						<Address>
								%d
						</Address>
					</Patch>
					<AbsolutePosition>
						<Location x="%.3f" y="%.3f" z="%.3f"
/>
						<Rotation x="%.2f" y="%.2f" z="%.2f"
/>
						<Scaling x="1.000" y="1.000" z="1.000"
/>
					</AbsolutePosition>
				</SubFixture>
			</Fixture>]], 
            name, fixtureId, fixtureTypeName, fixtureTypeNo,
            absoluteAddress, posX, posY, posZ, rotX, rotY, rotZ)
        
        table.insert(fixtureXMLs, fixtureXML)
    end
    
    -- 使用灯具类型名称作为 Layer 名称（与 fz2.xml 保持一致）
    local layerName = fixtureTypeName
    local fixturesContent = table.concat(fixtureXMLs, "\n")
    
    -- 使用与 fz2.xml 完全一致的格式
    local xml = string.format([[<MA xmlns="http://schemas.malighting.de/grandma2/xml/MA">
	<InfoItems>
		<Info type="Invisible" date="%s">
				SuperData Plugin Import
		</Info>
	</InfoItems>
	<Layers>
		<Layer name="%s">
%s
		</Layer>
	</Layers>
</MA>]], os.date("%y/%m/%d"), layerName, fixturesContent)
    
    return xml
end

function MA2Import.importFixtures(fixtures)
    local success = 0
    local failed = 0
    
    if #fixtures == 0 then
        gma.echo("[SuperData] No fixtures to import")
        return 0, 0
    end
    
    -- 调试：显示接收到的 fixtures 数据
    gma.echo("[SuperData] ========== FIXTURES DATA ==========")
    for i, f in ipairs(fixtures) do
        if i <= 5 then
            gma.echo(string.format("[SuperData] #%d: fixtureID=%s, name=%s, U=%s, A=%s",
                i,
                tostring(f.fixtureID or f.fixtureId or "NIL"),
                tostring(f.name or "NIL"),
                tostring(f.universe or "NIL"),
                tostring(f.startAddress or "NIL")))
        end
    end
    gma.echo("[SuperData] ===================================")
    
    local progress = gma.gui.progress.start("Importing fixtures...")
    gma.gui.progress.setrange(progress, 0, 100)
    gma.gui.progress.set(progress, 10)
    
    -- 获取灯具类型信息
    local fixtureTypeName = MA2Import.fixtureTypeName or "Generic Dimmer"
    local fixtureTypeNo = MA2Import.fixtureTypeId or 1
    
    -- Step 1: 生成 Layers XML（VectorWorks 风格）
    gma.gui.progress.settext(progress, "Generating layers XML...")
    local xml = MA2Import.generateLayersXML(fixtures, fixtureTypeName, fixtureTypeNo)
    gma.echo("[SuperData] Generated layers XML with " .. #fixtures .. " fixtures")
    
    -- Step 2: 写入临时文件到 importexport 文件夹
    gma.gui.progress.set(progress, 30)
    gma.gui.progress.settext(progress, "Writing temp file...")
    
    gma.cmd('SelectDrive 1')  -- 选择内部驱动器
    local showPath = gma.show.getvar("PATH")
    local tempFileName = "superdata_import"
    local tempFilePath = showPath .. "/importexport/" .. tempFileName .. ".xml"
    
    gma.echo("[SuperData] Writing to: " .. tempFilePath)
    
    local file = io.open(tempFilePath, "w")
    if not file then
        gma.gui.progress.stop(progress)
        gma.echo("[SuperData] ERROR: Cannot create temp file!")
        return 0, #fixtures
    end
    file:write(xml)
    file:close()
    gma.echo("[SuperData] File written successfully")
    
    -- Step 3: 进入 EditSetup
    gma.gui.progress.set(progress, 50)
    gma.gui.progress.settext(progress, "Entering EditSetup...")
    gma.cmd('CD EditSetup')
    gma.sleep(0.2)
    
    -- Step 4: 导入 Layers
    gma.gui.progress.set(progress, 60)
    gma.gui.progress.settext(progress, "Importing layers...")
    local importCmd = 'Import "' .. tempFileName .. '" At Layers /nc'
    gma.echo("[SuperData] " .. importCmd)
    gma.cmd(importCmd)
    gma.sleep(0.5)
    
    -- Step 5: 返回根目录
    gma.cmd('CD /')
    gma.sleep(0.3)
    
    -- Step 6: 修正 Fixture ID
    -- MA2 导入时会自动重新分配 ID，需要在 EditSetup 中修正
    gma.gui.progress.set(progress, 70)
    gma.gui.progress.settext(progress, "Fixing Fixture IDs...")
    gma.echo("[SuperData] ========== FIXING FIXTURE IDs ==========")
    
    -- 进入 EditSetup
    gma.cmd('CD EditSetup')
    gma.sleep(0.2)
    
    -- 按 DMX 地址构建映射：address -> targetId
    -- 然后根据导入顺序（也就是当前分配的 ID）来修正
    for i, f in ipairs(fixtures) do
        local targetId = f.fixtureID or f.fixtureId
        local universe = f.universe or 1
        local address = f.startAddress or 1
        
        if universe < 1 then universe = 1 end
        if address < 1 then address = 1 end
        
        if targetId and targetId ~= i then
            -- 方法1: 使用 Assign 命令修改 ID
            -- Assign Fixture <currentId> /ID=<targetId>
            local assignCmd = string.format('Assign Fixture %d /ID=%d', i, targetId)
            gma.echo("[Fix] " .. assignCmd)
            pcall(function() gma.cmd(assignCmd) end)
            gma.sleep(0.03)
        end
        
        gma.gui.progress.set(progress, 70 + (i / #fixtures) * 15)
    end
    
    -- 返回根目录
    gma.cmd('CD /')
    gma.echo("[SuperData] =========================================")
    
    -- Step 7: 不清理，保留 XML 文件用于调试
    gma.gui.progress.set(progress, 90)
    gma.gui.progress.settext(progress, "Cleaning up...")
    
    -- 删除临时文件
    local removeOk = os.remove(tempFilePath)
    if removeOk then
        gma.echo("[SuperData] Temp file deleted: " .. tempFilePath)
    else
        gma.echo("[SuperData] Warning: Could not delete temp file")
    end
    
    gma.gui.progress.set(progress, 100)
    gma.gui.progress.stop(progress)
    
    success = #fixtures
    gma.echo("[SuperData] Import complete: " .. success .. " fixtures")
    
    return success, failed
end

-- ===========================================
-- GUI 模块（简单一次性流程）
-- ===========================================
local GUI = {}

-- 硬编码服务器 IP（修改此处以更换服务器）
local SERVER_IP = "192.168.10.196"

-- 主流程：连接 → 获取 → 导入 → 结束
function GUI.showMainMenu(client)
    -- Step 1: 使用硬编码 IP
    local ip = SERVER_IP
    
    -- Step 2: 连接
    local progress = gma.gui.progress.start("Connecting to " .. ip .. "...")
    gma.gui.progress.setrange(progress, 0, 100)
    gma.gui.progress.set(progress, 30)
    
    local ok, err = client:connect(ip)
    
    if not ok then
        gma.gui.progress.stop(progress)
        gma.gui.msgbox("Error", "Connection failed:\n" .. (err or "unknown"))
        return
    end
    
    -- Step 3: 请求灯具（连接成功后立即请求，不弹窗）
    gma.gui.progress.settext(progress, "Requesting fixtures...")
    gma.gui.progress.set(progress, 50)
    
    gma.sleep(0.2)  -- 等待连接稳定
    client:requestFixtureList()
    
    -- Step 4: 等待接收
    gma.gui.progress.settext(progress, "Receiving fixtures...")
    
    for i = 1, 100 do
        gma.sleep(0.1)
        client:processPackets()
        gma.gui.progress.set(progress, 50 + i/2)
        if #client.fixtures > 0 then 
            gma.echo("[SuperData] Got " .. #client.fixtures .. " fixtures!")
            break 
        end
    end
    
    gma.gui.progress.stop(progress)
    
    local fixtures = client:getFixtures()
    if #fixtures == 0 then
        gma.gui.msgbox("Error", "No fixtures received!\n\nCheck System Monitor for details.")
        client:disconnect()
        return
    end
    
    -- Step 3: 显示并确认导入
    local msg = "Received " .. #fixtures .. " fixtures:\n\n"
    for i = 1, math.min(8, #fixtures) do
        local f = fixtures[i]
        msg = msg .. f.name .. " (U" .. f.universe .. "." .. f.startAddress .. ")\n"
    end
    if #fixtures > 8 then
        msg = msg .. "... and " .. (#fixtures - 8) .. " more\n"
    end
    msg = msg .. "\nPatch to MA2?"
    
    if not gma.gui.confirm("Import?", msg) then
        client:disconnect()
        return
    end
    
    -- Step 4: 检查 FixtureID 是否有重复
    local duplicates = MA2Import.checkDuplicateIDs(fixtures)
    if #duplicates > 0 then
        local dupStr = table.concat(duplicates, ", ")
        gma.gui.msgbox("ERROR: Duplicate FixtureID!", 
            "Found duplicate FixtureID(s): " .. dupStr .. "\n\n" ..
            "Please fix in Unity first!\n" ..
            "Each fixture must have a unique ID.")
        gma.echo("[SuperData] ERROR: Duplicate FixtureIDs: " .. dupStr)
        client:disconnect()
        return
    end
    
    -- 使用固定的灯具类型 ID = 3
    -- 导入成功后用户需自行替换灯具类型
    gma.echo("[SuperData] Using FixtureType ID: " .. MA2Import.fixtureTypeId)
    
    -- Step 5: 执行导入
    local success, failed = MA2Import.importFixtures(fixtures)
    
    -- Step 6: 显示结果
    if success > 0 then
        gma.gui.msgbox("Import Complete!", 
            "Added: " .. success .. " fixtures\n" ..
            "Failed: " .. failed .. "\n\n" ..
            "IMPORTANT: Please replace fixture types\n" ..
            "in Setup > Patch > Fixture Types now!")
    else
        gma.gui.msgbox("Import Failed", "No fixtures were imported.\nFailed: " .. failed)
    end
    
    -- 断开连接
    client:disconnect()
    gma.echo("[SuperData] Complete!")
end

-- ===========================================
-- 主程序
-- ===========================================
local client = nil
local running = false
local updateTimer = nil

-- 更新回调
function UpdateCallback(timer, count)
    if client and running then
        client:update()
    end
end

-- 启动函数
function Start()
    gma.echo("=========================================")
    gma.echo("   SuperData Protocol Client v1.0.0")
    gma.echo("   for GrandMA2")
    gma.echo("=========================================")
    
    -- 创建客户端实例
    client = setmetatable({}, {__index = SuperDataClient})
    
    -- 显示欢迎界面
    local welcome = [[
SuperData Protocol Client v1.0.0
─────────────────────────────

Cross-platform fixture data sync
for Unity / Unreal / Vectorworks

Developed by Yunsio SuperStage

─────────────────────────────
Press OK to continue...]]
    
    if not gma.gui.confirm("SuperData", welcome) then
        return
    end
    
    -- 初始化
    local progress = gma.gui.progress.start("Initializing...")
    gma.gui.progress.setrange(progress, 0, 100)
    gma.gui.progress.set(progress, 30)
    
    if not client:init() then
        gma.gui.progress.stop(progress)
        gma.gui.msgbox("Error", "Failed to initialize SuperData client\n\nCheck System Monitor for details")
        return
    end
    
    gma.gui.progress.set(progress, 70)
    
    running = true
    
    -- 启动更新定时器
    gma.timer(UpdateCallback, 0.1, 0, Cleanup)
    
    gma.gui.progress.set(progress, 100)
    gma.gui.progress.stop(progress)
    
    -- 显示主菜单
    GUI.showMainMenu(client)
end

-- 清理函数
function Cleanup()
    gma.echo("[SuperData] Cleanup called")
    running = false
    
    if client then
        client:disconnect()
        client = nil
    end
end

-- ===========================================
-- 返回入口函数
-- ===========================================
return Start, Cleanup

