-- ╔═══════════════════════════════════════════════════════════════════════════╗
-- ║                   SuperData Protocol Client for GrandMA2                  ║
-- ║                                                                           ║
-- ║  Version:    2.0.0 (Production Release)                                   ║
-- ║  Protocol:   SuperData v2.0                                               ║
-- ║  Author:     Yunsio SuperStage Team                                       ║
-- ║  Website:    https://yunsio.com/superdata                                 ║
-- ║  License:    CC BY-NC 4.0                                                 ║
-- ║                                                                           ║
-- ║  Description:                                                             ║
-- ║    Cross-platform fixture data synchronization plugin for GrandMA2.       ║
-- ║    Supports importing fixtures from Unity, Unreal Engine, Vectorworks.    ║
-- ║                                                                           ║
-- ╚═══════════════════════════════════════════════════════════════════════════╝

local internal_name = select(1, ...)
local visible_name = select(2, ...)

-- ═══════════════════════════════════════════════════════════════════════════
-- 版本信息
-- ═══════════════════════════════════════════════════════════════════════════
local VERSION = {
    MAJOR = 2,
    MINOR = 0,
    PATCH = 0,
    STRING = "2.0.0",
    DATE = "2025-12-01"
}

-- ═══════════════════════════════════════════════════════════════════════════
-- 协议常量定义 (SuperData Protocol v2.0)
-- ═══════════════════════════════════════════════════════════════════════════
local SUPERDATA = {
    -- 协议标识
    MAGIC = "SPDT",
    VERSION = 2,
    VERSION_STRING = "2.0",
    HEADER_SIZE = 24,
    MAX_PACKET_SIZE = 65536,
    
    -- 网络配置
    DATA_PORT = 5966,
    LISTEN_ADDRESS = "127.0.0.1",
    
    -- 时间配置 (秒)
    HEARTBEAT_INTERVAL = 3.0,
    CONNECT_TIMEOUT = 5.0,
    RECEIVE_TIMEOUT = 10.0,
    SERVER_START_TIMEOUT = 5.0,
    
    -- 平台代码
    PLATFORM = {
        UNKNOWN = 0,
        UNITY = 1,
        UNREAL = 2,
        VECTORWORKS = 3,
        GRANDMA = 4,
        CUSTOM = 255
    },
    
    -- 平台显示名称
    PLATFORM_NAMES = {
        [0] = "Unknown",
        [1] = "Unity",
        [2] = "Unreal Engine",
        [3] = "Vectorworks",
        [4] = "GrandMA",
        [255] = "Custom"
    },
    
    -- 数据包类型
    PKT = {
        CONNECT         = 0x0010,
        CONNECT_ACK     = 0x0011,
        DISCONNECT      = 0x0012,
        HEARTBEAT       = 0x0013,
        CLIENT_JOINED   = 0x0014,
        CLIENT_LEFT     = 0x0015,
        FIXTURE_LIST_REQ  = 0x0020,
        FIXTURE_LIST_RESP = 0x0021,
        FIXTURE_UPDATE    = 0x0022,
        FIXTURE_FULL_SYNC = 0x0023,
        FIXTURE_DELETE    = 0x0024,
        ERROR           = 0xFF00
    }
}

-- 获取平台显示名称
function SUPERDATA.getPlatformName(platform)
    return SUPERDATA.PLATFORM_NAMES[platform] or "Unknown"
end

-- ═══════════════════════════════════════════════════════════════════════════
-- 日志模块
-- ═══════════════════════════════════════════════════════════════════════════
local Log = {
    PREFIX = "[SuperData]",
    DEBUG_MODE = false  -- 生产环境关闭调试日志
}

function Log.info(msg)
    gma.echo(Log.PREFIX .. " " .. msg)
end

function Log.error(msg)
    gma.echo(Log.PREFIX .. " ERROR: " .. msg)
end

function Log.debug(msg)
    if Log.DEBUG_MODE then
        gma.echo(Log.PREFIX .. " [DEBUG] " .. msg)
    end
end

-- ═══════════════════════════════════════════════════════════════════════════
-- JSON 模块 (轻量级实现)
-- ═══════════════════════════════════════════════════════════════════════════
local JSON = {}

function JSON.encode(val)
    local t = type(val)
    if t == "nil" then
        return "null"
    elseif t == "boolean" then
        return val and "true" or "false"
    elseif t == "number" then
        if val ~= val then return "null" end
        if val >= math.huge then return "1e999" end
        if val <= -math.huge then return "-1e999" end
        return tostring(val)
    elseif t == "string" then
        local s = val:gsub('[\\"\x00-\x1f]', function(c)
            local codes = {['\\']='\\\\', ['"']='\\"', ['\n']='\\n', ['\r']='\\r', ['\t']='\\t'}
            return codes[c] or string.format('\\u%04x', c:byte())
        end)
        return '"' .. s .. '"'
    elseif t == "table" then
        local isArray = #val > 0 or next(val) == nil
        if isArray then
            for k in pairs(val) do
                if type(k) ~= "number" then isArray = false; break end
            end
        end
        local parts = {}
        if isArray then
            for i, v in ipairs(val) do parts[i] = JSON.encode(v) end
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
    local function char() return str:sub(pos, pos) end
    local function skip_ws()
        while char():match("[ \t\n\r]") do pos = pos + 1 end
    end
    
    local parse_value, parse_string, parse_number, parse_array, parse_object
    
    parse_string = function()
        pos = pos + 1
        local result = ""
        while pos <= #str do
            local c = char()
            if c == '"' then pos = pos + 1; return result
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
                    local code = tonumber(hex, 16)
                    if code and code < 128 then result = result .. string.char(code)
                    else result = result .. '?' end
                    pos = pos + 4
                end
            else result = result .. c end
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
        pos = pos + 1
        skip_ws()
        if char() == ']' then pos = pos + 1; return arr end
        while true do
            skip_ws()
            arr[#arr + 1] = parse_value()
            skip_ws()
            if char() == ']' then pos = pos + 1; return arr
            elseif char() == ',' then pos = pos + 1
            else break end
        end
        return arr
    end
    
    parse_object = function()
        local obj = {}
        pos = pos + 1
        skip_ws()
        if char() == '}' then pos = pos + 1; return obj end
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
            if char() == '}' then pos = pos + 1; return obj
            elseif char() == ',' then pos = pos + 1
            else break end
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
    
    local ok, result = pcall(parse_value)
    return ok and result or nil
end

-- ═══════════════════════════════════════════════════════════════════════════
-- 二进制数据处理模块
-- ═══════════════════════════════════════════════════════════════════════════
local Binary = {}

function Binary.writeUInt16LE(value)
    return string.char(value % 256, math.floor(value / 256) % 256)
end

function Binary.writeUInt32LE(value)
    return string.char(
        value % 256,
        math.floor(value / 256) % 256,
        math.floor(value / 65536) % 256,
        math.floor(value / 16777216) % 256
    )
end

function Binary.writeInt64LE(value)
    local low = value % 4294967296
    local high = math.floor(value / 4294967296)
    return Binary.writeUInt32LE(low) .. Binary.writeUInt32LE(high)
end

function Binary.readUInt16LE(data, offset)
    offset = offset or 1
    local b1, b2 = data:byte(offset, offset + 1)
    return b1 + b2 * 256
end

function Binary.readUInt32LE(data, offset)
    offset = offset or 1
    local b1, b2, b3, b4 = data:byte(offset, offset + 3)
    return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
end

-- ═══════════════════════════════════════════════════════════════════════════
-- 服务器启动模块
-- ═══════════════════════════════════════════════════════════════════════════
local ServerLauncher = {}

ServerLauncher.REGISTRY_KEY = [[HKLM\SOFTWARE\Yunsio\SuperData]]
ServerLauncher.DEFAULT_PATHS = {
    [[C:\Program Files\Yunsio\SuperData\SuperDataServer.exe]],
    [[C:\Program Files (x86)\Yunsio\SuperData\SuperDataServer.exe]],
}

function ServerLauncher.fileExists(path)
    local f = io.open(path, "r")
    if f then f:close(); return true end
    return false
end

function ServerLauncher.getServerPathFromRegistry()
    local handle = io.popen('reg query "' .. ServerLauncher.REGISTRY_KEY .. '" /v ExePath 2>nul')
    if not handle then return nil end
    local result = handle:read("*a")
    handle:close()
    local path = result:match("ExePath%s+REG_SZ%s+(.-)%s*[\r\n]")
    if path and ServerLauncher.fileExists(path) then return path end
    return nil
end

function ServerLauncher.getServerPath()
    local regPath = ServerLauncher.getServerPathFromRegistry()
    if regPath then return regPath end
    local envPath = os.getenv("SUPERDATA_SERVER_PATH")
    if envPath and ServerLauncher.fileExists(envPath) then return envPath end
    for _, path in ipairs(ServerLauncher.DEFAULT_PATHS) do
        if ServerLauncher.fileExists(path) then return path end
    end
    return nil
end

function ServerLauncher.startServer(serverPath)
    local cmd = 'start /B "" "' .. serverPath .. '"'
    local result = os.execute(cmd)
    return result == 0 or result == true
end

-- ═══════════════════════════════════════════════════════════════════════════
-- UUID 生成
-- ═══════════════════════════════════════════════════════════════════════════
local function generateUuid()
    local template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    return string.gsub(template, "[xy]", function(c)
        local v = (c == "x") and math.random(0, 0xf) or math.random(8, 0xb)
        return string.format("%x", v)
    end)
end

-- ═══════════════════════════════════════════════════════════════════════════
-- SuperData 客户端类
-- ═══════════════════════════════════════════════════════════════════════════
local SuperDataClient = {}
SuperDataClient.__index = SuperDataClient

function SuperDataClient.new()
    local self = setmetatable({}, SuperDataClient)
    self.connected = false
    self.sequenceNumber = 0
    self.tcpSocket = nil
    self.socket = nil
    self.receiveBuffer = ""
    self.clientInfo = nil
    self.otherClients = {}
    self.fixtures = {}
    self.lastHeartbeat = 0
    return self
end

function SuperDataClient:init()
    math.randomseed(os.time())
    self.clientInfo = {
        clientId = generateUuid(),
        clientName = "GrandMA2",
        platform = SUPERDATA.PLATFORM.GRANDMA,
        platformVersion = gma.git_version() or "3.3.4",
        protocolVersion = SUPERDATA.VERSION_STRING
    }
    self.otherClients = {}
    self.fixtures = {}
    self.receiveBuffer = ""
    Log.info("Client initialized (ID: " .. self.clientInfo.clientId:sub(1, 8) .. "...)")
    return true
end

function SuperDataClient:getTimestamp()
    return math.floor(gma.gettime() * 1000)
end

function SuperDataClient:buildPacket(packetType, payload)
    self.sequenceNumber = self.sequenceNumber + 1
    local payloadStr = payload and JSON.encode(payload) or "{}"
    local header = SUPERDATA.MAGIC
        .. Binary.writeUInt16LE(SUPERDATA.VERSION)
        .. Binary.writeUInt16LE(packetType)
        .. Binary.writeUInt32LE(self.sequenceNumber)
        .. Binary.writeInt64LE(self:getTimestamp())
        .. Binary.writeUInt32LE(#payloadStr)
    return header .. payloadStr
end

function SuperDataClient:parseHeader(data)
    if #data < SUPERDATA.HEADER_SIZE then return nil end
    if data:sub(1, 4) ~= SUPERDATA.MAGIC then return nil end
    return {
        version = Binary.readUInt16LE(data, 5),
        packetType = Binary.readUInt16LE(data, 7),
        sequenceNumber = Binary.readUInt32LE(data, 9),
        payloadLength = Binary.readUInt32LE(data, 21)
    }
end

function SuperDataClient:tryParsePacket()
    if #self.receiveBuffer < SUPERDATA.HEADER_SIZE then return nil, 0 end
    local header = self:parseHeader(self.receiveBuffer)
    if not header then return nil, 0 end
    local totalLength = SUPERDATA.HEADER_SIZE + header.payloadLength
    if #self.receiveBuffer < totalLength then return nil, 0 end
    
    local packet = { header = header, payload = {} }
    if header.payloadLength > 0 then
        local payloadStr = self.receiveBuffer:sub(SUPERDATA.HEADER_SIZE + 1, totalLength)
        packet.payload = JSON.decode(payloadStr) or {}
    end
    return packet, totalLength
end

function SuperDataClient:loadSocket()
    local paths = {"./plugins/requirements/?.lua", "./plugins/?.lua", "./?.lua"}
    for _, path in ipairs(paths) do
        package.path = package.path .. ";" .. path
    end
    
    local loadMethods = {"socket.socket", "socket.core", "socket"}
    for _, method in ipairs(loadMethods) do
        local ok, socket = pcall(require, method)
        if ok and socket then
            self.socket = socket
            Log.debug("Socket loaded via '" .. method .. "'")
            return true
        end
    end
    Log.error("Socket library not found")
    return false
end

function SuperDataClient:isServerRunning()
    if not self.socket then return false end
    local tcp = self.socket.tcp()
    tcp:settimeout(0.1)
    local result = tcp:connect(SUPERDATA.LISTEN_ADDRESS, SUPERDATA.DATA_PORT)
    tcp:close()
    return result ~= nil
end

function SuperDataClient:ensureServerRunning()
    if self:isServerRunning() then
        Log.info("Server is running")
        return true
    end
    
    local serverPath = ServerLauncher.getServerPath()
    if not serverPath then
        Log.error("SuperData Server not installed")
        return false
    end
    
    Log.info("Starting server...")
    if not ServerLauncher.startServer(serverPath) then
        Log.error("Failed to start server")
        return false
    end
    
    local startTime = gma.gettime()
    while gma.gettime() - startTime < SUPERDATA.SERVER_START_TIMEOUT do
        gma.sleep(0.1)
        if self:isServerRunning() then
            Log.info("Server started successfully")
            return true
        end
    end
    
    Log.error("Server start timeout")
    return false
end

function SuperDataClient:connect(autoStartServer)
    if autoStartServer == nil then autoStartServer = true end
    
    if not self.socket and not self:loadSocket() then
        return false, "Socket library not available.\nPlease check LuaSocket installation."
    end
    
    if autoStartServer and not self:ensureServerRunning() then
        return false, "SuperData Server not available.\n\nPlease install from:\nhttps://yunsio.com/superdata"
    end
    
    Log.info("Connecting to server...")
    
    local tcp, err = self.socket.tcp()
    if not tcp then
        return false, "Failed to create socket: " .. (err or "unknown")
    end
    
    tcp:settimeout(SUPERDATA.CONNECT_TIMEOUT)
    local ok, err = tcp:connect(SUPERDATA.LISTEN_ADDRESS, SUPERDATA.DATA_PORT)
    if not ok then
        tcp:close()
        return false, "Connection failed: " .. (err or "unknown")
    end
    
    tcp:setoption("tcp-nodelay", true)
    tcp:settimeout(0)
    
    self.tcpSocket = tcp
    self.receiveBuffer = ""
    
    local connectPayload = {
        clientId = self.clientInfo.clientId,
        clientName = self.clientInfo.clientName,
        platform = self.clientInfo.platform,
        platformVersion = self.clientInfo.platformVersion,
        protocolVersion = self.clientInfo.protocolVersion
    }
    
    local packet = self:buildPacket(SUPERDATA.PKT.CONNECT, connectPayload)
    local sent, err = tcp:send(packet)
    if not sent then
        tcp:close()
        self.tcpSocket = nil
        return false, "Failed to send connect request"
    end
    
    tcp:settimeout(SUPERDATA.CONNECT_TIMEOUT)
    local startTime = gma.gettime()
    while gma.gettime() - startTime < SUPERDATA.CONNECT_TIMEOUT do
        self:receiveData()
        self:processReceivedData()
        if self.connected then
            tcp:settimeout(0)
            return true
        end
        gma.sleep(0.05)
    end
    
    tcp:close()
    self.tcpSocket = nil
    return false, "Connection timeout - server not responding"
end

function SuperDataClient:receiveData()
    if not self.tcpSocket then return end
    while true do
        local data, err, partial = self.tcpSocket:receive(4096)
        if data then
            self.receiveBuffer = self.receiveBuffer .. data
        elseif partial and #partial > 0 then
            self.receiveBuffer = self.receiveBuffer .. partial
        end
        if err == "closed" then
            Log.info("Server closed connection")
            self:disconnect()
            return
        elseif err == "timeout" or not data then
            break
        end
    end
end

function SuperDataClient:processReceivedData()
    while #self.receiveBuffer >= SUPERDATA.HEADER_SIZE do
        local packet, consumed = self:tryParsePacket()
        if not packet or consumed == 0 then break end
        self.receiveBuffer = self.receiveBuffer:sub(consumed + 1)
        self:handlePacket(packet)
    end
end

function SuperDataClient:handlePacket(packet)
    local pktType = packet.header.packetType
    local payload = packet.payload or {}
    
    if pktType == SUPERDATA.PKT.CONNECT_ACK then
        self:handleConnectAck(payload)
    elseif pktType == SUPERDATA.PKT.HEARTBEAT then
        -- OK
    elseif pktType == SUPERDATA.PKT.CLIENT_JOINED then
        self:handleClientJoined(payload)
    elseif pktType == SUPERDATA.PKT.CLIENT_LEFT then
        self:handleClientLeft(payload)
    elseif pktType == SUPERDATA.PKT.FIXTURE_LIST_RESP then
        self:handleFixtureListResponse(payload)
    elseif pktType == SUPERDATA.PKT.ERROR then
        local msg = payload.errorMessage or payload.message or "Unknown error"
        Log.error("Server: " .. msg)
    end
end

function SuperDataClient:handleConnectAck(payload)
    if not (payload.accepted or payload.success) then
        Log.error("Connection rejected: " .. (payload.errorMessage or "unknown"))
        return
    end
    
    self.otherClients = {}
    if payload.clients then
        for _, c in ipairs(payload.clients) do
            if c.clientId and c.clientId ~= self.clientInfo.clientId then
                self.otherClients[c.clientId] = {
                    clientId = c.clientId,
                    clientName = c.clientName or "Unknown",
                    platform = c.platform or 0,
                    fixtureCount = c.fixtureCount or 0
                }
            end
        end
    end
    
    self.connected = true
    self.lastHeartbeat = gma.gettime()
    
    local count = 0
    for _ in pairs(self.otherClients) do count = count + 1 end
    Log.info("Connected! Found " .. count .. " data source(s)")
end

function SuperDataClient:handleClientJoined(payload)
    local info = payload.client or payload
    if info and info.clientId and info.clientId ~= self.clientInfo.clientId then
        self.otherClients[info.clientId] = {
            clientId = info.clientId,
            clientName = info.clientName or "Unknown",
            platform = info.platform or 0,
            fixtureCount = info.fixtureCount or 0
        }
        Log.info("New client joined: " .. (info.clientName or "Unknown"))
    end
end

function SuperDataClient:handleClientLeft(payload)
    local clientId = payload.clientId or ""
    local info = self.otherClients[clientId]
    if info then
        Log.info("Client disconnected: " .. info.clientName)
        self.otherClients[clientId] = nil
    end
end

function SuperDataClient:handleFixtureListResponse(payload)
    self.fixtures = payload.fixtures or {}
    Log.info("Received " .. #self.fixtures .. " fixtures")
end

function SuperDataClient:sendPacket(packetType, payload)
    if not self.tcpSocket then return false end
    local packet = self:buildPacket(packetType, payload)
    local sent = self.tcpSocket:send(packet)
    return sent ~= nil
end

function SuperDataClient:sendHeartbeat()
    if not self.connected then return end
    local now = gma.gettime()
    if now - self.lastHeartbeat >= SUPERDATA.HEARTBEAT_INTERVAL then
        self:sendPacket(SUPERDATA.PKT.HEARTBEAT, {})
        self.lastHeartbeat = now
    end
end

function SuperDataClient:requestFixtureList(sourceClientId)
    if not self.connected then return false end
    Log.info("Requesting fixtures...")
    return self:sendPacket(SUPERDATA.PKT.FIXTURE_LIST_REQ, {
        clientId = self.clientInfo.clientId,
        sourceClientId = sourceClientId
    })
end

function SuperDataClient:getOtherClients()
    return self.otherClients
end

function SuperDataClient:getFixtures()
    return self.fixtures
end

function SuperDataClient:update()
    if self.connected then
        self:sendHeartbeat()
        self:receiveData()
        self:processReceivedData()
    end
end

function SuperDataClient:disconnect()
    if self.tcpSocket then
        if self.connected then
            pcall(function()
                self:sendPacket(SUPERDATA.PKT.DISCONNECT, {clientId = self.clientInfo.clientId})
            end)
        end
        pcall(function() self.tcpSocket:close() end)
        self.tcpSocket = nil
    end
    local wasConnected = self.connected
    self.connected = false
    self.otherClients = {}
    self.fixtures = {}
    self.receiveBuffer = ""
    if wasConnected then Log.info("Disconnected") end
end

-- ═══════════════════════════════════════════════════════════════════════════
-- MA2 灯具导入模块
-- ═══════════════════════════════════════════════════════════════════════════
local MA2Import = {}

MA2Import.fixtureTypeId = 3
MA2Import.fixtureTypeName = "Generic"

function MA2Import.checkDuplicateIDs(fixtures)
    local idMap = {}
    local duplicates = {}
    for i, f in ipairs(fixtures) do
        local id = f.fixtureID or f.fixtureId or i
        if idMap[id] then table.insert(duplicates, id)
        else idMap[id] = true end
    end
    return duplicates
end

function MA2Import.buildFixtureRange(ids)
    if #ids == 0 then return "" end
    if #ids == 1 then return tostring(ids[1]) end
    
    local ranges = {}
    local rangeStart = ids[1]
    local rangeEnd = ids[1]
    
    for i = 2, #ids do
        if ids[i] == rangeEnd + 1 then
            rangeEnd = ids[i]
        else
            if rangeStart == rangeEnd then
                table.insert(ranges, tostring(rangeStart))
            else
                table.insert(ranges, rangeStart .. " Thru " .. rangeEnd)
            end
            rangeStart = ids[i]
            rangeEnd = ids[i]
        end
    end
    
    if rangeStart == rangeEnd then
        table.insert(ranges, tostring(rangeStart))
    else
        table.insert(ranges, rangeStart .. " Thru " .. rangeEnd)
    end
    
    return table.concat(ranges, " + ")
end

function MA2Import.generateLayersXML(fixtures, fixtureTypeName, fixtureTypeNo)
    -- 按灯具类型分组
    local fixturesByType = {}
    local typeOrder = {}  -- 保持类型顺序
    
    for i, f in ipairs(fixtures) do
        -- 获取灯具类型，支持多种字段名
        local fType = f.fixtureType or f.type or f.fixtureTypeName or "Generic"
        fType = tostring(fType):gsub('[<>&"]', '')  -- 清理XML非法字符
        
        if not fixturesByType[fType] then
            fixturesByType[fType] = {}
            table.insert(typeOrder, fType)
        end
        table.insert(fixturesByType[fType], f)
    end
    
    -- 生成多个Layer的XML
    local layerXMLs = {}
    
    for _, fType in ipairs(typeOrder) do
        local fixturesInType = fixturesByType[fType]
        local fixtureXMLs = {}
        
        for i, f in ipairs(fixturesInType) do
            local fixtureId = f.fixtureID or f.fixtureId or i
            local universe = math.max(1, f.universe or 1)
            local address = math.max(1, f.startAddress or 1)
            local name = (f.name or ("Fixture_" .. fixtureId)):gsub('[<>&"]', '')
            local absoluteAddress = ((universe - 1) * 512) + address
            
            -- 位置转换: cm → m
            local posX, posY, posZ = 0, 0, 0
            if f.position and type(f.position) == "table" then
                if f.position[1] then
                    posX, posY, posZ = (f.position[1] or 0) / 100, (f.position[2] or 0) / 100, (f.position[3] or 0) / 100
                else
                    posX, posY, posZ = (f.position.x or 0) / 100, (f.position.y or 0) / 100, (f.position.z or 0) / 100
                end
            end
            
            -- 旋转转换
            local rotX, rotY, rotZ = 0, 0, 0
            if f.rotation and type(f.rotation) == "table" then
                if f.rotation[1] then
                    rotX, rotY, rotZ = f.rotation[1] or 0, f.rotation[2] or 0, f.rotation[3] or 0
                else
                    rotX, rotY, rotZ = f.rotation.x or 0, f.rotation.y or 0, f.rotation.z or 0
                end
            end
            rotY = rotY + 180
            rotZ = rotZ + 90
            
            local fixtureXML = string.format([[
			<Fixture name="%s" fixture_id="%d" channel_id="">
				<FixtureType name="%s"><No>%d</No></FixtureType>
				<SubFixture index="0" react_to_grandmaster="true" color="FFFFFF">
					<Patch><Address>%d</Address></Patch>
					<AbsolutePosition>
						<Location x="%.3f" y="%.3f" z="%.3f"/>
						<Rotation x="%.2f" y="%.2f" z="%.2f"/>
						<Scaling x="1.000" y="1.000" z="1.000"/>
					</AbsolutePosition>
				</SubFixture>
			</Fixture>]], 
                name, fixtureId, fixtureTypeName, fixtureTypeNo,
                absoluteAddress, posX, posY, posZ, rotX, rotY, rotZ)
            
            table.insert(fixtureXMLs, fixtureXML)
        end
        
        -- 为每个类型生成一个Layer
        local layerXML = string.format([[
		<Layer name="%s">
%s
		</Layer>]], fType, table.concat(fixtureXMLs, "\n"))
        
        table.insert(layerXMLs, layerXML)
    end
    
    -- 生成完整的MA XML文档
    return string.format([[<MA xmlns="http://schemas.malighting.de/grandma2/xml/MA">
	<InfoItems>
		<Info type="Invisible" date="%s">SuperData v%s Import (%d types)</Info>
	</InfoItems>
	<Layers>
%s
	</Layers>
</MA>]], os.date("%y/%m/%d"), VERSION.STRING, #typeOrder, table.concat(layerXMLs, "\n"))
end

function MA2Import.importFixtures(fixtures, progressCallback)
    if #fixtures == 0 then
        Log.info("No fixtures to import")
        return 0, 0
    end
    
    if progressCallback then progressCallback("Analyzing fixture types...", 10) end
    
    -- 统计灯具类型分布
    local typeStats = {}
    for _, f in ipairs(fixtures) do
        local fType = f.fixtureType or f.type or f.fixtureTypeName or "Generic"
        fType = tostring(fType):gsub('[<>&"]', '')
        typeStats[fType] = (typeStats[fType] or 0) + 1
    end
    
    -- 输出分类信息
    local typeCount = 0
    for _ in pairs(typeStats) do typeCount = typeCount + 1 end
    Log.info("Fixture classification: " .. typeCount .. " types detected")
    for fType, count in pairs(typeStats) do
        Log.info("  - " .. fType .. ": " .. count .. " fixtures")
    end
    
    local xml = MA2Import.generateLayersXML(fixtures, MA2Import.fixtureTypeName, MA2Import.fixtureTypeId)
    
    if progressCallback then progressCallback("Writing file...", 30) end
    gma.cmd('SelectDrive 1')
    local showPath = gma.show.getvar("PATH")
    local tempFileName = "superdata_import"
    local tempFilePath = showPath .. "/importexport/" .. tempFileName .. ".xml"
    
    local file = io.open(tempFilePath, "w")
    if not file then
        Log.error("Cannot create temp file")
        return 0, #fixtures
    end
    file:write(xml)
    file:close()
    
    if progressCallback then progressCallback("Importing to MA2...", 50) end
    gma.cmd('CD EditSetup')
    gma.sleep(0.2)
    
    gma.cmd('Import "' .. tempFileName .. '" At Layers /nc')
    gma.sleep(0.5)
    
    gma.cmd('CD /')
    gma.sleep(0.2)
    
    -- 为每个灯具类型创建灯组
    if progressCallback then progressCallback("Creating groups...", 70) end
    
    -- 收集每个类型的灯具ID
    local fixtureIdsByType = {}
    for _, f in ipairs(fixtures) do
        local fType = f.fixtureType or f.type or f.fixtureTypeName or "Generic"
        fType = tostring(fType):gsub('[<>&"]', '')
        local fixtureId = f.fixtureID or f.fixtureId
        
        if fixtureId then
            if not fixtureIdsByType[fType] then
                fixtureIdsByType[fType] = {}
            end
            table.insert(fixtureIdsByType[fType], fixtureId)
        end
    end
    
    -- 为每个类型创建灯组
    local groupCount = 0
    for fType, ids in pairs(fixtureIdsByType) do
        if #ids > 0 then
            -- 排序ID列表
            table.sort(ids)
            
            -- 构建灯具选择范围
            local fixtureRange = MA2Import.buildFixtureRange(ids)
            
            -- 创建灯组命令
            local groupName = "GRP_" .. fType
            local cmd = string.format('Store Group "%s"', groupName)
            
            -- 先选择灯具
            gma.cmd('ClearAll')
            gma.sleep(0.05)
            gma.cmd('Fixture ' .. fixtureRange)
            gma.sleep(0.1)
            
            -- 存储灯组
            gma.cmd(cmd)
            gma.sleep(0.1)
            
            groupCount = groupCount + 1
            Log.info("Created group: " .. groupName .. " (" .. #ids .. " fixtures)")
        end
    end
    
    gma.cmd('ClearAll')
    
    if progressCallback then progressCallback("Cleaning up...", 90) end
    os.remove(tempFilePath)
    
    Log.info("Import complete: " .. #fixtures .. " fixtures, " .. groupCount .. " groups")
    return #fixtures, 0
end

-- ═══════════════════════════════════════════════════════════════════════════
-- GUI 模块
-- ═══════════════════════════════════════════════════════════════════════════
local GUI = {}

function GUI.showProgress(title, initialText)
    local progress = gma.gui.progress.start(title)
    gma.gui.progress.setrange(progress, 0, 100)
    gma.gui.progress.settext(progress, initialText or "")
    return progress
end

function GUI.updateProgress(progress, text, percent)
    if progress then
        gma.gui.progress.settext(progress, text)
        gma.gui.progress.set(progress, percent)
    end
end

function GUI.stopProgress(progress)
    if progress then gma.gui.progress.stop(progress) end
end

function GUI.showMainMenu(client)
    -- Step 1: 连接服务器
    local progress = GUI.showProgress("SuperData", "Connecting to server...")
    GUI.updateProgress(progress, "Connecting...", 20)
    
    local ok, err = client:connect(true)
    
    if not ok then
        GUI.stopProgress(progress)
        gma.gui.msgbox("Connection Failed", err or "Unknown error")
        return
    end
    
    GUI.updateProgress(progress, "Checking clients...", 60)
    gma.sleep(0.3)
    client:update()
    gma.sleep(0.2)
    client:update()
    
    GUI.stopProgress(progress)
    
    -- Step 2: 获取客户端列表
    local otherClients = client:getOtherClients()
    local clientCount = 0
    local clientList = {}
    
    for id, info in pairs(otherClients) do
        clientCount = clientCount + 1
        table.insert(clientList, {
            id = id,
            name = info.clientName,
            platform = info.platform,
            fixtureCount = info.fixtureCount
        })
    end
    
    if clientCount == 0 then
        gma.gui.msgbox("No Data Sources", 
            "No clients connected to SuperData Server.\n\n" ..
            "Please start Unity / Unreal / Vectorworks\n" ..
            "with SuperData plugin first.")
        client:disconnect()
        return
    end
    
    -- Step 3: 显示可用数据源
    local listMsg = "Available data sources:\n" ..
                    string.rep("-", 32) .. "\n\n"
    
    for i, c in ipairs(clientList) do
        local platformName = SUPERDATA.getPlatformName(c.platform)
        listMsg = listMsg .. string.format(
            "[%d]  %s\n" ..
            "     Platform: %s\n" ..
            "     Fixtures: %d\n\n",
            i, c.name, platformName, c.fixtureCount or 0)
    end
    
    gma.gui.msgbox("SuperData - Select Source", listMsg)
    
    -- Step 4: 输入选择
    local choice = gma.textinput("Import from", "Enter number (1-" .. clientCount .. "):")
    
    if not choice or choice == "" then
        client:disconnect()
        return
    end
    
    local selectedIdx = tonumber(choice)
    if not selectedIdx or selectedIdx < 1 or selectedIdx > clientCount then
        gma.gui.msgbox("Invalid Selection", 
            "'" .. tostring(choice) .. "' is not valid.\n" ..
            "Please enter a number from 1 to " .. clientCount)
        client:disconnect()
        return
    end
    
    local selectedClient = clientList[selectedIdx]
    Log.info("Selected: " .. selectedClient.name)
    
    -- Step 5: 请求灯具数据
    progress = GUI.showProgress("SuperData", "Requesting fixtures from " .. selectedClient.name .. "...")
    GUI.updateProgress(progress, "Requesting...", 30)
    
    client:requestFixtureList(selectedClient.id)
    
    GUI.updateProgress(progress, "Receiving data...", 50)
    
    local timeout = 10  -- 10 秒超时
    local startTime = gma.gettime()
    while gma.gettime() - startTime < timeout do
        gma.sleep(0.05)
        client:update()
        local pct = 50 + ((gma.gettime() - startTime) / timeout) * 40
        GUI.updateProgress(progress, "Receiving...", math.min(90, pct))
        if #client.fixtures > 0 then break end
    end
    
    GUI.stopProgress(progress)
    
    local fixtures = client:getFixtures()
    if #fixtures == 0 then
        gma.gui.msgbox("No Data", 
            "No fixtures received from:\n" .. selectedClient.name .. "\n\n" ..
            "Check if the source has fixture data.")
        client:disconnect()
        return
    end
    
    -- Step 6: 确认导入
    local confirmMsg = string.format(
        "Received %d fixtures from:\n%s\n\n",
        #fixtures, selectedClient.name)
    
    local previewCount = math.min(6, #fixtures)
    for i = 1, previewCount do
        local f = fixtures[i]
        local u = f.universe or 1
        local a = f.startAddress or 1
        confirmMsg = confirmMsg .. string.format("  • %s (U%d.%03d)\n", f.name or "Fixture", u, a)
    end
    
    if #fixtures > previewCount then
        confirmMsg = confirmMsg .. string.format("  ... and %d more\n", #fixtures - previewCount)
    end
    
    confirmMsg = confirmMsg .. "\nImport to MA2 now?"
    
    if not gma.gui.confirm("Confirm Import", confirmMsg) then
        client:disconnect()
        return
    end
    
    -- Step 7: 检查重复 ID
    local duplicates = MA2Import.checkDuplicateIDs(fixtures)
    if #duplicates > 0 then
        gma.gui.msgbox("Data Error", 
            "Duplicate FixtureID found: " .. table.concat(duplicates, ", ") .. "\n\n" ..
            "Please fix in " .. selectedClient.name .. " first.")
        client:disconnect()
        return
    end
    
    -- Step 8: 执行导入
    progress = GUI.showProgress("Importing", "Preparing...")
    
    local success, failed = MA2Import.importFixtures(fixtures, function(text, pct)
        GUI.updateProgress(progress, text, pct)
    end)
    
    GUI.updateProgress(progress, "Complete!", 100)
    gma.sleep(0.3)
    GUI.stopProgress(progress)
    
    -- Step 9: 显示结果
    if success > 0 then
        gma.gui.msgbox("Import Complete", 
            string.format("Successfully imported %d fixtures.\n\n", success) ..
            "Note: Fixture types are set to 'Generic'.\n" ..
            "Go to Setup > Patch > Fixture Types\n" ..
            "to replace with correct types if needed.")
    else
        gma.gui.msgbox("Import Failed", 
            "No fixtures were imported.\n" ..
            "Check System Monitor for details.")
    end
    
    client:disconnect()
    Log.info("Session complete")
end

-- ═══════════════════════════════════════════════════════════════════════════
-- 主程序
-- ═══════════════════════════════════════════════════════════════════════════
local client = nil
local running = false

function UpdateCallback(timer, count)
    if client and running then
        pcall(function() client:update() end)
    end
end

function Start()
    Log.info(string.rep("=", 50))
    Log.info("SuperData Client v" .. VERSION.STRING)
    Log.info("Protocol: SuperData v" .. SUPERDATA.VERSION_STRING)
    Log.info(string.rep("=", 50))
    
    -- 欢迎界面
    local welcome = string.format([[
SuperData for GrandMA2
Version %s
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Import fixture data from:
  • Unity
  • Unreal Engine
  • Vectorworks

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
© Yunsio SuperStage Team
]], VERSION.STRING)
    
    if not gma.gui.confirm("SuperData", welcome) then
        return
    end
    
    -- 初始化
    client = SuperDataClient.new()
    
    if not client:init() then
        gma.gui.msgbox("Error", "Failed to initialize client.\nCheck System Monitor for details.")
        return
    end
    
    running = true
    gma.timer(UpdateCallback, 0.1, 0, Cleanup)
    
    -- 主菜单
    GUI.showMainMenu(client)
end

function Cleanup()
    Log.info("Cleanup")
    running = false
    if client then
        pcall(function() client:disconnect() end)
        client = nil
    end
end

-- ═══════════════════════════════════════════════════════════════════════════
-- 返回入口函数
-- ═══════════════════════════════════════════════════════════════════════════
return Start, Cleanup
