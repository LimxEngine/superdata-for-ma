-- *********************************************
-- SuperData Protocol Client for GrandMA2
-- Version: 2.0.0
-- Protocol: SuperData v2.0 (群聊模式)
-- Author: Yunsio SuperStage Team
-- *********************************************

local internal_name = select(1, ...)
local visible_name = select(2, ...)

-- ===========================================
-- 协议常量定义 (v2.0)
-- ===========================================
local SUPERDATA = {
    -- 协议标识
    MAGIC = "SPDT",
    VERSION = 2,
    VERSION_STRING = "2.0",
    HEADER_SIZE = 24,
    
    -- 端口 (v2.0 只有 TCP)
    DATA_PORT = 5966,
    LISTEN_ADDRESS = "127.0.0.1",
    
    -- 时间间隔 (秒)
    HEARTBEAT_INTERVAL = 3.0,
    TIMEOUT = 10.0,
    CONNECT_TIMEOUT = 5.0,
    
    -- 平台代码
    PLATFORM = {
        UNKNOWN = 0,
        UNITY = 1,
        UNREAL = 2,
        VECTORWORKS = 3,
        GRANDMA = 4,
        CUSTOM = 255
    },
    
    -- 数据包类型 (v2.0)
    PKT = {
        -- 连接管理
        CONNECT             = 0x0010,
        CONNECT_ACK         = 0x0011,
        DISCONNECT          = 0x0012,
        HEARTBEAT           = 0x0013,
        -- 客户端管理 (v2.0 新增)
        CLIENT_JOINED       = 0x0014,
        CLIENT_LEFT         = 0x0015,
        -- 数据同步
        FIXTURE_LIST_REQ    = 0x0020,
        FIXTURE_LIST_RESP   = 0x0021,
        FIXTURE_UPDATE      = 0x0022,
        FIXTURE_FULL_SYNC   = 0x0023,  -- v2.0: 替代原 FIXTURE_CREATE
        FIXTURE_DELETE      = 0x0024,
        -- 错误
        ERROR               = 0xFF00
    },
    
    -- 错误代码
    ERROR_CODE = {
        NONE = 0,
        INVALID_PACKET = 1,
        VERSION_MISMATCH = 2,
        CONNECTION_REFUSED = 3,
        TIMEOUT = 4,
        CLIENT_NOT_FOUND = 8,
        INTERNAL_ERROR = 255
    }
}

-- 获取包类型名称
function SUPERDATA.getPacketTypeName(packetType)
    for name, value in pairs(SUPERDATA.PKT) do
        if value == packetType then
            return name
        end
    end
    return string.format("Unknown(0x%04X)", packetType)
end

-- 获取平台名称
function SUPERDATA.getPlatformName(platform)
    for name, value in pairs(SUPERDATA.PLATFORM) do
        if value == platform then
            return name
        end
    end
    return "Unknown"
end

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
                    local code = tonumber(hex, 16)
                    if code and code < 128 then
                        result = result .. string.char(code)
                    else
                        result = result .. '?'
                    end
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
-- 服务器启动模块 (v2.0 新增)
-- ===========================================
local ServerLauncher = {}

-- 注册表路径
ServerLauncher.REGISTRY_KEY = [[HKLM\SOFTWARE\Yunsio\SuperData]]
ServerLauncher.REGISTRY_VALUE = "ExePath"

-- 默认安装路径
ServerLauncher.DEFAULT_PATHS = {
    [[C:\Program Files\Yunsio\SuperData\SuperDataServer.exe]],
    [[C:\Program Files (x86)\Yunsio\SuperData\SuperDataServer.exe]],
}

-- 检查文件是否存在
function ServerLauncher.fileExists(path)
    local f = io.open(path, "r")
    if f then
        f:close()
        return true
    end
    return false
end

-- 从注册表获取服务器路径 (Windows)
function ServerLauncher.getServerPathFromRegistry()
    local handle = io.popen('reg query "' .. ServerLauncher.REGISTRY_KEY .. '" /v ' .. ServerLauncher.REGISTRY_VALUE .. ' 2>nul')
    if not handle then
        return nil
    end
    
    local result = handle:read("*a")
    handle:close()
    
    -- 解析输出: ExePath    REG_SZ    C:\...\SuperDataServer.exe
    local path = result:match("ExePath%s+REG_SZ%s+(.-)%s*[\r\n]")
    if path and ServerLauncher.fileExists(path) then
        return path
    end
    
    return nil
end

-- 获取服务器可执行文件路径
function ServerLauncher.getServerPath()
    -- 1. 注册表
    local regPath = ServerLauncher.getServerPathFromRegistry()
    if regPath then
        return regPath
    end
    
    -- 2. 环境变量
    local envPath = os.getenv("SUPERDATA_SERVER_PATH")
    if envPath and ServerLauncher.fileExists(envPath) then
        return envPath
    end
    
    -- 3. 默认路径
    for _, path in ipairs(ServerLauncher.DEFAULT_PATHS) do
        if ServerLauncher.fileExists(path) then
            return path
        end
    end
    
    return nil
end

-- 启动服务器进程
function ServerLauncher.startServer(serverPath)
    -- Windows: 后台启动
    local cmd = 'start /B "" "' .. serverPath .. '"'
    local result = os.execute(cmd)
    return result == 0 or result == true
end

-- ===========================================
-- UUID 生成
-- ===========================================
local function generateUuid()
    local template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    return string.gsub(template, "[xy]", function(c)
        local v = (c == "x") and math.random(0, 0xf) or math.random(8, 0xb)
        return string.format("%x", v)
    end)
end

-- ===========================================
-- SuperData 客户端类 (v2.0)
-- ===========================================
local SuperDataClient = {
    -- 状态
    connected = false,
    sequenceNumber = 0,
    
    -- Socket
    tcpSocket = nil,
    socket = nil,  -- LuaSocket 库引用
    
    -- 接收缓冲区
    receiveBuffer = "",
    
    -- 客户端信息
    clientInfo = nil,
    
    -- 群聊成员 (v2.0)
    otherClients = {},
    
    -- 灯具数据
    fixtures = {},
    
    -- 计时器
    lastHeartbeat = 0,
    
    -- 回调
    onConnected = nil,
    onDisconnected = nil,
    onClientJoined = nil,
    onClientLeft = nil,
    onFixturesReceived = nil,
    onError = nil
}

-- 获取当前时间戳 (毫秒)
function SuperDataClient:getTimestamp()
    return math.floor(gma.gettime() * 1000)
end

-- 初始化
function SuperDataClient:init()
    -- 设置随机种子
    math.randomseed(os.time())
    
    -- 初始化客户端信息 (v2.0 简化格式)
    self.clientInfo = {
        clientId = generateUuid(),
        clientName = "GrandMA2 Client",
        platform = SUPERDATA.PLATFORM.GRANDMA,
        platformVersion = gma.git_version() or "3.3.4",
        protocolVersion = SUPERDATA.VERSION_STRING
    }
    
    self.otherClients = {}
    self.fixtures = {}
    self.receiveBuffer = ""
    
    gma.echo("[SuperData] Initialized - ID: " .. self.clientInfo.clientId:sub(1, 8) .. "...")
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

-- 解析包头
function SuperDataClient:parseHeader(data)
    if #data < SUPERDATA.HEADER_SIZE then
        return nil
    end
    
    -- 验证魔数
    local magic = data:sub(1, 4)
    if magic ~= SUPERDATA.MAGIC then
        return nil
    end
    
    return {
        magic = magic,
        version = Binary.readUInt16LE(data, 5),
        packetType = Binary.readUInt16LE(data, 7),
        sequenceNumber = Binary.readUInt32LE(data, 9),
        timestamp = Binary.readInt64LE(data, 13),
        payloadLength = Binary.readUInt32LE(data, 21)
    }
end

-- 尝试解析数据包
function SuperDataClient:tryParsePacket()
    if #self.receiveBuffer < SUPERDATA.HEADER_SIZE then
        return nil, 0
    end
    
    -- 解析包头
    local header = self:parseHeader(self.receiveBuffer)
    if not header then
        return nil, 0
    end
    
    -- 计算完整包长度
    local totalLength = SUPERDATA.HEADER_SIZE + header.payloadLength
    
    -- 检查数据是否完整
    if #self.receiveBuffer < totalLength then
        return nil, 0
    end
    
    -- 解析负载
    local packet = {
        header = header,
        payload = nil
    }
    
    if header.payloadLength > 0 then
        local payloadStr = self.receiveBuffer:sub(SUPERDATA.HEADER_SIZE + 1, totalLength)
        local ok, result = pcall(JSON.decode, payloadStr)
        if ok then
            packet.payload = result
        else
            packet.payload = {}
        end
    else
        packet.payload = {}
    end
    
    return packet, totalLength
end

-- 加载 Socket 库
function SuperDataClient:loadSocket()
    gma.echo("[SuperData] Loading socket library...")
    
    -- 尝试多种路径
    local paths = {
        "./plugins/requirements/?.lua",
        "./plugins/?.lua",
        "./?.lua"
    }
    
    for _, path in ipairs(paths) do
        package.path = package.path .. ";" .. path
    end
    
    -- 尝试不同的加载方式
    local loadMethods = {
        {"socket.socket", "socket.socket"},
        {"socket.core", "socket.core"},
        {"socket", "socket"}
    }
    
    for _, method in ipairs(loadMethods) do
        local ok, socket = pcall(function()
            return require(method[1])
        end)
        if ok and socket then
            self.socket = socket
            gma.echo("[SuperData] Socket loaded via '" .. method[2] .. "'")
            return true
        end
    end
    
    gma.echo("[SuperData] ERROR: All socket loading methods failed!")
    return false
end

-- 检查服务器是否运行
function SuperDataClient:isServerRunning()
    if not self.socket then return false end
    
    local tcp = self.socket.tcp()
    tcp:settimeout(0.1)
    
    local result = tcp:connect(SUPERDATA.LISTEN_ADDRESS, SUPERDATA.DATA_PORT)
    tcp:close()
    
    return result ~= nil
end

-- 确保服务器运行 (v2.0 新增)
function SuperDataClient:ensureServerRunning()
    -- 1. 检查是否已运行
    if self:isServerRunning() then
        gma.echo("[SuperData] Server already running")
        return true
    end
    
    -- 2. 查找服务器路径
    local serverPath = ServerLauncher.getServerPath()
    if not serverPath then
        gma.echo("[SuperData] ERROR: SuperData Server not installed!")
        gma.echo("[SuperData] Please install from: https://yunsio.com/superdata")
        return false
    end
    
    gma.echo("[SuperData] Starting server: " .. serverPath)
    
    -- 3. 启动服务器
    if not ServerLauncher.startServer(serverPath) then
        gma.echo("[SuperData] Failed to start server")
        return false
    end
    
    -- 4. 等待服务器就绪
    local startTime = gma.gettime()
    while gma.gettime() - startTime < SUPERDATA.CONNECT_TIMEOUT do
        gma.sleep(0.1)
        if self:isServerRunning() then
            gma.echo("[SuperData] Server is ready")
            return true
        end
    end
    
    gma.echo("[SuperData] Server start timeout")
    return false
end

-- 连接到服务器 (v2.0 重构)
function SuperDataClient:connect(autoStartServer)
    if autoStartServer == nil then autoStartServer = true end
    
    if not self.socket then
        if not self:loadSocket() then
            return false, "Socket library not available"
        end
    end
    
    -- 自动启动服务器
    if autoStartServer then
        if not self:ensureServerRunning() then
            return false, "Server not available. Please install SuperData Server."
        end
    end
    
    gma.echo("[SuperData] Connecting to " .. SUPERDATA.LISTEN_ADDRESS .. ":" .. SUPERDATA.DATA_PORT .. "...")
    
    -- 创建 TCP socket
    local tcp, err = self.socket.tcp()
    if not tcp then
        return false, "Failed to create TCP socket: " .. (err or "unknown")
    end
    
    -- 设置超时
    tcp:settimeout(SUPERDATA.CONNECT_TIMEOUT)
    
    -- 连接
    local ok, err = tcp:connect(SUPERDATA.LISTEN_ADDRESS, SUPERDATA.DATA_PORT)
    if not ok then
        tcp:close()
        return false, "Connection failed: " .. (err or "unknown")
    end
    
    -- 禁用 Nagle 算法
    tcp:setoption("tcp-nodelay", true)
    
    -- 设置非阻塞
    tcp:settimeout(0)
    
    self.tcpSocket = tcp
    self.receiveBuffer = ""
    
    -- 发送 Connect 请求 (v2.0 格式)
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
        return false, "Failed to send connect: " .. (err or "unknown")
    end
    
    -- 等待 ConnectAck
    tcp:settimeout(SUPERDATA.CONNECT_TIMEOUT)
    
    local startTime = gma.gettime()
    while gma.gettime() - startTime < SUPERDATA.CONNECT_TIMEOUT do
        self:receiveData()
        self:processReceivedData()
        
        if self.connected then
            tcp:settimeout(0)
            return true
        end
        
        gma.sleep(0.1)
    end
    
    tcp:close()
    self.tcpSocket = nil
    return false, "Connection timeout - no response from server"
end

-- 接收数据
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
            gma.echo("[SuperData] Server closed connection")
            self:disconnect()
            return
        elseif err == "timeout" then
            break
        elseif err then
            break
        end
        
        if not data then
            break
        end
    end
end

-- 处理接收的数据 (TCP 粘包处理)
function SuperDataClient:processReceivedData()
    while #self.receiveBuffer >= SUPERDATA.HEADER_SIZE do
        local packet, consumed = self:tryParsePacket()
        
        if not packet or consumed == 0 then
            break
        end
        
        -- 移除已处理的数据
        self.receiveBuffer = self.receiveBuffer:sub(consumed + 1)
        
        -- 处理数据包
        self:handlePacket(packet)
    end
end

-- 处理数据包
function SuperDataClient:handlePacket(packet)
    local packetType = packet.header.packetType
    local payload = packet.payload or {}
    
    if packetType == SUPERDATA.PKT.CONNECT_ACK then
        self:handleConnectAck(payload)
    elseif packetType == SUPERDATA.PKT.HEARTBEAT then
        -- 心跳响应，无需处理
    elseif packetType == SUPERDATA.PKT.CLIENT_JOINED then
        self:handleClientJoined(payload)
    elseif packetType == SUPERDATA.PKT.CLIENT_LEFT then
        self:handleClientLeft(payload)
    elseif packetType == SUPERDATA.PKT.FIXTURE_LIST_RESP then
        self:handleFixtureListResponse(payload)
    elseif packetType == SUPERDATA.PKT.ERROR then
        self:handleError(payload)
    else
        gma.echo("[SuperData] Unknown packet type: " .. SUPERDATA.getPacketTypeName(packetType))
    end
end

-- 处理 ConnectAck (v2.0)
function SuperDataClient:handleConnectAck(payload)
    local accepted = payload.accepted or payload.success
    
    if not accepted then
        local errMsg = payload.errorMessage or payload.message or "Connection rejected"
        gma.echo("[SuperData] Connection rejected: " .. errMsg)
        return
    end
    
    -- 解析群聊中的其他客户端
    self.otherClients = {}
    if payload.clients then
        for _, c in ipairs(payload.clients) do
            if c.clientId and c.clientId ~= self.clientInfo.clientId then
                self.otherClients[c.clientId] = {
                    clientId = c.clientId,
                    clientName = c.clientName or "Unknown",
                    platform = c.platform or SUPERDATA.PLATFORM.UNKNOWN,
                    fixtureCount = c.fixtureCount or 0
                }
            end
        end
    end
    
    self.connected = true
    self.lastHeartbeat = gma.gettime()
    
    local clientCount = 0
    for _ in pairs(self.otherClients) do clientCount = clientCount + 1 end
    
    gma.echo("[SuperData] Connected! Found " .. clientCount .. " other clients in session")
    
    if self.onConnected then
        self.onConnected()
    end
end

-- 处理 ClientJoined (v2.0 新增)
function SuperDataClient:handleClientJoined(payload)
    local info = payload.client or payload
    
    if info and info.clientId and info.clientId ~= self.clientInfo.clientId then
        self.otherClients[info.clientId] = {
            clientId = info.clientId,
            clientName = info.clientName or "Unknown",
            platform = info.platform or SUPERDATA.PLATFORM.UNKNOWN,
            fixtureCount = info.fixtureCount or 0
        }
        
        gma.echo("[SuperData] Client joined: " .. (info.clientName or "Unknown") .. 
                 " (" .. SUPERDATA.getPlatformName(info.platform or 0) .. ")")
        
        if self.onClientJoined then
            self.onClientJoined(info)
        end
    end
end

-- 处理 ClientLeft (v2.0 新增)
function SuperDataClient:handleClientLeft(payload)
    local clientId = payload.clientId or ""
    local info = self.otherClients[clientId]
    
    if info then
        gma.echo("[SuperData] Client left: " .. info.clientName)
        self.otherClients[clientId] = nil
        
        if self.onClientLeft then
            self.onClientLeft(clientId)
        end
    end
end

-- 处理灯具列表响应 (v2.0)
function SuperDataClient:handleFixtureListResponse(payload)
    if not payload then return end
    
    local sourceId = payload.sourceClientId or ""
    self.fixtures = payload.fixtures or {}
    
    gma.echo("[SuperData] Received " .. #self.fixtures .. " fixtures from " .. sourceId:sub(1, 8) .. "...")
    
    -- 调试：显示前几个灯具
    for i, f in ipairs(self.fixtures) do
        if i <= 5 then
            local fid = f.fixtureID or f.fixtureId or "?"
            local u = f.universe or "?"
            local a = f.startAddress or "?"
            local name = f.name or "?"
            gma.echo(string.format("[DEBUG] #%d: ID=%s, U%s.%s, %s", i, tostring(fid), tostring(u), tostring(a), name))
        end
    end
    
    if self.onFixturesReceived then
        self.onFixturesReceived(sourceId, self.fixtures)
    end
end

-- 处理错误
function SuperDataClient:handleError(payload)
    local code = payload.errorCode or payload.code or 255
    local message = payload.errorMessage or payload.message or "Unknown error"
    
    gma.echo("[SuperData] Server error [" .. code .. "]: " .. message)
    
    if self.onError then
        self.onError(code, message)
    end
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

-- 请求灯具列表 (v2.0: 需要指定 sourceClientId)
function SuperDataClient:requestFixtureList(sourceClientId)
    if not self.connected then
        gma.echo("[SuperData] Not connected")
        return false
    end
    
    gma.echo("[SuperData] Requesting fixtures from " .. sourceClientId:sub(1, 8) .. "...")
    return self:sendPacket(SUPERDATA.PKT.FIXTURE_LIST_REQ, {
        clientId = self.clientInfo.clientId,
        sourceClientId = sourceClientId
    })
end

-- 获取其他客户端列表
function SuperDataClient:getOtherClients()
    return self.otherClients
end

-- 获取灯具数据
function SuperDataClient:getFixtures()
    return self.fixtures
end

-- 更新循环
function SuperDataClient:update()
    if self.connected then
        -- 发送心跳
        self:sendHeartbeat()
        
        -- 接收和处理数据
        self:receiveData()
        self:processReceivedData()
    end
end

-- 断开连接
function SuperDataClient:disconnect()
    if self.tcpSocket then
        if self.connected then
            self:sendPacket(SUPERDATA.PKT.DISCONNECT, {
                clientId = self.clientInfo.clientId
            })
        end
        self.tcpSocket:close()
        self.tcpSocket = nil
    end
    
    local wasConnected = self.connected
    self.connected = false
    self.otherClients = {}
    self.receiveBuffer = ""
    
    if wasConnected then
        gma.echo("[SuperData] Disconnected")
        if self.onDisconnected then
            self.onDisconnected()
        end
    end
end

-- ===========================================
-- MA2 灯具导入模块
-- ===========================================
local MA2Import = {}

-- 默认灯具类型（固定为 3，用户导入后自行替换）
MA2Import.fixtureTypeId = 3
MA2Import.fixtureTypeName = "Generic"

-- 检查 FixtureID 是否有重复
function MA2Import.checkDuplicateIDs(fixtures)
    local idMap = {}
    local duplicates = {}
    
    for i, f in ipairs(fixtures) do
        local id = f.fixtureID or f.fixtureId or i
        if idMap[id] then
            table.insert(duplicates, id)
        else
            idMap[id] = true
        end
    end
    
    return duplicates
end

-- 生成 VectorWorks 风格的 Layers XML 用于导入灯具
function MA2Import.generateLayersXML(fixtures, fixtureTypeName, fixtureTypeNo)
    local fixtureXMLs = {}
    
    for i, f in ipairs(fixtures) do
        local fixtureId = f.fixtureID or f.fixtureId or i
        local universe = f.universe or 1
        if universe < 1 then universe = 1 end
        local address = f.startAddress or 1
        if address < 1 then address = 1 end
        local name = f.name or ("Fixture_" .. fixtureId)
        name = name:gsub('"', ''):gsub('<', ''):gsub('>', ''):gsub('&', 'and')
        
        -- 计算绝对 DMX 地址
        local absoluteAddress = ((universe - 1) * 512) + address
        
        -- 位置转换: 协议标准 (cm) → MA2 (m)
        local posX, posY, posZ = 0, 0, 0
        if f.position then
            if type(f.position) == "table" then
                if f.position[1] then
                    posX = (f.position[1] or 0) / 100
                    posY = (f.position[2] or 0) / 100
                    posZ = (f.position[3] or 0) / 100
                else
                    posX = (f.position.x or 0) / 100
                    posY = (f.position.y or 0) / 100
                    posZ = (f.position.z or 0) / 100
                end
            end
        end
        
        -- 旋转转换: SuperData Standard → MA2 (根据实测)
        local rotX, rotY, rotZ = 0, 0, 0
        if f.rotation then
            if type(f.rotation) == "table" then
                if f.rotation[1] then
                    rotX = f.rotation[1] or 0
                    rotY = f.rotation[2] or 0
                    rotZ = f.rotation[3] or 0
                else
                    rotX = f.rotation.x or 0
                    rotY = f.rotation.y or 0
                    rotZ = f.rotation.z or 0
                end
            end
        end
        
        -- MA2 旋转修正: Y+180, Z+90
        rotY = rotY + 180
        rotZ = rotZ + 90
        
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
    
    local layerName = fixtureTypeName
    local fixturesContent = table.concat(fixtureXMLs, "\n")
    
    local xml = string.format([[<MA xmlns="http://schemas.malighting.de/grandma2/xml/MA">
	<InfoItems>
		<Info type="Invisible" date="%s">
				SuperData Protocol v2.0 Import
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

-- 导入灯具到 MA2
function MA2Import.importFixtures(fixtures)
    local success = 0
    local failed = 0
    
    if #fixtures == 0 then
        gma.echo("[SuperData] No fixtures to import")
        return 0, 0
    end
    
    local progress = gma.gui.progress.start("Importing fixtures...")
    gma.gui.progress.setrange(progress, 0, 100)
    gma.gui.progress.set(progress, 10)
    
    local fixtureTypeName = MA2Import.fixtureTypeName
    local fixtureTypeNo = MA2Import.fixtureTypeId
    
    -- Step 1: 生成 XML
    gma.gui.progress.settext(progress, "Generating XML...")
    local xml = MA2Import.generateLayersXML(fixtures, fixtureTypeName, fixtureTypeNo)
    
    -- Step 2: 写入临时文件
    gma.gui.progress.set(progress, 30)
    gma.gui.progress.settext(progress, "Writing temp file...")
    
    gma.cmd('SelectDrive 1')
    local showPath = gma.show.getvar("PATH")
    local tempFileName = "superdata_import"
    local tempFilePath = showPath .. "/importexport/" .. tempFileName .. ".xml"
    
    local file = io.open(tempFilePath, "w")
    if not file then
        gma.gui.progress.stop(progress)
        gma.echo("[SuperData] ERROR: Cannot create temp file!")
        return 0, #fixtures
    end
    file:write(xml)
    file:close()
    
    -- Step 3: 进入 EditSetup
    gma.gui.progress.set(progress, 50)
    gma.gui.progress.settext(progress, "Importing to MA2...")
    gma.cmd('CD EditSetup')
    gma.sleep(0.2)
    
    -- Step 4: 导入 Layers
    local importCmd = 'Import "' .. tempFileName .. '" At Layers /nc'
    gma.echo("[SuperData] " .. importCmd)
    gma.cmd(importCmd)
    gma.sleep(0.5)
    
    -- Step 5: 返回根目录
    gma.cmd('CD /')
    gma.sleep(0.2)
    
    -- Step 6: 清理临时文件
    gma.gui.progress.set(progress, 90)
    gma.gui.progress.settext(progress, "Cleaning up...")
    os.remove(tempFilePath)
    
    gma.gui.progress.set(progress, 100)
    gma.gui.progress.stop(progress)
    
    success = #fixtures
    gma.echo("[SuperData] Import complete: " .. success .. " fixtures")
    
    return success, failed
end

-- ===========================================
-- GUI 模块 (v2.0 重构)
-- ===========================================
local GUI = {}

-- 主菜单流程
function GUI.showMainMenu(client)
    -- Step 1: 连接服务器
    local progress = gma.gui.progress.start("Connecting to SuperData Server...")
    gma.gui.progress.setrange(progress, 0, 100)
    gma.gui.progress.set(progress, 20)
    
    local ok, err = client:connect(true)  -- 自动启动服务器
    
    if not ok then
        gma.gui.progress.stop(progress)
        gma.gui.msgbox("Connection Error", 
            "Failed to connect to SuperData Server:\n\n" .. (err or "Unknown error") .. 
            "\n\nPlease install SuperData Server from:\nhttps://yunsio.com/superdata")
        return
    end
    
    gma.gui.progress.set(progress, 50)
    gma.gui.progress.settext(progress, "Connected! Checking clients...")
    gma.sleep(0.3)
    
    -- 处理一下可能的消息
    client:update()
    gma.sleep(0.2)
    client:update()
    
    gma.gui.progress.stop(progress)
    
    -- Step 2: 显示群聊成员列表
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
            "No other clients connected to SuperData Server.\n\n" ..
            "Please start Unity/UE/VW with SuperData plugin first,\n" ..
            "then try again.")
        client:disconnect()
        return
    end
    
    -- Step 3: 显示可用数据源列表
    local listMsg = "Found " .. clientCount .. " data source(s):\n\n"
    for i, c in ipairs(clientList) do
        local platformName = SUPERDATA.getPlatformName(c.platform)
        listMsg = listMsg .. string.format("[%d] %s\n    Platform: %s\n    Fixtures: %d\n\n", 
            i, c.name, platformName, c.fixtureCount or 0)
    end
    listMsg = listMsg .. "Click OK to select a source..."
    
    -- 先显示列表
    gma.gui.msgbox("Available Sources", listMsg)
    
    -- 再输入序号
    local promptMsg = "Enter source number (1-" .. clientCount .. "):"
    local choice = gma.textinput("Select Source", promptMsg)
    if not choice or choice == "" then
        client:disconnect()
        return
    end
    
    local selectedIdx = tonumber(choice)
    if not selectedIdx or selectedIdx < 1 or selectedIdx > clientCount then
        gma.gui.msgbox("Error", "Invalid selection: " .. tostring(choice) .. "\nPlease enter 1-" .. clientCount)
        client:disconnect()
        return
    end
    
    local selectedClient = clientList[selectedIdx]
    gma.echo("[SuperData] Selected: " .. selectedClient.name)
    
    -- Step 4: 请求灯具数据
    local progress2 = gma.gui.progress.start("Requesting fixtures from " .. selectedClient.name .. "...")
    gma.gui.progress.setrange(progress2, 0, 100)
    gma.gui.progress.set(progress2, 30)
    
    client:requestFixtureList(selectedClient.id)
    
    -- 等待接收
    gma.gui.progress.settext(progress2, "Receiving fixtures...")
    
    for i = 1, 100 do
        gma.sleep(0.1)
        client:update()
        gma.gui.progress.set(progress2, 30 + i * 0.5)
        if #client.fixtures > 0 then
            gma.echo("[SuperData] Got " .. #client.fixtures .. " fixtures!")
            break
        end
    end
    
    gma.gui.progress.stop(progress2)
    
    local fixtures = client:getFixtures()
    if #fixtures == 0 then
        gma.gui.msgbox("Error", "No fixtures received from " .. selectedClient.name .. "!")
        client:disconnect()
        return
    end
    
    -- Step 5: 确认导入
    local confirmMsg = "Received " .. #fixtures .. " fixtures from:\n" ..
                       selectedClient.name .. "\n\n"
    
    for i = 1, math.min(8, #fixtures) do
        local f = fixtures[i]
        confirmMsg = confirmMsg .. f.name .. " (U" .. (f.universe or 1) .. "." .. (f.startAddress or 1) .. ")\n"
    end
    if #fixtures > 8 then
        confirmMsg = confirmMsg .. "... and " .. (#fixtures - 8) .. " more\n"
    end
    confirmMsg = confirmMsg .. "\nPatch to MA2?"
    
    if not gma.gui.confirm("Import Fixtures?", confirmMsg) then
        client:disconnect()
        return
    end
    
    -- Step 6: 检查重复 ID
    local duplicates = MA2Import.checkDuplicateIDs(fixtures)
    if #duplicates > 0 then
        local dupStr = table.concat(duplicates, ", ")
        gma.gui.msgbox("ERROR: Duplicate FixtureID!", 
            "Found duplicate FixtureID(s): " .. dupStr .. "\n\n" ..
            "Please fix in " .. selectedClient.name .. " first!")
        client:disconnect()
        return
    end
    
    -- Step 7: 执行导入
    local success, failed = MA2Import.importFixtures(fixtures)
    
    -- Step 8: 显示结果
    if success > 0 then
        gma.gui.msgbox("Import Complete!", 
            "Added: " .. success .. " fixtures\n" ..
            "Failed: " .. failed .. "\n\n" ..
            "IMPORTANT: Replace fixture types in\n" ..
            "Setup > Patch > Fixture Types if needed!")
    else
        gma.gui.msgbox("Import Failed", "No fixtures were imported.\nFailed: " .. failed)
    end
    
    client:disconnect()
    gma.echo("[SuperData] Complete!")
end

-- ===========================================
-- 主程序
-- ===========================================
local client = nil
local running = false

-- 更新回调
function UpdateCallback(timer, count)
    if client and running then
        client:update()
    end
end

-- 启动函数
function Start()
    gma.echo("=========================================")
    gma.echo("   SuperData Protocol Client v2.0.0")
    gma.echo("   for GrandMA2 (群聊模式)")
    gma.echo("=========================================")
    
    -- 创建客户端实例
    client = setmetatable({}, {__index = SuperDataClient})
    
    -- 显示欢迎界面
    local welcome = [[
SuperData Protocol Client v2.0.0
─────────────────────────────────

Cross-platform fixture data sync
for Unity / Unreal / Vectorworks

v2.0 Features:
• Auto-start server
• Session-based group chat
• Select import source

Developed by Yunsio SuperStage

─────────────────────────────────
Press OK to connect...]]
    
    if not gma.gui.confirm("SuperData", welcome) then
        return
    end
    
    -- 初始化
    local progress = gma.gui.progress.start("Initializing...")
    gma.gui.progress.setrange(progress, 0, 100)
    gma.gui.progress.set(progress, 30)
    
    if not client:init() then
        gma.gui.progress.stop(progress)
        gma.gui.msgbox("Error", "Failed to initialize SuperData client")
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
