do
    -- package.path = Dir.global_plugins_path() .. ';' .. package.path
    require "pb"
    require "rpc"

    local types = {
        [1] = "Request",
        [2] = "Response",
        [3] = "Binary Blob",
        [4] = "Error",
        [5] = "Notify",
    }
    local types2 = {
        [1] = "CALL",
        [2] = "RESP",
        [3] = "BLOB",
        [4] = "ERRR",
        [5] = "NTFY",
    }
    local methods = {
        [0] = "getPortIdList",
        [1] = "getPortConfig",
        [2] = "modifyPort",
        [3] = "getStreamIdList",
        [4] = "getStreamConfig",
        [5] = "addStream",
        [6] = "deleteStream",
        [7] = "modifyStream",
        [8] = "startTransmit",
        [9] = "stopTransmit",
        [10] = "startCapture",
        [11] = "stopCapture",
        [12] = "getCaptureBuffer",
        [13] = "getStats",
        [14] = "clearStats",
        [15] = "checkVersion"
    }
    local rpc_list = {
        [0] = {rpc = "getPortIdList",
               request = "Void",
               response = "PortIdList"},
        [1] = {rpc = "getPortConfig",
               request = "PortIdList",
               response = "PortConfigList"},
        [2] = {rpc = "modifyPort",
               request = "PortConfig",
               response = "Ack"},
        [3] = {rpc = "getStreamIdList",
               request = "PortId",
               response = "StreamIdList"},
        [4] = {rpc = "getStreamConfig",
               request = "StreamIdList",
               response = "Ack"},
        [5] = {rpc = "addStream",
               request = "StreamIdList",
               response = "Ack"},
        [6] = {rpc = "deleteStream",
               request = "StreamIdList",
               response = "Ack"},
        [7] = {rpc = "modifyStream",
               request = "StreamConfigList",
               response = "Ack"},
        [8] = {rpc = "startTransmit",
               request = "PortIdList",
               response = "Ack"},
        [9] = {rpc = "stopTransmit",
               request = "PortIdList",
               response = "Ack"},
        [10] = {rpc = "startCapture",
               request = "PortIdList",
               response = "Ack"},
        [11] = {rpc = "stopCapture",
               request = "PortIdList",
               response = "Ack"},
        [12] = {rpc = "getCaptureBuffer",
               request = "PortId",
               response = "CaptureBuffer"},
        [13] = {rpc = "getStats",
               request = "PortIdList",
               response = "PortStatsList"},
        [14] = {rpc = "clearStats",
               request = "PortIdList",
               response = "Ack"},
        [15] = {rpc = "checkVersion",
                request = "VersionInfo",
                response = "VersionCompatibility"}
    }
    -- OST-RPC protocol
    local p_ostrpc = Proto("ostrpc","Ostinato RPC");

    -- RPC Header (Sub)Proto and Field(s)
    local p_hdr = Proto("ostrpc.header","RPC Header")
    local f_type = ProtoField.uint16("ostrpc.type","Type",base.DEC, types)
    local f_method = ProtoField.uint16("ostrpc.method","Method",base.DEC,
                         methods)
    local f_len = ProtoField.uint32("ostrpc.length","Message Length",base.DEC)

    -- RPC Data (Sub)Proto and Field(s)
    local p_data = Proto("ostrpc.data","RPC Data")
    local f_msg = ProtoField.string("ostrpc.message","Message")

    p_ostrpc.fields = {f_type, f_method, f_len, f_msg}

    function string.fromhex(str)
        return (str:gsub('..', function (cc)
                return string.char(tonumber(cc, 16))
        end))
    end

    function p_ostrpc.dissector(buf, pinfo, root)
        -- add OST-RPC tree
        local t = root:add(p_ostrpc, buf(0,buf:len()))

        -- add RPC Header subtree to OST-RPC tree
        local hdr = t:add(p_hdr, buf(0,8))
        local msg_type = buf(0,2):uint()
        local method = buf(2,2):uint()
        local length = buf(4,4):uint()

        hdr:add(f_type, buf(0,2), msg_type)
        hdr:add(f_method, buf(2,2), method)
        hdr:add(f_len, buf(4,4), length)

        hdr:append_text(": "..types[msg_type].." "..methods[method])
        t:append_text(", "..types2[msg_type].." "..methods[method])
        info("1")

        -- find the Message corresponding to the RPC method and msg_type
        local pbmsg = ""
        local r = rpc_list[method]
        if msg_type == 1 then
            pbmsg = r.request
        elseif msg_type == 2 then
            pbmsg = r.response
        else
            -- TODO: other msg types
            return
        end

        t:append_text("("..pbmsg..")")

        -- local msg = rpc.VersionInfo():Parse(byt)

        -- TODO: do we have entire message in this packet
        -- or do we need reassembly?

        -- build the 'program' to parse the suitable Message
        local prog = assert(loadstring("return rpc."..pbmsg.."():Parse(...)"))
        info("2")

        -- extract the serialized data to parse
        local byt = tostring(buf(8, length):bytes()):fromhex()
        info("2a")

        -- Actually parse the serialized binary data using the built 'program'
        local msg = prog(byt)
        info("3")

        -- Serialize to human-readable text
        local txt= msg:Serialize("text")
        info("4")

        -- add RPC Data subtree to OST-RPC tree
        local data = t:add(p_data, buf(8, length))
        data:append_text(": "..pbmsg)
        local pbm = data:add(f_msg, buf(8, length))
        pbm:set_text(txt)

        -- update top pane cols
        -- TODO: instead of pbmsg use actual [elided] data
        pinfo.cols.protocol = "OST-RPC"
        pinfo.cols.info = types2[msg_type]..": "..methods[method].." ("..pbmsg..")"
    end

    local tcp_encap_table = DissectorTable.get("tcp.port")
    tcp_encap_table:add(7878, p_ostrpc)
end
