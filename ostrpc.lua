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
    -- Header Format (8 bytes): MsgType(2), Method(2), Length(4)
    -- Note: Length excluding header
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

    function ostrpc_pdu_len(buf, pinfo, offset)
        -- validate hdr
        local msg_type = buf(0,2):uint()
        local method = buf(2,2):uint()
        if (types[msg_type] == nil or methods[method] == nil) then
            info("invalid msgType or method")
            return -1
        end

        return 8 + buf(4,4):uint()
    end

    function ostrpc_dissector(buf, pinfo, root)
        info("tvb len = "..buf:len())

        -- TODO: different cap_len and reported_len

        -- add OST-RPC tree
        local t = root:add(p_ostrpc, buf(0,buf:len()))

        local msg_type = buf(0,2):uint()
        local method = buf(2,2):uint()
        local length = buf(4,4):uint()

        -- validate hdr
        local msg_type = buf(0,2):uint()
        local method = buf(2,2):uint()
        if (types[msg_type] == nil or methods[method] == nil) then
            info("[invalid msgType or method]")
            if ProtoExpert then
                local err = ProtoExpert("", "Malformed RPC Header",
                                        expert.group.MALFORMED,
                                        expert.severity.ERROR)
                t:add(err, buf(0,8))
            end
            return 0
        end

        -- add RPC Header subtree to OST-RPC tree
        local hdr = t:add(p_hdr, buf(0,8))
        hdr:add(f_type, buf(0,2), msg_type)
        hdr:add(f_method, buf(2,2), method)
        hdr:add(f_len, buf(4,4), length)

        hdr:append_text(": "..types[msg_type].." "..methods[method])
        t:append_text(", "..types2[msg_type].." "..methods[method])

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

        -- build the 'program' to parse the suitable Message
        local prog = assert(loadstring("return rpc."..pbmsg.."():Parse(...)"))

        -- extract the serialized data to parse
        local byt = tostring(buf(8, length):bytes()):fromhex()

        -- Actually parse the serialized binary data using the built 'program'
        local msg = prog(byt)

        -- Serialize to human-readable text
        local txt= msg:Serialize("text")

        -- add RPC Data subtree to OST-RPC tree
        local data = t:add(p_data, buf(8, length))
        data:append_text(": "..pbmsg)

        -- Wireshark truncates each decode line at 240 characters
        -- split into multiple line if required
        if (#txt > 240) then
            for s in txt:gmatch("[^\r\n]+") do
                local s2 = data:add(f_msg)
                s2:set_text(s)
            end
        else
            local pbm = data:add(f_msg, buf(8, length))
            pbm:set_text(txt)
        end

        -- update top pane cols
        -- TODO: instead of pbmsg use actual [elided] data
        pinfo.cols.protocol = "OST-RPC"
        pinfo.cols.info = types2[msg_type]..": "..methods[method].." ("..pbmsg..")"
    end

    function tcp_dissect_pdu(buf, pinfo, tree, pdu_hdr_len,
                             get_pdu_len, pdu_dissector)
        local offset = 0
        local len = buf:len()
        local pdu_len = 0

        while (len > 0) do
            info("#"..pinfo.number.." len: "..pinfo.len)
            if (len < pdu_hdr_len) then
                -- don't have full header, need more bytes
                pinfo.desegment_offset = offset
                pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
                info("incomplete pdu hdr ["..offset..", +1]")
                return
            end

            pdu_len = get_pdu_len(buf, pinfo, offset)
            if (pdu_len < pdu_hdr_len) then
                info("invalid msgType or method")
                if ProtoExpert then
                    local err = ProtoExpert("", "Malformed RPC Header",
                                            expert.group.MALFORMED,
                                            expert.severity.ERROR)
                    tree:add(err, buf(offset,8))
                end
                return 0
            end
            if (len < pdu_len) then
                -- don't have full PDU, need more bytes
                pinfo.desegment_offset = offset
                pinfo.desegment_len = pdu_len - len
                info("incomplete pdu ["..offset..", "..pdu_len-len.."]")
                return;
            end

            info("calling pdu dissector ["..offset..", "..pdu_len.."]")
            pdu_dissector(buf(offset, pdu_len):tvb(), pinfo, tree)

            offset = offset + pdu_len
            len = len - pdu_len
        end

    end

    function p_ostrpc.dissector(buf, pinfo, root)
        -- recent version of Wireshark have a tcp_dissect_pdus() but
        -- for some reason it doesn't seem to accept pinfo as a param
        return tcp_dissect_pdu(buf, pinfo, root,
                               8, ostrpc_pdu_len, ostrpc_dissector)
    end

    local tcp_encap_table = DissectorTable.get("tcp.port")
    tcp_encap_table:add(7878, p_ostrpc)
end
