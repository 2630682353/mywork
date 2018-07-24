-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Licensed to the public under the Apache License 2.0.

local fs = require "nixio.fs"

m = Map("sjwxqos", translate("商机无限qos"),
	translate("商机无限qos"))

s = m:section(NamedSection, "qos_base", "qos_base")

e = s:option(Flag, "enable", translate("开启"))
e.rmempty = false


s = m:section(TypedSection, "client_ip", translate("条目"))
s.template = "cbi/tblsection"
s.anonymous = true
s.addremove = true
s.sortable  = true


p = s:option(Value, "ipaddr", translate("ip地址"))
p:value("", translate("无限制"))
p.rmempty = false

p = s:option(Value, "upload", translate("保证上行速率(KB/s)"))
p:value("", translate("无限制"))
p.rmempty = true

p = s:option(Value, "ceil_up", translate("最大上行速率(KB/s)"))
p:value("", translate("无限制"))
p.rmempty = true


p = s:option(Value, "download", translate("保证下行速率(KB/s)"))
p:value("", translate("无限制"))
p.rmempty = true

p = s:option(Value, "ceil_down", translate("最大下行速率(KB/s)"))
p:value("", translate("无限制"))
p.rmempty = true

return m
