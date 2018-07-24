-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Licensed to the public under the Apache License 2.0.

module("luci.controller.sjwxqos", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/sjwxqos") then
		return
	end
	
	local page

	page = entry({"admin", "network", "sjwxqos"}, cbi("qos/sjwxqos"), _("sjwxQoS"))
	page.dependent = true
end
