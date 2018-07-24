-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Licensed to the public under the Apache License 2.0.

module("luci.controller.sjmain", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/ap_config") then
		return
	end
	
	local page

	page = entry({"admin", "status", "sjwx_traffic"}, template("admin_status/sjwx_traffic"), _("sjwx_traffic"), 8)
	page.dependent = true
end
