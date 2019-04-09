#!/bin/sh /etc/rc.common
config_load network
config_get lanip lan ipaddr
sed -i -r "s/([0-9]{1,3}\.){3}([0-9]{1,3})/${lanip}/g" /www/portal/portal_redirect.html
