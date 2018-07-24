#
# Copyright (C) 2008-2014 The LuCI Team <luci@lists.subsignal.org>
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk

LUCI_TITLE:=Quality of Service configuration module
LUCI_DEPENDS:=+sjmain
PKG_NAME:=luci-app-sjmain
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

define Package/$(PKG_NAME)/config
# shown in make menuconfig <Help>
help
	$(LUCI_TITLE)
	Version: $(PKG_VERSION)-$(PKG_RELEASE)
endef
include ../../luci.mk


# call BuildPackage - OpenWrt buildroot signature
