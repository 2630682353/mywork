include $(TOPDIR)/rules.mk

PKG_NAME:=sjmain
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/sjmain
  SECTION:=base
  CATEGORY:=Network
  TITLE:=sjmain
  DEPENDS= +libshare +libcurl
endef

define Package/sjmain/description
	sjmain 
endef

define Build/Configure
	$(call Build/Configure/Default)
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	$(CP) ./etc $(PKG_BUILD_DIR)/
endef


define Package/sjmain/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sjmain $(1)/bin/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/etc/config/ap_config $(1)/etc/config/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/sjmain.init $(1)/etc/init.d/sjmain
endef

$(eval $(call BuildPackage,sjmain))