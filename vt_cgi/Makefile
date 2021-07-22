include $(TOPDIR)/rules.mk

PKG_NAME:=vt_cgi
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/vt_cgi
  SECTION:=base
  CATEGORY:=Vantron
  TITLE:=vt_cgi
  DEPENDS:=+luci-app-nlbwmon +libuci
endef

define Package/vt_cgi/description
	vt_cgi cgi 
endef

define Build/Configure
	$(call Build/Configure/Default)
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef


define Package/vt_cgi/install
	$(INSTALL_DIR) $(1)/www/cgi
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/vt_cgi $(1)/www/cgi
endef

$(eval $(call BuildPackage,vt_cgi))