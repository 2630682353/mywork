include $(TOPDIR)/rules.mk

PKG_NAME:=portal
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/portal
  SECTION:=base
  CATEGORY:=Network
  TITLE:=portal
  DEPENDS=+libipc +libshare
endef

define Package/portal/description
	portal cgi 
endef

define Build/Configure
	$(call Build/Configure/Default)
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef


define Package/portal/install
	$(INSTALL_DIR) $(1)/www/portal
	$(INSTALL_DIR) $(1)/www/cgi-bin
	
	$(CP) ./html/* $(1)/www/portal
	$(CP) ./ads $(1)/www/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/portal_cgi $(1)/www/cgi-bin
endef

$(eval $(call BuildPackage,portal))