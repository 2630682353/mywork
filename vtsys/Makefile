include $(TOPDIR)/rules.mk

PKG_NAME:=vtsys
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/vtsys
  SECTION:=base
  CATEGORY:=Vantron
  TITLE:=vtsys
  DEPENDS:= +libuci
endef

define Package/vtsys/description
	vtsys system api
endef

define Build/Configure
	$(call Build/Configure/Default)
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef


define Package/vtsys/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/vtsys $(1)/usr/sbin
endef

$(eval $(call BuildPackage,vtsys))