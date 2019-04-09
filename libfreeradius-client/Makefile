include $(TOPDIR)/rules.mk

PKG_NAME:=libfreeradius-client
PKG_VERSION:=1.1.7
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/freeradius-client-$(PKG_VERSION)
PKG_SOURCE:=freeradius-client-$(PKG_VERSION).tar.gz


include $(INCLUDE_DIR)/package.mk

define Package/libfreeradius-client
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=libfreeradius-client
endef

define Package/libfreeradius-client/description
	libfreeradius-client
endef

define Build/Configure
	$(call Build/Configure/Default)
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib 
	$(CP) $(PKG_BUILD_DIR)/lib/.libs/libfreeradius-client.a $(1)/usr/lib/

endef

define Package/libfreeradius-client/install

	$(INSTALL_DIR) $(1)/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/.libs/libfreeradius-client.a $(1)/lib/

endef

$(eval $(call BuildPackage,libfreeradius-client))