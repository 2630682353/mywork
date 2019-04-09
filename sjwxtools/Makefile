include $(TOPDIR)/rules.mk
#include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:= sjwxtool
PKG_RELEASE:=1
PKG_VERSION:=1.0

include $(INCLUDE_DIR)/package.mk
#PKG_BUILD_DIR:= $(BUILD_DIR)/$(PKG_NAME)

define Package/sjwxtool
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=sjwxtool r/w test
	PKGARCH:=all
	DEPENDS:=+libpcap +libpthread
endef

define Package/sjwxtool/description
	sjwxtool building test
endef

define Build/Prepare
	$(CP) ./* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/src \
	$(TARGET_CONFIGURE_OPTS) CFLAGS="$(TARGET_CFLAGS) -I$(LINUX_DIR)/include"
endef

define Package/sjwxtool/install
	$(INSTALL_DIR) $(1)/usr/wifi/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/sjwxtool $(1)/usr/wifi/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/sctl $(1)/usr/wifi/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/etc/init.d/sjwxtool $(1)/etc/init.d/
	
	$(INSTALL_DIR) $(1)/etc/rc.d
	ln -s ../init.d/sjwxtool $(1)/etc/rc.d/S99sjwxtool
endef

$(eval $(call BuildPackage,sjwxtool)) 
