include $(TOPDIR)/rules.mk
#include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:= sjwxd
PKG_RELEASE:=1
PKG_VERSION:=1.0

include $(INCLUDE_DIR)/package.mk
#PKG_BUILD_DIR:= $(BUILD_DIR)/$(PKG_NAME)

define Package/sjwxd
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=sjwxd r/w test
	PKGARCH:=all
	DEPENDS:=+libevent2 +libpthread
endef

define Package/sjwxd/description
	sjwxd building test
endef

define Package/sjwxd/extra_provides
    echo 'libgcc_s.so.1'; \
    echo 'libc.so';
endef

define Build/Prepare
	$(CP) ./* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/src \
	$(TARGET_CONFIGURE_OPTS) CFLAGS="$(TARGET_CFLAGS) -I$(LINUX_DIR)/include"
endef

define Package/sjwxd/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/sjwxdc $(1)/usr/bin

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/etc/init.d/sjwxdc $(1)/etc/init.d/sjwxdc
	
	$(INSTALL_DIR) $(1)/etc/rc.d
	ln -s ../init.d/sjwxdc $(1)/etc/rc.d/S99sjwxdc
endef

$(eval $(call BuildPackage,sjwxd)) 
