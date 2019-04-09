include $(TOPDIR)/rules.mk
#include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:= minishell
PKG_RELEASE:=1
PKG_VERSION:=1.0

include $(INCLUDE_DIR)/package.mk
#PKG_BUILD_DIR:= $(BUILD_DIR)/$(PKG_NAME)

define Package/minishell
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=minishell r/w test
	PKGARCH:=all
endef

define Package/minishell/description
	minishell building test
endef

define Build/Prepare
	$(CP) ./* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/src \
	$(TARGET_CONFIGURE_OPTS) CFLAGS="$(TARGET_CFLAGS) -I$(LINUX_DIR)/include"
endef

define Package/minishell/install
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/minishell $(1)/usr/bin/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/etc/init.d/minishell $(1)/etc/init.d/
	
	$(INSTALL_DIR) $(1)/etc/rc.d
	ln -s ../init.d/minishell $(1)/etc/rc.d/S99minishell
endef

$(eval $(call BuildPackage,minishell)) 
