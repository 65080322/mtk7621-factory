#
# Copyright (C) 2010-2013 hua.shao@mediatek.com
#
# MTK Property Software.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=factory_test
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_CONFIG_DEPENDS:=+ libpthread

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

define Package/factory_test
  SECTION:=base
  CATEGORY:=X-Speed Modules
  DEPENDS:=+libpthread
  TITLE:= do hardware testing and ageing
endef

define Package/factory_test/description
  An program to do hardware testing and ageing.
endef

TARGET_LDFLAGS:= -lpthread  

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef



#TARGET_CFLAGS += \
#	-I$(LINUX_DIR)/arch/mips/include \
#	-I$(LINUX_DIR)/drivers/net/rt_rdm
#MAKE_FLAGS += \
#	CFLAGS="$(TARGET_CFLAGS)"


define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/factory_test/install
	$(INSTALL_DIR) $(1)/usr/bin
#	$(CP) /lib/libpthread.so.0 $(1)/usr/bin/  
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/factory_test $(1)/usr/bin
endef


$(eval $(call BuildPackage,factory_test))

