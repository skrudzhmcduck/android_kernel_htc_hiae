ifneq (,$(findstring N70,$(PRIVATE_RCMS_NAME)))

#
# Makefile for the <t-base core and trusted UI drivers
#

obj-$(CONFIG_TRUSTONIC_TEE) := 310d/MobiCoreDriver/
obj-$(CONFIG_TRUSTONIC_TRUSTED_UI) += 310d/TlcTui/

else

#
# Makefile for the kernel mobicore drivers
#
GUD_ROOT_FOLDER := drivers/gud/301c
# add our modules to kernel.
obj-$(CONFIG_MOBICORE_API) += mcKernelApi.o
obj-$(CONFIG_MOBICORE_SUPPORT) += mcDrvModule.o

mcDrvModule-y := 301c/MobiCoreDriver/logging.o \
                301c/MobiCoreDriver/ops.o \
                301c/MobiCoreDriver/mem.o \
                301c/MobiCoreDriver/api.o \
                301c/MobiCoreDriver/pm.o \
                301c/MobiCoreDriver/main.o

mcKernelApi-y := 301c/MobiCoreKernelApi/main.o \
                301c/MobiCoreKernelApi/clientlib.o \
                301c/MobiCoreKernelApi/device.o \
                301c/MobiCoreKernelApi/session.o \
                301c/MobiCoreKernelApi/connection.o

# Release mode by default
ccflags-y := -DNDEBUG -I$(GUD_ROOT_FOLDER)
ccflags-y += -Wno-declaration-after-statement

#Netlink changed arguments number
ccflags-y += -DMC_NETLINK_COMPAT_V37

ccflags-$(CONFIG_MOBICORE_DEBUG) += -DDEBUG
ccflags-$(CONFIG_MOBICORE_VERBOSE) += -DDEBUG_VERBOSE

# Choose one platform from the folder
MOBICORE_PLATFORM := $(shell (ls -1 $(PWD)/$(GUD_ROOT_FOLDER)/MobiCoreDriver/platforms | tail -1) )
# Use the available platform folder
ccflags-y += -I$(GUD_ROOT_FOLDER)/MobiCoreDriver/platforms/$(MOBICORE_PLATFORM)
# MobiCore Driver includes
ccflags-y += -I$(GUD_ROOT_FOLDER)/MobiCoreDriver/public
# MobiCore KernelApi required incldes
ccflags-y += -I$(GUD_ROOT_FOLDER)/MobiCoreKernelApi/include
ccflags-y += -I$(GUD_ROOT_FOLDER)/MobiCoreKernelApi/public

endif
