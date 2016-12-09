OPTEE_SRC=$(ANDROID_BUILD_TOP)/device/renesas/bootloaders/optee/
export OPTEE_OUT=$(ANDROID_BUILD_TOP)/$(TARGET_OUT_INTERMEDIATES)/OPTEE_OBJ
export CROSS_COMPILE64=$(ANDROID_BUILD_TOP)/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-gnu-5.1/bin/aarch64-linux-gnu-

PLATFORM=rcar

LOCAL_CFLAGS+=-march=armv8-a
LOCAL_CFLAGS+=-mtune=cortex-a57.cortex-a53

$(OPTEE_OUT):
	$(hide) mkdir -p $(OPTEE_OUT)

optee: $(OPTEE_OUT)
	@echo "Building optee"
	$(hide) ARCH=arm make  -e MAKEFLAGS= CFG_ARM64_core=y PLATFORM=rcar -C $(OPTEE_SRC) O=$(OPTEE_OUT) clean
	$(hide) ARCH=arm make  -e MAKEFLAGS= CFG_ARM64_core=y PLATFORM=rcar -C $(OPTEE_SRC) O=$(OPTEE_OUT) all
	$(hide) cp $(OPTEE_OUT)/core/*.srec $(ANDROID_PRODUCT_OUT)/
	$(hide) cp $(OPTEE_OUT)/core/*.bin $(ANDROID_PRODUCT_OUT)/

android_optee: $(OPTEE_OUT)
	@echo "Building optee"
	$(hide) ARCH=arm make  -e MAKEFLAGS= CFG_ARM64_core=y PLATFORM=rcar -C $(OPTEE_SRC) O=$(OPTEE_OUT) clean
	$(hide) ARCH=arm make  -e MAKEFLAGS= CFG_ARM64_core=y PLATFORM=rcar -C $(OPTEE_SRC) O=$(OPTEE_OUT) all

.PHONY: optee


LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

TEE_BIN_PATH := $(OPTEE_OUT)/core/tee.bin
$(TEE_BIN_PATH): android_optee

LOCAL_MODULE := tee.bin
LOCAL_PREBUILT_MODULE_FILE:= $(TEE_BIN_PATH)
LOCAL_MODULE_PATH := $(ANDROID_BUILD_TOP)/$(PRODUCT_OUT)

include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)

TEE_SREC_PATH := $(OPTEE_OUT)/core/tee.srec
$(TEE_SREC_PATH): android_optee

LOCAL_MODULE := tee.srec
LOCAL_PREBUILT_MODULE_FILE:= $(TEE_SREC_PATH)
LOCAL_MODULE_PATH := $(ANDROID_BUILD_TOP)/$(PRODUCT_OUT)

include $(BUILD_EXECUTABLE)
