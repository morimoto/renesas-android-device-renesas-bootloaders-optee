OPTEE_SRC=$(ANDROID_BUILD_TOP)/device/renesas/salvator/bootloaders/optee/
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
	$(hide) cp $(OPTEE_OUT)/core/*.srec $(ANDROID_BUILD_TOP)/$(PRODUCT_OUT)/

.PHONY: optee
