#
# Copyright (C) 2011 The Android Open-Source Project
# Copyright (C) 2018 GlobalLogic
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Include only for Renesas ones.
ifneq (,$(filter $(TARGET_PRODUCT), salvator ulcb kingfisher))

# Android build top/root directory
ANDROID_ROOT		:= $(shell cd $(OUT_DIR)/target/product/$(TARGET_PRODUCT) && cd ../../../.. && pwd)

OPTEE_SRC		:= device/renesas/bootloaders/optee
OPTEE_OUT		:= $(ANDROID_ROOT)/$(OUT_DIR)/target/product/$(TARGET_PRODUCT)/obj/OPTEE_OBJ
OPTEE_CROSS_COMPILE	:= $(ANDROID_ROOT)/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-gnu-7.1.1/bin/aarch64-linux-gnu-

LOCAL_CFLAGS		+= -march=armv8-a
LOCAL_CFLAGS		+= -mtune=cortex-a57.cortex-a53

$(OPTEE_OUT):
	$(hide) mkdir -p $(OPTEE_OUT)

optee: $(OPTEE_OUT)
	@echo "Building optee"
	$(hide) ARCH=arm make -e MAKEFLAGS= CFG_ARM64_core=y PLATFORM=rcar -C $(OPTEE_SRC) O=$(OPTEE_OUT) CROSS_COMPILE64=$(OPTEE_CROSS_COMPILE) clean
	$(hide) ARCH=arm make -e MAKEFLAGS= CFG_ARM64_core=y PLATFORM=rcar -C $(OPTEE_SRC) O=$(OPTEE_OUT) CROSS_COMPILE64=$(OPTEE_CROSS_COMPILE) all
	$(hide) cp $(OPTEE_OUT)/core/*.srec $(PRODUCT_OUT)/
	$(hide) cp $(OPTEE_OUT)/core/*.bin $(PRODUCT_OUT)/

android_optee: $(OPTEE_OUT)
	@echo "Building optee"
	$(hide) ARCH=arm make -e MAKEFLAGS= CFG_ARM64_core=y PLATFORM=rcar -C $(OPTEE_SRC) O=$(OPTEE_OUT) CROSS_COMPILE64=$(OPTEE_CROSS_COMPILE) clean
	$(hide) ARCH=arm make -e MAKEFLAGS= CFG_ARM64_core=y PLATFORM=rcar -C $(OPTEE_SRC) O=$(OPTEE_OUT) CROSS_COMPILE64=$(OPTEE_CROSS_COMPILE) all

.PHONY: optee


LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

TEE_BIN_PATH := $(OPTEE_OUT)/core/tee.bin
$(TEE_BIN_PATH): android_optee

LOCAL_MODULE := tee.bin
LOCAL_PREBUILT_MODULE_FILE:= $(TEE_BIN_PATH)
LOCAL_MODULE_PATH := $(PRODUCT_OUT)

include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)

TEE_SREC_PATH := $(OPTEE_OUT)/core/tee.srec
$(TEE_SREC_PATH): android_optee

LOCAL_MODULE := tee.srec
LOCAL_PREBUILT_MODULE_FILE:= $(TEE_SREC_PATH)
LOCAL_MODULE_PATH := $(PRODUCT_OUT)

include $(BUILD_EXECUTABLE)

endif # TARGET_PRODUCT salvator ulcb kingfisher
