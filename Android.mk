#
# Copyright (C) 2019 The Android Open-Source Project
# Copyright (C) 2019 GlobalLogic
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

OPTEE_SRC            := $(abspath ./device/renesas/bootloaders/optee)
OPTEE_OBJ            := $(PRODUCT_OUT)/obj/OPTEE_OBJ
OPTEE_BINARY         := $(OPTEE_OBJ)/core/tee.bin
OPTEE_SREC           := $(OPTEE_OBJ)/core/tee.srec
OPTEE_OUT_DIR        := $(abspath $(OPTEE_OBJ))
OPTEE_BUILD_FLAGS    := CFG_ARM64_core=y PLATFORM=rcar RMDIR=$(RMDIR) MAKEFLAGS=
OPTEE_BUILD_FLAGS    += CFLAGS="-march=armv8-a -mtune=cortex-a57.cortex-a53"

# Proper RMDIR definition for Android Q build environment
RMDIR                := "/bin/rmdir --ignore-fail-on-non-empty"
MKDIR                := /bin/mkdir

#.PHONY: $(OPTEE_BINARY)
$(OPTEE_BINARY):
	@echo "Building OPTEE-ANDROID"
	$(MKDIR) -p $(OPTEE_OUT_DIR)
	$(hide) ARCH=arm $(ANDROID_MAKE) -e $(OPTEE_BUILD_FLAGS) -C $(OPTEE_SRC) O=$(OPTEE_OUT_DIR) CROSS_COMPILE64=$(BSP_GCC_CROSS_COMPILE) RMDIR=$(RMDIR) clean
	$(hide) ARCH=arm $(ANDROID_MAKE) -e $(OPTEE_BUILD_FLAGS) -C $(OPTEE_SRC) O=$(OPTEE_OUT_DIR) CROSS_COMPILE64=$(BSP_GCC_CROSS_COMPILE) all

$(OPTEE_SREC): $(OPTEE_BINARY)

include $(CLEAR_VARS)
LOCAL_MODULE                := tee.bin
LOCAL_PREBUILT_MODULE_FILE  := $(OPTEE_BINARY)
LOCAL_MODULE_PATH           := $(PRODUCT_OUT)
LOCAL_MODULE_CLASS          := FIRMWARE
include $(BUILD_PREBUILT)

$(LOCAL_BUILT_MODULE): $(OPTEE_BINARY)

include $(CLEAR_VARS)
LOCAL_MODULE                := tee.srec
LOCAL_PREBUILT_MODULE_FILE  := $(OPTEE_SREC)
LOCAL_MODULE_PATH           := $(PRODUCT_OUT)
LOCAL_MODULE_CLASS          := FIRMWARE
include $(BUILD_PREBUILT)

$(LOCAL_BUILT_MODULE): $(OPTEE_SREC)

endif # TARGET_PRODUCT salvator ulcb kingfisher
