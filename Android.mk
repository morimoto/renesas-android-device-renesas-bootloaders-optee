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

PRODUCT_OUT_ABS      := $(abspath $(PRODUCT_OUT))
OPTEE_SRC            := $(abspath ./device/renesas/bootloaders/optee)
OPTEE_OUT_DIR        := $(PRODUCT_OUT_ABS)/obj/OPTEE_OBJ

OPTEE_BUILD_FLAGS    := CFG_ARM64_core=y PLATFORM=rcar RMDIR=$(RMDIR) MAKEFLAGS=
OPTEE_BUILD_FLAGS    += CFLAGS="-march=armv8-a -mtune=cortex-a57.cortex-a53"

# Proper RMDIR definition for Android Q build environment
RMDIR                := "/bin/rmdir --ignore-fail-on-non-empty"
MAKE                 := `which make`
MKDIR                := `which mkdir`

.PHONY: optee-out-dir
optee-out-dir:
	$(MKDIR) -p $(OPTEE_OUT_DIR)

.PHONY: optee-android
optee-android: optee-out-dir
	@echo "Building OPTEE-ANDROID"
	$(hide) ARCH=arm $(MAKE) -e $(OPTEE_BUILD_FLAGS) -C $(OPTEE_SRC) O=$(OPTEE_OUT_DIR) CROSS_COMPILE64=$(BSP_GCC_CROSS_COMPILE) RMDIR=$(RMDIR) clean
	$(hide) ARCH=arm $(MAKE) -e $(OPTEE_BUILD_FLAGS) -C $(OPTEE_SRC) O=$(OPTEE_OUT_DIR) CROSS_COMPILE64=$(BSP_GCC_CROSS_COMPILE) all

.PHONY: tee.bin
tee.bin: optee-android
	cp $(OPTEE_OUT_DIR)/core/tee.bin $(PRODUCT_OUT_ABS)/tee.bin

.PHONY: tee_hf.bin
tee_hf.bin: optee-android
	cp $(OPTEE_OUT_DIR)/core/tee.bin $(PRODUCT_OUT_ABS)/tee_hf.bin

.PHONY: tee_hf.srec
tee_hf.srec: optee-android
	cp $(OPTEE_OUT_DIR)/core/tee.srec $(PRODUCT_OUT_ABS)/tee_hf.srec

endif # TARGET_PRODUCT salvator ulcb kingfisher
