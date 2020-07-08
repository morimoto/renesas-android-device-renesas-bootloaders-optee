subdirs-$(CFG_TEE_CORE_EMBED_INTERNAL_TESTS) += tests

srcs-$(CFG_TEE_BENCHMARK) += benchmark.c
srcs-$(CFG_DEVICE_ENUM_PTA) += device.c
srcs-$(CFG_TA_GPROF_SUPPORT) += gprof.c
srcs-$(CFG_SDP_PTA) += sdp.c
ifeq ($(CFG_WITH_USER_TA),y)
srcs-$(CFG_SECSTOR_TA_MGMT_PTA) += secstor_ta_mgmt.c
endif
srcs-$(CFG_WITH_STATS) += stats.c
srcs-$(CFG_SYSTEM_PTA) += system.c

subdirs-y += bcm

cppflags-hyper_ta.c-y += -Ilib/libzlib/include
cppflags-asn1_parser.c-y += -Ilib/libmpa/include

srcs-y += rng_entropy.c
srcs-y += hyper_ta.c
srcs-y += asn1_parser.c
srcs-y += attestations.c
srcs-y += encoders.c
srcs-y += oem_lock_ability.c

subdirs-y +=../../lib/libzlib
subdirs-y +=../../lib/libmpa
