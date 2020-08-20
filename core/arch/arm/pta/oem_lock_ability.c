/*
 * Copyright (C) 2019 GlobalLogic
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <kernel/pseudo_ta.h>
#include <tee/tee_svc_storage.h>
#include <tee/tee_pobj.h>
#include <crypto/crypto.h>
#include <tee_api_types.h>
#include <tee_api.h>
#include <trace.h>
#include <string.h>

#define TA_NAME		"oem_lock_ability.ta"
#define OEM_LOCK_ABILITY_UUID \
		{ 0xac6a5a79, 0x688d, 0x4ca7, \
			{ 0x8c, 0xbb, 0x5c, 0x13, 0x33, 0x6a, 0xb4, 0x31 } }

typedef enum {
	GET_OEM_UNLOCK_ALLOWED_BY_CARRIER = 0,
	SET_OEM_UNLOCK_ALLOWED_BY_CARRIER,
	GET_OEM_UNLOCK_ALLOWED_BY_DEVICE,
	SET_OEM_UNLOCK_ALLOWED_BY_DEVICE,
} oemlock_command_t;

/*
 * Trusted Application Entry Points
 */

/*
 * OemLock storage format:
 * [Version, 1 byte, must be 0x01 | Carrier lock bit, 1 byte, default 1 |
 * Device lock bit, 1 byte, default 1 | Padding, 1 byte, always 0 | Hash SHA-1]
 */

/*
 * OemLock storage object ID
 */
static uint8_t oemlock_id[] = { 0x11, 0xdb, 0x05, 0x9e };

#define OEMLOCK_STORAGE_SIZE		(24)
#define OEMLOCK_DATA_SIZE		(4)
#define OEMLOCK_HASH_SIZE		(20)

#define OEMLOCK_VERSION_OFFSET		(0)
#define OEMLOCK_CARRIER_OFFSET		(1)
#define OEMLOCK_DEVICE_OFFSET		(2)

#define OEMLOCK_VERSION			(1)
#define OEMLOCK_DEFAULT_CARRIER		(1)
#define OEMLOCK_DEFAULT_DEVICE		(1)

static TEE_Result get_payload_sha1(uint8_t *payload,
	uint32_t payload_size, uint8_t *sha1, uint32_t sha1_buf_size)
{
	void *ctx = NULL;
	TEE_Result res = TEE_SUCCESS;

	if (!payload || !sha1 || !payload_size || sha1_buf_size != OEMLOCK_HASH_SIZE)
		return TEE_ERROR_BAD_STATE;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA1);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate hash context, res = %x\n", res);
		return res;
	}

	res = crypto_hash_init(ctx, TEE_ALG_SHA1);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to init hash context, res = %x\n", res);
		crypto_hash_free_ctx(ctx, TEE_ALG_SHA1);
		return res;
	}

	res = crypto_hash_update(ctx, TEE_ALG_SHA1, payload,
		payload_size);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to update SHA-1 operation, res=0x%x\n", res);
		crypto_hash_free_ctx(ctx, TEE_ALG_SHA1);
		return res;
	}

	res = crypto_hash_final(ctx, TEE_ALG_SHA1, sha1, OEMLOCK_HASH_SIZE);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to final SHA-1 operation, res=0x%x\n", res);
	}

	crypto_hash_free_ctx(ctx, TEE_ALG_SHA1);
	return res;
}

static TEE_Result read_oem_lock_storage(uint8_t* carrier, uint8_t* device)
{
	TEE_Result res = TEE_SUCCESS;
	struct tee_file_handle *fh;
	uint64_t actual_read = OEMLOCK_STORAGE_SIZE;
	uint64_t file_size = OEMLOCK_STORAGE_SIZE;
	uint8_t oemlock_storage[OEMLOCK_STORAGE_SIZE] = { 0 };
	uint8_t sha1[OEMLOCK_HASH_SIZE] = { 0 };

	struct tee_pobj po = {
		.obj_id = (void *)oemlock_id,
		.obj_id_len = sizeof(oemlock_id),
		.flags = TEE_DATA_FLAG_ACCESS_READ,
		.uuid = OEM_LOCK_ABILITY_UUID,
	};

	po.fops = tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);

	if (!po.fops) {
		EMSG("Failed to get storage file ops\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	res = po.fops->open(&po, &file_size, &fh);
	if (res != TEE_SUCCESS)
		goto ret_res;

	res = po.fops->read(fh, 0, oemlock_storage, &actual_read);
	if (((res != TEE_SUCCESS) || (OEMLOCK_STORAGE_SIZE != actual_read))) {
		EMSG("Failed to read oem lock storage object, res=0x%x, read=%lu\n", res,
				actual_read);
		goto close_obj;
	}

	res = get_payload_sha1(oemlock_storage, OEMLOCK_DATA_SIZE,
		sha1, OEMLOCK_HASH_SIZE);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to obtain SHA-1 from the payload data, res = 0x%x\n", res);
		goto close_obj;
	}

	if (memcmp(sha1, &oemlock_storage[OEMLOCK_DATA_SIZE],
			OEMLOCK_HASH_SIZE) != 0) {
		res = TEE_ERROR_BAD_STATE;
		EMSG("Actual SHA-1 digest doesn't match the data\n");
		goto close_obj;
	}

	if (oemlock_storage[OEMLOCK_VERSION_OFFSET] != OEMLOCK_VERSION) {
		res = TEE_ERROR_BAD_STATE;
		EMSG("Version error oem lock storage object\n");
		goto close_obj;
	}

	if (carrier){
		*carrier = oemlock_storage[OEMLOCK_CARRIER_OFFSET];
	}
	if (device){
		*device = oemlock_storage[OEMLOCK_DEVICE_OFFSET];
	}

close_obj:
	po.fops->close(&fh);
ret_res:
	return res;
}

static TEE_Result write_oem_lock_storage(uint8_t* carrier, uint8_t* device)
{
	TEE_Result res = TEE_SUCCESS;
	struct tee_file_handle *fh;
	uint64_t actual_read = OEMLOCK_STORAGE_SIZE;
	uint64_t file_size = OEMLOCK_STORAGE_SIZE;
	uint8_t oemlock_storage[OEMLOCK_STORAGE_SIZE] = { 0 };
	uint8_t sha1[OEMLOCK_HASH_SIZE] = { 0 };

	struct tee_pobj po = {
		.obj_id = (void *)oemlock_id,
		.obj_id_len = sizeof(oemlock_id),
		.flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE,
		.uuid = OEM_LOCK_ABILITY_UUID,
	};

	po.fops = tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);

	if (!po.fops) {
		EMSG("Failed to get storage file ops\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	res = po.fops->open(&po, &file_size, &fh);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open OemLock storage object, res=0x%x\n", res);
		goto ret_res;
	}

	actual_read = OEMLOCK_STORAGE_SIZE;
	res = po.fops->read(fh, 0, oemlock_storage, &actual_read);
	if (((res != TEE_SUCCESS) || (OEMLOCK_STORAGE_SIZE != actual_read))) {
		EMSG("Failed to write OemLock storage object, res=0x%x, read=%lu\n", res,
				actual_read);
		goto close_obj;
	}

	if (carrier)
		oemlock_storage[OEMLOCK_CARRIER_OFFSET] = *carrier;

	if (device)
		oemlock_storage[OEMLOCK_DEVICE_OFFSET] = *device;

	res = get_payload_sha1(oemlock_storage, OEMLOCK_DATA_SIZE,
		sha1, OEMLOCK_HASH_SIZE);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to obtain sha1 from the payload data, res = 0x%x\n", res);
		goto close_obj;
	}

	memmove(&oemlock_storage[OEMLOCK_DATA_SIZE], sha1, OEMLOCK_HASH_SIZE);

	res = po.fops->write(fh, 0, oemlock_storage, OEMLOCK_STORAGE_SIZE);
	if (res != TEE_SUCCESS)
		EMSG("Failed to write oem lock storage object, res=0x%x\n", res);

close_obj:
	po.fops->close(&fh);
ret_res:
	return res;
}

/* Called each time a new instance is created */
static TEE_Result open_entry_point(uint32_t param_types,
			TEE_Param params[TEE_NUM_PARAMS] __unused, void **sess_ctx __unused)
{
	TEE_Result res = TEE_SUCCESS;
	struct tee_file_handle *fh;
	uint64_t file_size = OEMLOCK_STORAGE_SIZE;
	uint8_t oemlock_storage[OEMLOCK_STORAGE_SIZE] = { 0 };
	uint8_t sha1[OEMLOCK_HASH_SIZE] = { 0 };

	struct tee_pobj po = {
		.obj_id = (void *)oemlock_id,
		.obj_id_len = sizeof(oemlock_id),
		.flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE,
		.uuid = OEM_LOCK_ABILITY_UUID,
	};

	if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE) != param_types) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	po.fops = tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);

	if (!po.fops) {
		EMSG("Failed to get storage file ops\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	res = po.fops->open(&po, &file_size, &fh);
	/* Storage was initialized before */
	if (res == TEE_SUCCESS)
		return res;

	/* Error case */
	if (res != TEE_ERROR_ITEM_NOT_FOUND) {
		EMSG("Failed to open oem lock storage object, res=0x%x\n", res);
		return res;
	}

	/* If the item is not found, storage should be created before using */
	oemlock_storage[OEMLOCK_VERSION_OFFSET] = OEMLOCK_VERSION;
	oemlock_storage[OEMLOCK_CARRIER_OFFSET] = OEMLOCK_DEFAULT_CARRIER;
	oemlock_storage[OEMLOCK_DEVICE_OFFSET] = OEMLOCK_DEFAULT_DEVICE;

	res = get_payload_sha1(oemlock_storage, OEMLOCK_DATA_SIZE,
		sha1, OEMLOCK_HASH_SIZE);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to obtain sha1 from the payload data, res = 0x%x\n", res);
		return res;
	}

	memmove(&oemlock_storage[OEMLOCK_DATA_SIZE], sha1, OEMLOCK_HASH_SIZE);

	res = po.fops->create(&po, false, NULL, 0, NULL, 0,
		oemlock_storage, OEMLOCK_STORAGE_SIZE, &fh);

	if (res != TEE_SUCCESS)
		EMSG("Failed to create oem lock storage object, res=0x%x\n", res);
	else
		po.fops->close(&fh);

	return res;
}

/* Called when a command is invoked */
static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t carrier = 0;
	uint8_t device = 0;

	if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE) != param_types) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch (cmd_id) {
	case GET_OEM_UNLOCK_ALLOWED_BY_CARRIER:
		res = read_oem_lock_storage(&carrier, NULL);
		if (res == TEE_SUCCESS) {
			params[0].value.a = carrier;
		} else {
			EMSG("Failed to get OEM lock allowed by the carrier, res=0x%x\n", res);
		}
		break;
	case SET_OEM_UNLOCK_ALLOWED_BY_CARRIER:
		carrier = params[0].value.a;
		res = write_oem_lock_storage(&carrier, NULL);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to set OEM lock allowed by the carrier, res=0x%x\n", res);
		}
		break;
	case GET_OEM_UNLOCK_ALLOWED_BY_DEVICE:
		res = read_oem_lock_storage(NULL, &device);
		if (res == TEE_SUCCESS) {
			params[0].value.a = device;
		} else {
			EMSG("Failed to get OEM lock allowed by the device, res=0x%x\n", res);
		}
		break;
	case SET_OEM_UNLOCK_ALLOWED_BY_DEVICE:
		device = params[0].value.a;
		res = write_oem_lock_storage(NULL, &device);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to set OEM lock allowed by the device, res=0x%x\n", res);
		}
		break;

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return res;
}

pseudo_ta_register(.uuid = OEM_LOCK_ABILITY_UUID, .name = TA_NAME,
		.flags = PTA_DEFAULT_FLAGS,
		.open_session_entry_point = open_entry_point,
		.invoke_command_entry_point = invoke_command);