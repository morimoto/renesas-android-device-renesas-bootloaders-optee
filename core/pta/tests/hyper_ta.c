/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2016 GlobalLogic
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <compiler.h>
#include <stdio.h>
#include <trace.h>
#include <kernel/pseudo_ta.h>
#include <mm/tee_pager.h>
#include <mm/tee_mm.h>
#include <string.h>
#include <string_ext.h>
#include <malloc.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include <drivers/qspi_hyper_flash.h>
#include <zlib.h>
#include <tee/tee_fs.h>
#include <tee/tee_standalone_fs.h>

#define TA_NAME		"hyper.ta"

/*TODO This is manually created uuid. Has to be replaced with UUID from
 *  http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define HYPER_UUID \
		{ 0xd96a5b40, 0xe2c7, 0xb1af, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc7, 0x1f } }

#define HYPER_CMD_INIT_DRV		0
#define HYPER_CMD_READ			1
#define HYPER_CMD_WRITE			2
#define HYPER_CMD_ERASE			3

struct img_param {
	const char *img_name;
	uint32_t flash_addr;
	uint32_t max_size;
};

/*We can flash 7 images*/
#define MAX_IMAGES 7

/*Set legal address and maximum size for every image*/
static const struct img_param img_params[MAX_IMAGES] = {
			{"Boot_params", 0, 1*SECTOR_SIZE},
			{"BL2", 0x40000, 1*SECTOR_SIZE},
			{"Cert_header", 0x180000, 1*SECTOR_SIZE},
			{"BL31", 0x1C0000, 1*SECTOR_SIZE},
			{"OPTEE-OS", 0x200000, 2*SECTOR_SIZE},
			{"U-boot", 0x640000, 4*SECTOR_SIZE},
			{"Secure_store", STANDALONE_FS_SECTOR_ADDR,
				STANDALONE_FS_SECTOR_NUM*SECTOR_SIZE} };


/*This is called separately for reading*/
static TEE_Result init_hyper_drv(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
			    TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE) != type) {
		EMSG("expect 1 output value as argument");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	p[0].value.a = qspi_hyper_flash_init();
	if (p[0].value.a == FL_DRV_OK) {
		return TEE_SUCCESS;
	} else
		return TEE_ERROR_GENERIC;
}



/*Dumps data from hyperflash (up to 1 sector)*/
/*INPUT - From CA(REE) to TA(TEE)*/
/*OUTPUT - From TA(TEE) to CA(REE)*/
/*(p[0].value.a - Flash Read Address */
/*(p[0].value.b - Read Data Size (0..SECTOR_SIZE) */

static TEE_Result read_hyper_drv(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	uint32_t ret;

	if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
			    TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_MEMREF_OUTPUT) != type) {
		EMSG("expect 1 input value as argument and 1 as mem out");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*Add check for buffer size*/
	if (p[0].value.b > SECTOR_SIZE) {
		EMSG("Max buffer size exceeded");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = qspi_hyper_flash_read(p[0].value.a,
		    p[3].memref.buffer, p[0].value.b);
	if (ret == FL_DRV_OK) {
		return TEE_SUCCESS;
	} else
		return TEE_ERROR_GENERIC;
}

/*(p[0].value.a - Write Address */
/*(p[0].value.b - Write Data Size */
/*(p[1].value.a - CRC32 CheckSum of the block */
/*(p[1].value.b - Boot Image Type */

#define IMAGE_VERIFY_ON
static TEE_Result write_hyper_drv(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	uint32_t i, ret;
	uint32_t crc_orig = p[1].value.a, crc = crc32(0L, Z_NULL, 0);
	uint8_t *buf = (uint8_t *)p[3].memref.buffer;
	uint32_t len = p[0].value.b, count;
	uint32_t addr = p[0].value.a;
	uint32_t sectors = len / SECTOR_SIZE;
	const char *image;

	if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
			    TEE_PARAM_TYPE_VALUE_INPUT,
			    TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_MEMREF_INOUT) != type) {
		EMSG("Parameters check error\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (p[1].value.b >= MAX_IMAGES) {
		EMSG("Image type error (%d)\n", p[1].value.b);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	image = img_params[p[1].value.b].img_name;

	if ((addr != img_params[p[1].value.b].flash_addr) ||
		(len > img_params[p[1].value.b].max_size)) {
		EMSG("Image %s flash parameter error (addr = 0x%x, len = %d)\n",
			image, addr, len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	crc = crc32(crc, buf, len);
	DMSG("CRC = 0x%x\n", crc);
	if (crc != crc_orig) {
		EMSG("CRC check error (0x%x != 0x%x\n)", crc, crc_orig);
		return TEE_ERROR_SIGNATURE_INVALID;
	}

	if (len % SECTOR_SIZE) {
		sectors++;
	}
	ret = qspi_hyper_flash_init();
	if (ret != FL_DRV_OK) {
		return TEE_ERROR_GENERIC;
	}
	DMSG("Image: %s, sectors = %d\n", image, sectors);

	for (i = 0; i < sectors; i++) {
		ret = qspi_hyper_flash_erase(addr);
		if (ret == FL_DRV_OK) {
			count = len > SECTOR_SIZE ? SECTOR_SIZE : len;
			ret = qspi_hyper_flash_write(addr, buf, count);
			if (ret != FL_DRV_OK) {
				break;
			}
		} else
			break;
		addr += count;
		buf += count;
		len -= count;
	}

	if (ret != FL_DRV_OK) {
		EMSG("Image writing Error(%d)", ret);
		return ret;
	}

#ifdef IMAGE_VERIFY_ON
	/*Verification is done by checking CRC.
	* Apart from that, image read from HyperFlash
	* is written back to the shared buffer and
	* can be additionally checked by CA.
	*/
	buf = p[3].memref.buffer;
	len = p[0].value.b;
	addr = p[0].value.a;
	memset(buf, 0, len);
	crc = crc32(0L, Z_NULL, 0);
	for (i = 0; i < sectors; i++) {
		count = len > SECTOR_SIZE ? SECTOR_SIZE : len;
		ret = qspi_hyper_flash_read(addr, buf, count);
		if (ret != FL_DRV_OK) {
			break;
		}
		addr += count;
		buf += count;
		len -= count;
	}
	crc = crc32(crc, p[3].memref.buffer, p[0].value.b);
	if (crc != crc_orig) {
		EMSG("Image verification failed! CRC error (0x%x != 0x%x)"
			, crc, crc_orig);
		return TEE_ERROR_GENERIC;
	}
#endif
	DMSG("%s Image updated successfully\n", image);
	return TEE_SUCCESS;

}

static TEE_Result erase_hyper_drv(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	uint32_t i, ret;
	uint32_t len = p[0].value.b, count;
	uint32_t addr = p[0].value.a;
	uint32_t sectors = len / SECTOR_SIZE;
	const char *image;

	if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
			    TEE_PARAM_TYPE_VALUE_INPUT,
			    TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE) != type) {
		EMSG("Parameters check error\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (p[1].value.b >= MAX_IMAGES) {
		EMSG("Image type error (%d)\n", p[1].value.b);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	image = img_params[p[1].value.b].img_name;

	if ((addr != img_params[p[1].value.b].flash_addr) ||
		(len > img_params[p[1].value.b].max_size)) {
		EMSG("Image %s flash parameter error (addr = 0x%x(0x%x), len = %d(%d))\n",
			image, addr, img_params[p[1].value.b].flash_addr, len, img_params[p[1].value.b].max_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (len % SECTOR_SIZE) {
		sectors++;
	}

	ret = qspi_hyper_flash_init();
	if (ret != FL_DRV_OK)
		return TEE_ERROR_GENERIC;

	for (i = 0; i < sectors; i++) {
		ret = qspi_hyper_flash_erase(addr);
		if (ret == FL_DRV_OK) {
			count = len > SECTOR_SIZE ? SECTOR_SIZE : len;
		} else {
			EMSG("Image writing Error(%d)", ret);
			return ret;
		}
		addr += count;
		len -= count;
	}

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *psess __unused,
				 uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case HYPER_CMD_INIT_DRV:
		return init_hyper_drv(ptypes, params);
	case HYPER_CMD_READ:
		return read_hyper_drv(ptypes, params);
	case HYPER_CMD_WRITE:
		return write_hyper_drv(ptypes, params);
	case HYPER_CMD_ERASE:
		return erase_hyper_drv(ptypes, params);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}
pseudo_ta_register(.uuid = HYPER_UUID, .name = TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);

