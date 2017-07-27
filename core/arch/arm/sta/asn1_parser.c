/*
 * Copyright (c) 2017 GlobalLogic
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

#include <kernel/static_ta.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include <tomcrypt.h>
#include <trace.h>
#include <tee/tee_cryp_provider.h>
#include "mpa.h"

#define TA_NAME		"asn1_parser.ta"

#define ASN1_PARSER_UUID \
		{ 0x273fcb14, 0xe831, 0x4cf2, \
			{ 0x93, 0xc4, 0x76, 0x15, 0xdb, 0xd3, 0x0e, 0x90 } }

#define ATTR_COUNT_RSA 8
#define ATTR_COUNT_EC 3
#define MAX_OCTET_COUNT 10

#define ALGORITHM_RSA 1
#define ALGORITHM_EC 3

#define KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM -19
#define KM_ERROR_MEMORY_ALLOCATION_FAILED -41
#define KM_ERROR_INVALID_ARGUMENT -38
#define KM_ERROR_UNIMPLEMENTED -100
#define KM_ERROR_UNKNOWN_ERROR -1000

#define CMD_PARSE 0
#define CMD_X509_ENCODE 1
#define CMD_EC_SIGN_ENCODE 2
#define CMD_EC_SIGN_DECODE 3

#define MAX_HEADER_SIZE 4
#define CODE_SEQUENCE 0x30
#define CODE_SET 0x31
#define LONG_MASK 0x80
#define EDGE_SHORT 128
#define MAX_OID_SIZE 32

#define EC_KEY_SIZE_NIST_224 224
#define EC_KEY_SIZE_NIST_256 256
#define EC_KEY_SIZE_NIST_384 384
#define EC_KEY_SIZE_NIST_521 521

struct import_data_t {
	uint64_t obj_ident1[MAX_OCTET_COUNT];
	uint64_t obj_ident2[MAX_OCTET_COUNT];
	uint32_t obj1_length;
	uint32_t obj2_length;
	uint8_t *octet_str_data;
	unsigned long octet_str_length;
};

struct blob {
	uint8_t *data;
	size_t data_length;
};

struct bignum {
	uint32_t alloc;
	int32_t size;
	uint32_t d[];
};

uint64_t const identifier_rsa[] = {1, 2, 840, 113549, 1, 1, 1};
/* RSAPrivateKey ::= SEQUENCE {
 *    version Version,
 *    modulus INTEGER, -- n
 *    publicExponent INTEGER, -- e
 *    privateExponent INTEGER, -- d
 *    prime1 INTEGER, -- p
 *    prime2 INTEGER, -- q
 *    exponent1 INTEGER, -- d mod (p-1)
 *    exponent2 INTEGER, -- d mod (q-1)
 *    coefficient INTEGER -- (inverse of q) mod p }
 */

uint64_t const identifier_ec[] = {1, 2, 840, 10045, 2, 1};
/* ECPrivateKey ::= SEQUNCE {
 *    version Version,
 *    secretValue OCTET_STRING,
 *    publicValue CONSTRUCTED {
 *        XYValue BIT_STRING } }
 */

static const uint32_t identifier_rsa_c = 7;
static const uint32_t identifier_ec_c = 6;
/* EC second OID */
static const uint64_t oid_ec2_224[] = {1, 3, 132, 0, 33};/* secp224r1 */
static const uint64_t oid_ec2_256[] = {1, 2, 840, 10045, 3, 1, 7};/* prime256v1 */
static const uint64_t oid_ec2_384[] = {1, 3, 132, 0, 34};/* secp384r1 */
static const uint64_t oid_ec2_521[] = {1, 3, 132, 0, 35};/* secp521r1 */
static const uint32_t oid_ec2_c = 5;
static const uint32_t oid_ec2_prime_c = 7;

static int TA_iterate_asn1_list(ltc_asn1_list *list,
				const uint32_t level,
				struct import_data_t *imp_data)
{
	int res = CRYPT_OK;
	uint8_t *data = NULL;

	while (list != NULL) {
		switch (list->type) {
		case LTC_ASN1_SEQUENCE:
			res = TA_iterate_asn1_list(list->child,
						level + 1, imp_data);
			if (res != CRYPT_OK)
				goto out;
			break;
		case LTC_ASN1_OBJECT_IDENTIFIER:
			if (level != 2 || (imp_data->obj1_length != 0
						&& imp_data->obj2_length != 0))
				break;
			if (imp_data->obj1_length == 0) {
				memcpy(imp_data->obj_ident1, list->data,
						list->size * sizeof(uint64_t));
				imp_data->obj1_length = list->size;
			} else {
				memcpy(imp_data->obj_ident2, list->data,
						list->size * sizeof(uint64_t));
				imp_data->obj2_length = list->size;
			}
			break;
		case LTC_ASN1_OCTET_STRING:
			if (level != 1 || imp_data->octet_str_data != NULL)
				break;
			data = malloc(list->size);
			if (!data) {
				res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
				EMSG("Failed to allocate memory for octet string buffer");
				goto out;
			}
			memcpy(data, list->data, list->size);
			imp_data->octet_str_data = data;
			imp_data->octet_str_length = list->size;
			break;
		default:
			break;
		}
		list = list->next;
	}
out:
	return res;
}

static int TA_check_object_identifier(const struct import_data_t *imp_data,
						const uint32_t algorithm,
						uint32_t *key_size)
{
	int32_t cmp_res = 0;
	const uint64_t *exp_ident = NULL;

	if (imp_data->obj1_length == 0) {
		EMSG("Object identifier of imported key is empty");
		return KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM;
	}
	if (algorithm == ALGORITHM_RSA) {
		exp_ident = identifier_rsa;
	} else {
		exp_ident = identifier_ec;
	}

	cmp_res = memcmp(exp_ident, imp_data->obj_ident1,
				imp_data->obj1_length * sizeof(uint64_t));
	if (cmp_res != 0) {
		EMSG("First Object Identifier is not match expected one");
		return KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM;
	}
	if (algorithm == ALGORITHM_RSA)
		return CRYPT_OK;
	/* Check second object identifier only for EC */
	if (imp_data->obj2_length == 0) {
		EMSG("Second Object Identifier of imported key is empty");
		return KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM;
	}
	if (!memcmp(oid_ec2_224, imp_data->obj_ident2,
			imp_data->obj2_length * sizeof(uint64_t))) {
		*key_size = EC_KEY_SIZE_NIST_224;
	} else if (!memcmp(oid_ec2_256, imp_data->obj_ident2,
			imp_data->obj2_length * sizeof(uint64_t))) {
		*key_size = EC_KEY_SIZE_NIST_256;
	} else if (!memcmp(oid_ec2_384, imp_data->obj_ident2,
			imp_data->obj2_length * sizeof(uint64_t))) {
		*key_size = EC_KEY_SIZE_NIST_384;
	} else if (!memcmp(oid_ec2_521, imp_data->obj_ident2,
			imp_data->obj2_length * sizeof(uint64_t))) {
		*key_size = EC_KEY_SIZE_NIST_521;
	} else {
		EMSG("Unexpected value fo the second EC Object Identifier");
		return KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM;
	}
	return CRYPT_OK;
}

static int TA_bits_to_bytes(struct blob *point,
				const ltc_asn1_list *list)
{
	int res = CRYPT_OK;
	uint32_t pi = 0;
	uint8_t *data = (uint8_t *) list->data;

	point->data_length = list->size / 8;
	point->data = malloc(point->data_length);
	if (!point->data) {
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		EMSG("Failed to allocate memory for bytes converted from bits");
		goto out;
	}
	for (size_t i = 0; i < list->size; i++) {
		pi = i / 8;
		point->data[pi] = (point->data[pi] << 1) | data[i];
	}
out:
	return res;
}

static int TA_push_to_output(uint8_t *output,
			const uint8_t *input,
			const uint32_t size)
{
	uint32_t offset = 0;

	memcpy(output + offset, &size, sizeof(size));
	offset += sizeof(size);
	memcpy(output + offset, input, size);
	offset += size;
	return offset;
}

static int getBuffer(const uint32_t size, uint8_t **buffer) {
	if (!(*buffer)) {
		*buffer = malloc(size);
		if (!(*buffer)) {
			EMSG("Failed to allocate memory for BN buffer");
			return KM_ERROR_MEMORY_ALLOCATION_FAILED;
		}
	}
	return CRYPT_OK;
}

static int TA_iterate_asn1_attrs(const ltc_asn1_list *list,
				const uint32_t level,
				uint32_t *attrs_count,
				const uint32_t algorithm,
				uint8_t *output,
				uint32_t *output_size,
				uint32_t *key_size)
{
	int res = CRYPT_OK;
	struct bignum *nummpa = NULL;
	struct blob point = {
			.data = NULL,
			.data_length = 0};
	uint32_t attr_size = 0;
	uint32_t pad = 0;
	uint32_t offset = *output_size;
	uint8_t *buf = NULL;

	while (list != NULL) {
		switch (list->type) {
		case LTC_ASN1_CONSTRUCTED:
		case LTC_ASN1_SEQUENCE:
			res = TA_iterate_asn1_attrs(list->child,
					level + 1, attrs_count, algorithm,
					output, &offset, key_size);
			if (res != CRYPT_OK)
				goto out;
			break;
		case LTC_ASN1_INTEGER:
			nummpa = list->data;
			if (nummpa->size == 0 || algorithm != ALGORITHM_RSA
				|| *attrs_count > ATTR_COUNT_RSA)
				break;
			attr_size = crypto_ops.bignum.num_bytes(nummpa);
			res = getBuffer(attr_size, &buf);
			if (res != CRYPT_OK)
				goto out;
			crypto_ops.bignum.bn2bin(nummpa, buf);
			offset += TA_push_to_output(output + offset,
					buf, attr_size);
			if (*attrs_count == 0)
				*key_size = attr_size * 8;
			(*attrs_count)++;
			break;
		case LTC_ASN1_OCTET_STRING:
			if (algorithm != ALGORITHM_EC ||
						*attrs_count > ATTR_COUNT_EC)
				break;
			attr_size = list->size;
			offset += TA_push_to_output(output + offset,
							list->data, attr_size);
			(*attrs_count)++;
			break;
		case LTC_ASN1_BIT_STRING:
			if (algorithm != ALGORITHM_EC ||
						*attrs_count > ATTR_COUNT_EC)
				break;
			res = TA_bits_to_bytes(&point, list);
			if (res != CRYPT_OK)
				goto out;
			if (point.data[0] != 0x04) {
				/* Point is not in uncompressed form*/
				res = KM_ERROR_INVALID_ARGUMENT;
				EMSG("Imported EC point is not uncompressed");
				goto out;
			}
			/* First byte is not part of
			 * X and Y values - ignore it
			 */
			pad += 1;
			attr_size = (point.data_length - pad) / 2;
			offset += TA_push_to_output(output + offset,
						point.data + pad, attr_size);
			pad += attr_size;
			(*attrs_count)++;
			offset += TA_push_to_output(output + offset,
						point.data + pad, attr_size);
			(*attrs_count)++;
			break;
		default:
			break;
		}
		list = list->next;
	}
out:
	*output_size = offset;
	if (point.data)
		free(point.data);
	if (buf)
		free(buf);
	return res;
}

/*
 * INPUT
 * params[0].memref.buffer - key asn1 data to parse
 * params[0].memref.size - size of data to parse
 * params[1].value.a - algorithm
 *
 * OUTPUT
 * params[2].memref.buffer - parse result array
 * params[2].memref.size - parse result size
 * params[3].value.a - key size
 */
static TEE_Result TA_parse_asn1(uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_VALUE_INPUT,
					TEE_PARAM_TYPE_MEMREF_OUTPUT,
					TEE_PARAM_TYPE_VALUE_OUTPUT);
	unsigned long res = CRYPT_OK;
	ltc_asn1_list *list_root = NULL;
	struct import_data_t imp_data = {
				.obj1_length = 0,
				.obj2_length = 0,
				.octet_str_length = 0,
				.octet_str_data = NULL,};
	unsigned char *output = params[2].memref.buffer;
	uint32_t *output_size = &params[2].memref.size;
	unsigned char *data = (unsigned char *) params[0].memref.buffer;
	unsigned long size = params[0].memref.size;
	uint32_t algorithm = params[1].value.a;
	uint32_t attrs_count = 0;
	uint32_t *key_size = &params[3].value.a;

	if (ptypes != exp_param_types) {
		EMSG("Wrong parameters\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	*output_size = 0;
	*key_size = 0;
	res = der_decode_sequence_flexi(data, &size, &list_root);
	if (res != CRYPT_OK) {
		EMSG("Failed to decode asn1 list");
		goto out;
	}
	res = TA_iterate_asn1_list(list_root, 0, &imp_data);
	if (res != CRYPT_OK) {
		EMSG("Root iteration failed");
		goto out;
	}
	res = TA_check_object_identifier(&imp_data, algorithm, key_size);
	if (res != CRYPT_OK)
		goto out;
	if (imp_data.octet_str_data == NULL ||
				imp_data.octet_str_length == 0) {
		EMSG("Octet string is empty");
		res = KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM;
		goto out;
	}
	der_sequence_free(list_root);
	res = der_decode_sequence_flexi(imp_data.octet_str_data,
				&imp_data.octet_str_length, &list_root);
	if (res != CRYPT_OK) {
		EMSG("Failed to decode attributes with code %lx", res);
		res = KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM;
		goto out;
	}
	res = TA_iterate_asn1_attrs(list_root, 0,
				&attrs_count, algorithm,
				output, output_size, key_size);
out:
	der_sequence_free(list_root);
	if (imp_data.octet_str_data)
		free(imp_data.octet_str_data);
	return res;
}

static int wrap(uint8_t *out, uint64_t *out_l, const uint8_t *in,
		const uint64_t in_l, const uint32_t code)
{
	int res = CRYPT_OK;
	uint32_t length_bytes = 0;
	uint32_t pos = 0;
	uint64_t remainder = in_l;

	if (*out_l < in_l + MAX_HEADER_SIZE) {
		res = KM_ERROR_UNKNOWN_ERROR;
		EMSG("Output buffer is to small to do wrap");
		goto out;
	}
	if (in_l > EDGE_SHORT) {
	/* check if input length requered additinal bytes for size */
		do {
			length_bytes++;
			remainder >>= 8;
		} while (remainder > 0);
	}
	out[pos++] = code;/* write type */
	if (length_bytes > 0) {
		/* mark that size is more than 128 */
		out[pos++] = LONG_MASK | length_bytes;
	} else {
		length_bytes++;/* at least one byte for size */
	}
	while (length_bytes > 0) {
		length_bytes--;
		remainder = in_l >> (8 * length_bytes);
		out[pos] = remainder & 0xff;
		pos++;
	}
	memcpy(out + pos, in, in_l);
	pos += in_l;
out:
	*out_l = pos;
	return res;
}

static int add_obj_ident_in_seq(uint8_t *out, uint64_t *out_l,
				const uint64_t *oid, const uint64_t oid_l,
				const uint8_t *second, const uint32_t second_l,
				const uint32_t second_type)
{
	int res = CRYPT_OK;
	uint8_t out_buf[*out_l];
	uint64_t out_buf_l = *out_l;

	if (!second || second_l == 0 || second_type == 0) {
		res = der_encode_sequence_multi(out_buf, &out_buf_l,
				LTC_ASN1_OBJECT_IDENTIFIER, oid_l, oid,
				LTC_ASN1_NULL, 1UL, NULL,
				LTC_ASN1_EOL, 0UL, NULL);
	} else {
		res = der_encode_sequence_multi(out_buf, &out_buf_l,
				LTC_ASN1_OBJECT_IDENTIFIER, oid_l, oid,
				second_type, second_l, second,
				LTC_ASN1_EOL, 0UL, NULL);
	}
	if (res != CRYPT_OK) {
		EMSG("failed to encode sequence res = %x", res);
		goto out;
	}
	memcpy(out, out_buf, out_buf_l);
	*out_l = out_buf_l;
out:
	return res;
}

static int encode_params(uint8_t **params_buf, uint64_t *params_buf_l,
			const uint32_t type, const uint8_t *attr1,
			const uint32_t attr1_l, const uint8_t *attr2,
			const uint32_t attr2_l, const uint32_t key_size)
{
	int res = CRYPT_OK;
	struct bignum *num_attr1 = NULL;
	uint8_t *out_buf = NULL;
	uint64_t out_buf_l = 0;
	uint32_t offset = 0;
	uint64_t rsa_pe = 0;
	/* rounded up the bytes count */
	uint32_t key_size_bytes = (key_size + 7) / 8;

	if (type == TEE_TYPE_RSA_KEYPAIR) {
		num_attr1 = malloc(sizeof(struct bignum) +
					BYTES_PER_WORD + attr1_l);
		if (!num_attr1) {
			EMSG("Failed to allocate memory for number of attr 1");
			res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			goto out;
		}
		num_attr1->alloc = sizeof(struct bignum) +
						BYTES_PER_WORD + attr1_l;
		res = crypto_ops.bignum.bin2bn(attr1, attr1_l, num_attr1);
		if (res != CRYPT_OK) {
			EMSG("Failed to convert bin to BN");
			goto out;
		}
		memcpy(&rsa_pe, attr2, attr2_l);

		/* Note: 3 headers are: INTEGRE, INTEGER, SEQUENCE */
		out_buf_l = attr1_l + attr2_l + 3 * MAX_HEADER_SIZE;
		out_buf = malloc(out_buf_l);
		if (!out_buf) {
			EMSG("Failed to allocate memory for params buffer");
			res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			goto out;
		}
		res = der_encode_sequence_multi(out_buf, &out_buf_l,
					LTC_ASN1_INTEGER, 1UL, num_attr1,
					LTC_ASN1_SHORT_INTEGER, 1UL, &rsa_pe,
					LTC_ASN1_EOL, 0UL, NULL);
		if (res != CRYPT_OK) {
			EMSG("Failed to encode RSA params res = %x", res);
			goto out;
		}
	} else {
		/* each EC key attribute must to be as long as
		 * key size in bytes and 1 byte - is for additional byte
		 */
		out_buf_l = key_size_bytes * 2 + 1;
		out_buf = malloc(out_buf_l);
		if (!out_buf) {
			EMSG("Failed to allocate memory for params buffer");
			res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			goto out;
		}
		memset(out_buf, 0, out_buf_l);
		/* the first byte must be equal to 0x04 - not compressed */
		out_buf[0] = 0x04;
		offset += 1;
		/* if attribute size is less then key
		 * size - left first bits equal to 0
		 */
		memcpy(out_buf + offset + (key_size_bytes - attr1_l),
							attr1, attr1_l);
		offset += key_size_bytes;
		memcpy(out_buf + offset + (key_size_bytes - attr2_l),
							attr2, attr2_l);
		offset += key_size_bytes;
	}
	/* 2 additional bytes of bit string */
	*params_buf_l = out_buf_l + MAX_HEADER_SIZE + 2;
	*params_buf = malloc(*params_buf_l);
	if (!(*params_buf)) {
		EMSG("Failed to allocate memory for key params");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	res = der_encode_raw_bit_string(out_buf, out_buf_l * 8,
						*params_buf, params_buf_l);
	if (res != CRYPT_OK) {
		EMSG("Failed to encode bit string res = %x", res);
		goto out;
	}
out:
	if (num_attr1)
		free(num_attr1);
	if (out_buf)
		free(out_buf);
	return res;
}

/*
 * INPUT
 * params[0].memref.buffer - first public key attribute
 * params[0].memref.size - first public key attribute size
 * params[1].memref.buffer - second public key attribute
 * params[1].memref.size - second public key attribute size
 * params[2].value.a - type
 * params[2].value.b - key_size
 *
 * OUTPUT
 * params[3].memref.buffer - x.509 certificate
 * params[3].memref.size - x.509 certificate size
 */
static TEE_Result TA_x509_encode(uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_VALUE_INPUT,
					TEE_PARAM_TYPE_MEMREF_OUTPUT);
	unsigned long res = CRYPT_OK;
	uint32_t type = params[2].value.a;
	uint32_t key_size = params[2].value.b;
	unsigned char *output = params[3].memref.buffer;
	uint64_t output_size = params[3].memref.size;
	uint32_t attr1_l = params[0].memref.size;
	uint32_t attr2_l = params[1].memref.size;
	uint8_t *attr1 = params[0].memref.buffer;
	uint8_t *attr2 = params[1].memref.buffer;
	const uint64_t *oid1 = NULL;
	const uint64_t *oid2 = NULL;
	uint64_t oid1_c = 0;
	uint64_t oid2_c = 0;
	uint64_t params_buf_l = 0;
	uint8_t *params_buf = NULL;
	uint64_t oid_buf_l = MAX_OID_SIZE;
	uint8_t *oid_buf = NULL;
	uint8_t *out_buf = NULL;
	uint64_t out_buf_l = 0;

	if (ptypes != exp_param_types) {
		EMSG("Wrong parameters\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (type == TEE_TYPE_RSA_KEYPAIR) {
		oid1 = identifier_rsa;
		oid1_c = identifier_rsa_c;
	} else {
		oid1 = identifier_ec;
		oid1_c = identifier_ec_c;
		switch (key_size) {
		case EC_KEY_SIZE_NIST_224:
			/* 1.3.132.0.33 secp224r1 */
			oid2 = oid_ec2_224;
			oid2_c = oid_ec2_c;
			break;
		case EC_KEY_SIZE_NIST_256:
			/* 1.2.840.10045.3.1.7 prime256v1 */
			oid2 = oid_ec2_256;
			oid2_c = oid_ec2_prime_c;
			break;
		case EC_KEY_SIZE_NIST_384:
			/* 1.3.132.0.34 secp384r1 */
			oid2 = oid_ec2_384;
			oid2_c = oid_ec2_c;
			break;
		case EC_KEY_SIZE_NIST_521:
			/* 1.3.132.0.35 secp521r1 */
			oid2 = oid_ec2_521;
			oid2_c = oid_ec2_c;
			break;
		default:
			EMSG("Fialed to determine OID for EC key with size %u",
								key_size);
			res = KM_ERROR_UNIMPLEMENTED;
			goto out;
		}
	}
	oid_buf = malloc(oid_buf_l);
	if (!oid_buf) {
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		EMSG("Failed to allocate memory for OID buffer");
		goto out;
	}
	res = add_obj_ident_in_seq(oid_buf, &oid_buf_l,
				oid1, oid1_c, (uint8_t *)oid2, oid2_c,
				LTC_ASN1_OBJECT_IDENTIFIER);
	if (res != CRYPT_OK) {
		EMSG("Failed to encode key object ID");
		goto out;
	}
	res = encode_params(&params_buf, &params_buf_l, type,
				attr1, attr1_l, attr2, attr2_l, key_size);
	if (res != CRYPT_OK) {
		EMSG("Failed to encode key params");
		goto out;
	}
	out_buf_l = params_buf_l + oid_buf_l;
	out_buf = malloc(out_buf_l);
	if (!out_buf) {
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		EMSG("Failed to allocate memory for ASN.1 key buffer");
		goto out;
	}
	memcpy(out_buf, oid_buf, oid_buf_l);
	memcpy(out_buf + oid_buf_l, params_buf, params_buf_l);
	res = wrap(output, &output_size, out_buf, out_buf_l, CODE_SEQUENCE);
	if (res != CRYPT_OK) {
		EMSG("Failed to encode public key attributes");
		goto out;
	}
out:
	params[3].memref.size = (uint32_t) output_size;
	if (out_buf)
		free(out_buf);
	if (oid_buf)
		free(oid_buf);
	if (params_buf)
		free(params_buf);
	return res;
}

/*
 * INPUT
 * params[0].memref.buffer - r-part of EC sign
 * params[0].memref.size - length of r-part
 * params[1].memref.buffer - s-part of EC sign
 * params[1].memref.size - length of s-part
 *
 * OUTPUT
 * params[2].memref.buffer - encoded sign data
 * params[2].memref.size - encoded sign data length
 */
static TEE_Result TA_ec_sign_encode(uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_OUTPUT,
					TEE_PARAM_TYPE_NONE);
	uint32_t res = CRYPT_OK;
	uint32_t r_size = params[0].memref.size;
	uint32_t s_size = params[1].memref.size;
	uint64_t out_buf_l = 0;
	uint8_t *out_buf = NULL;
	struct bignum *s = NULL;
	struct bignum *r = NULL;

	if (ptypes != exp_param_types) {
		EMSG("Wrong parameters\n");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	s = malloc(sizeof(struct bignum) + BYTES_PER_WORD + s_size);
	if (!s) {
		EMSG("Failed to allocate memory for EC sign number S");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	r = malloc(sizeof(struct bignum) + BYTES_PER_WORD + r_size);
	if (!r) {
		EMSG("Failed to allocate memory for EC sign number R");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	s->alloc = sizeof(struct bignum) + BYTES_PER_WORD + s_size;
	r->alloc = sizeof(struct bignum) + BYTES_PER_WORD + r_size;
	res = crypto_ops.bignum.bin2bn(params[0].memref.buffer, r_size, r);
	if (res != CRYPT_OK) {
		EMSG("Failed to convert r to big number");
		goto out;
	}

	res = crypto_ops.bignum.bin2bn(params[1].memref.buffer, s_size, s);
	if (res != CRYPT_OK) {
		EMSG("Failed to convert s to big number");
		goto out;
	}
	out_buf_l = r_size + s_size + 3 * MAX_HEADER_SIZE;
	out_buf = malloc(out_buf_l);
	if (!out_buf) {
		EMSG("Failed to allocate memory for EC sign buffer");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	res = der_encode_sequence_multi(out_buf, &out_buf_l,
				LTC_ASN1_INTEGER, 1UL, r,
				LTC_ASN1_INTEGER, 1UL, s,
				LTC_ASN1_EOL, 0UL, NULL);
	if (res != CRYPT_OK) {
		EMSG("Failed to encode EC sign res = %x", res);
		goto out;
	}
	memcpy(params[2].memref.buffer, out_buf, out_buf_l);
out:
	params[2].memref.size = out_buf_l;
	if (r)
		free(r);
	if (s)
		free(s);
	if (out_buf)
		free(out_buf);
	return res;
}


/*
 * INPUT
 * params[0].memref.buffer - EC sign in ASN.1 format
 * params[0].memref.size - EC sign length
 * params[1].value.a - key size in bits
 *
 * OUTPUT
 * params[2].memref.buffer - decoded sign data
 * params[2].memref.size - decoded sign data length
 */
static TEE_Result TA_ec_sign_decode(uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_VALUE_INPUT,
					TEE_PARAM_TYPE_MEMREF_OUTPUT,
					TEE_PARAM_TYPE_NONE);
	uint32_t res = CRYPT_OK;
	uint8_t *input = params[0].memref.buffer;
	uint32_t input_l = params[0].memref.size;
	uint8_t *output = params[2].memref.buffer;
	uint32_t output_l = 0;
	uint32_t key_size = (params[1].value.a + 7) / 8;
	uint32_t bn_size = 0;
	struct bignum *s = NULL;
	struct bignum *r = NULL;

	if (ptypes != exp_param_types) {
		EMSG("Wrong parameters\n");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	s = malloc(sizeof(struct bignum) + BYTES_PER_WORD + input_l / 2);
	if (!s) {
		EMSG("Failed to allocate memory for EC sign number S");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	r = malloc(sizeof(struct bignum) + BYTES_PER_WORD + input_l / 2);
	if (!r) {
		EMSG("Failed to allocate memory for EC sign number R");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	s->alloc = sizeof(struct bignum) + BYTES_PER_WORD + input_l / 2;
	r->alloc = sizeof(struct bignum) + BYTES_PER_WORD + input_l / 2;
	res = der_decode_sequence_multi(input, input_l,
				LTC_ASN1_INTEGER, 1UL, r,
				LTC_ASN1_INTEGER, 1UL, s,
				LTC_ASN1_EOL, 0UL, NULL);
	if (res != CRYPT_OK) {
		EMSG("Failed to decode sequence of EC signature");
		goto out;
	}
	bn_size = crypto_ops.bignum.num_bytes(r);
	output_l += key_size > bn_size ? (key_size - bn_size) : 0;
	crypto_ops.bignum.bn2bin(r, output + output_l);
	output_l += bn_size;

	bn_size = crypto_ops.bignum.num_bytes(s);
	output_l += key_size > bn_size ? (key_size - bn_size) : 0;
	crypto_ops.bignum.bn2bin(s, output + output_l);
	output_l += bn_size;
out:
	params[2].memref.size = output_l;
	if (s)
		free(s);
	if (r)
		free(r);
	return res;
}

/*
 * Trusted Application Entry Points
 */

static TEE_Result create_ta(void)
{
	return TEE_SUCCESS;
}

static void destroy_ta(void)
{
}

static TEE_Result open_session(uint32_t ptype __unused,
				TEE_Param params[TEE_NUM_PARAMS] __unused,
				void **ppsess __unused)
{
	return TEE_SUCCESS;
}

static void close_session(void *psess __unused)
{
}

static TEE_Result invoke_command(void *psess __unused,
				 uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case CMD_PARSE:
		return TA_parse_asn1(ptypes, params);
	case CMD_X509_ENCODE:
		return TA_x509_encode(ptypes, params);
	case CMD_EC_SIGN_ENCODE:
		return TA_ec_sign_encode(ptypes, params);
	case CMD_EC_SIGN_DECODE:
		return TA_ec_sign_decode(ptypes, params);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

static_ta_register(.uuid = ASN1_PARSER_UUID, .name = TA_NAME,
		.create_entry_point = create_ta,
		.destroy_entry_point = destroy_ta,
		.open_session_entry_point = open_session,
		.close_session_entry_point = close_session,
		.invoke_command_entry_point = invoke_command);
