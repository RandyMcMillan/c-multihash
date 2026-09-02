#include "mh/multihash.h"

#include "mh/hashes.h"
#include "mh/errors.h"
#include "mh/generic.h"

#include <string.h>
#include <stdlib.h>

/* Canonical unsigned varint helpers */
static size_t uvarint_encode(unsigned char *buf, unsigned long long val)
{
	size_t i = 0;
	while (val >= 0x80) {
		buf[i++] = (unsigned char)(val | 0x80);
		val >>= 7;
	}
	buf[i++] = (unsigned char)val;
	return i;
}

static size_t uvarint_decode(const unsigned char *buf, size_t len,
	unsigned long long *val)
{
	size_t i = 0;
	unsigned int shift = 0;
	unsigned char b;

	*val = 0;
	while (i < len) {
		b = buf[i++];
		*val |= (unsigned long long)(b & 0x7F) << shift;
		if ((b & 0x80) == 0)
			return i;
		shift += 7;
		if (shift >= 64)
			return 0; /* overflow */
	}
	return 0; /* incomplete */
}

/**
 * do some general checks on the multihash for validity
 * @param mh the multihash
 * @param len the length of the multihash
 * @returns errors or MH_E_NO_ERROR(0)
 */
static int check_multihash(const unsigned char mh[], size_t len)
{
	unsigned long long code = 0;
	unsigned long long digest_len = 0;
	size_t code_bytes = 0;
	size_t len_bytes = 0;

	if (len < 3)
		return MH_E_TOO_SHORT;

	code_bytes = uvarint_decode(mh, len, &code);
	if (code_bytes == 0)
		return MH_E_TOO_SHORT;

	len_bytes = uvarint_decode(&mh[code_bytes], len - code_bytes, &digest_len);
	if (len_bytes == 0)
		return MH_E_TOO_SHORT;

	if (code_bytes + len_bytes + digest_len != len)
		return MH_E_TOO_SHORT;

	return MH_E_NO_ERROR;
}

/**
 * returns hash code or error (which is < 0)
 * @param mh the multihash
 * @param len the length of the multihash
 * @returns errors ( < 0 ) or the multihash
 */
int mh_multihash_hash(const unsigned char *mh, size_t len)
{
	int err;
	unsigned long long code = 0;

	err = check_multihash(mh, len);
	if (err)
		return err;

	uvarint_decode(mh, len, &code);
	return (int)code;
}

/***
 * returns the length of the multihash's data section
 * @param mh the multihash
 * @param len the length of the multihash
 * @returns the length of the data section, or an error if < 0
 */
int mh_multihash_length(const unsigned char *mh, size_t len)
{
	int err;
	unsigned long long code = 0;
	unsigned long long digest_len = 0;
	size_t code_bytes = 0;

	err = check_multihash(mh, len);
	if (err)
		return err;

	code_bytes = uvarint_decode(mh, len, &code);
	uvarint_decode(&mh[code_bytes], len - code_bytes, &digest_len);

	return (int)digest_len;
}

/**
 * gives access to raw digest inside multihash buffer
 * @param multihash the multihash
 * @param len the length
 * @param digest the results
 * @returns error if less than zero, otherwise 0
 */
int mh_multihash_digest(const unsigned char *multihash, size_t len,
	unsigned char **digest, size_t *digest_len)
{
	int err;
	unsigned long long code = 0;
	unsigned long long dlen = 0;
	size_t code_bytes = 0;
	size_t len_bytes = 0;

	err = check_multihash(multihash, len);
	if (err)
		return err;

	code_bytes = uvarint_decode(multihash, len, &code);
	len_bytes = uvarint_decode(&multihash[code_bytes],
		len - code_bytes, &dlen);

	(*digest_len) = (size_t)dlen;
	(*digest) = (unsigned char *)multihash + code_bytes + len_bytes;

	return 0;
}

/**
 * determine the size of the multihash given the data size
 * @param code the hash function code
 * @param hash_len the data size
 * @returns the total multihash size in bytes
 */
int mh_new_length(int code, size_t digest_len)
{
	unsigned char tmp[16];
	size_t code_bytes;
	size_t len_bytes;

	code_bytes = uvarint_encode(tmp, (unsigned long long)code);
	len_bytes = uvarint_encode(tmp, (unsigned long long)digest_len);
	return (int)(code_bytes + len_bytes + digest_len);
}

/***
 * create a multihash based on some data
 * @param buffer where to put the multihash
 * @param code the code
 * @param digest the data within the multihash
 * @returns error (if < 0) or 0
 */
int mh_new(unsigned char *buffer, int code, const unsigned char *digest,
	size_t digest_len)
{
	size_t code_bytes;
	size_t len_bytes;

	code_bytes = uvarint_encode(buffer, (unsigned long long)code);
	len_bytes = uvarint_encode(&buffer[code_bytes],
		(unsigned long long)digest_len);
	memcpy(buffer + code_bytes + len_bytes, digest, digest_len);

	return 0;
}
