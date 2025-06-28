
#include "sm4.h"
#include <gmssl/sm4.h>

int sm4_ecb_enc(const uint8_t key[16], const uint8_t* in, int in_len, uint8_t* out)
{
	if (in_len % 16 != 0)
	{
		return -1;
	}

	size_t nblocks = in_len / 16;
	SM4_KEY sm4_key;
	sm4_set_encrypt_key(&sm4_key, key);
	sm4_encrypt_blocks(&sm4_key, in, nblocks, out);
}

int sm4_ecb_dec(const uint8_t key[16], const uint8_t* in, int in_len, uint8_t* out)
{
	if (in_len % 16 != 0)
	{
		return -1;
	}

	size_t nblocks = in_len / 16;
	SM4_KEY sm4_key;
	sm4_set_decrypt_key(&sm4_key, key);
	sm4_encrypt_blocks(&sm4_key, in, nblocks, out);
}

int sm4_cbc_enc(const uint8_t key[16], const uint8_t iv[16], const uint8_t* in, int in_len, uint8_t* out)
{
	if (in_len % 16 != 0)
	{
		return -1;
	}

	size_t nblocks = in_len / 16;
	uint8_t iv_tmp[16];
	memcpy(iv_tmp, iv, 16);
	
	SM4_KEY sm4_key;
	sm4_set_encrypt_key(&sm4_key, key);
	sm4_cbc_encrypt_blocks(&sm4_key, iv_tmp, in, nblocks, out);
}

int sm4_cbc_dec(const uint8_t key[16], const uint8_t iv[16], const uint8_t* in, int in_len, uint8_t* out)
{
	if (in_len % 16 != 0)
	{
		return -1;
	}

	size_t nblocks = in_len / 16;
	uint8_t iv_tmp[16];
	memcpy(iv_tmp, iv, 16);

	SM4_KEY sm4_key;
	sm4_set_decrypt_key(&sm4_key, key);
	sm4_cbc_decrypt_blocks(&sm4_key, iv_tmp, in, nblocks, out);
}