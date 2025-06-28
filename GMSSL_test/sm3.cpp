
#include "sm3.h"
#include <gmssl/sm3.h>

void sm3_hash(const uint8_t* data, int len, uint8_t digest[32])
{
	SM3_CTX sm3_ctx;
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, data, len);
	sm3_finish(&sm3_ctx, digest);
}

void sm3_hmac(const uint8_t *key, int key_len, const uint8_t* data, int len, uint8_t mac[32])
{
	SM3_HMAC_CTX ctx;
	sm3_hmac_init(&ctx, key, key_len);
	sm3_hmac_update(&ctx, data, len);
	sm3_hmac_finish(&ctx, mac);
}