
#include <stdint.h>

void sm3_hash(const uint8_t* data, int len, uint8_t digest[32]);

void sm3_hmac(const uint8_t* key, int key_len, const uint8_t* data, int len, uint8_t mac[32]);