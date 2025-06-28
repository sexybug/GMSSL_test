
#include <stdint.h>

int sm4_ecb_enc(const uint8_t K[16], const uint8_t* in, int in_len, uint8_t* out);

int sm4_ecb_dec(const uint8_t K[16], const uint8_t* in, int in_len, uint8_t* out);

int sm4_cbc_enc(const uint8_t key[16], const uint8_t iv[16], const uint8_t* in, int in_len, uint8_t* out);

int sm4_cbc_dec(const uint8_t key[16], const uint8_t iv[16], const uint8_t* in, int in_len, uint8_t* out);

