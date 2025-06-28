
#include <stdint.h>

void sm2_compute_pub_key(const uint8_t priv_key[32], uint8_t pub_key[64]);

int sm2_enc(const uint8_t pub_key[64], const uint8_t* plain, int plain_len, uint8_t* cipher, int* cipher_len);
int sm2_dec(const uint8_t priv_key[32], uint8_t* cipher, int cipher_len, uint8_t* plain, size_t* plain_len);

int sm2_sign_ida(const uint8_t priv_key[32], const uint8_t* ida, int ida_len, const uint8_t* msg, int msg_len, uint8_t signature[64]);
int sm2_verify_ida(const uint8_t pub_key[64], const uint8_t* ida, int ida_len, const uint8_t* msg, int msg_len, const uint8_t signature[64]);
int sm2_sign_hash(const uint8_t priv_key[32], const uint8_t hash[32], uint8_t signature[64]);
int sm2_verify_hash(const uint8_t pub_key[64], const uint8_t hash[32], const uint8_t signature[64]);