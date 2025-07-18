#pragma once

#include <stdint.h>

int sm2_sign_sca(int bn_byte_len, const uint8_t* n, const uint8_t* k, const uint8_t* r, const uint8_t* s, uint8_t* d);

void sm2_sign_sca_test();
