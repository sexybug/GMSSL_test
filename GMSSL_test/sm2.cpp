

#include "sm2.h"
#include "test.h"

#include <gmssl/sm2.h>
#include <gmssl/sm2_z256.h>


//print priv_key,pub_key
void sm2_print_key(const SM2_KEY* sm2_key);
//set priv_key, compute pub_key
void sm2_set_key(SM2_KEY* sm2_key, const uint8_t priv_key[32]);
int sm2_set_pub_key(SM2_KEY* sm2_key, const uint8_t pub_key[64]);


//C1||C3||C2
void SM2_CIPHERTEXT_to_u8(const SM2_CIPHERTEXT* c, uint8_t* out, int* outlen);
void u8_to_SM2_CIPHERTEXT(const uint8_t* in, int inlen, SM2_CIPHERTEXT* c);
void sm2_compute_e(const SM2_KEY* key, const uint8_t* IDA, size_t IDA_len, const uint8_t* M, size_t M_len, uint8_t e[32]);

void sm2_print_key(const SM2_KEY* sm2_key)
{
	uint8_t priv_key[32];
	sm2_z256_to_bytes(sm2_key->private_key, priv_key);
	print_u8("private_key", priv_key, sizeof(priv_key));

	uint8_t pub_key[64];
	sm2_z256_point_to_bytes(&sm2_key->public_key, pub_key);
	print_u8("public_key", pub_key, sizeof(pub_key));
}
void sm2_set_key(SM2_KEY* sm2_key, const uint8_t priv_key[32])
{
	sm2_z256_t priv_key_bn;
	sm2_z256_from_bytes(priv_key_bn, priv_key);
	sm2_key_set_private_key(sm2_key, priv_key_bn);
}
int sm2_set_pub_key(SM2_KEY* sm2_key, const uint8_t pub_key[64])
{
	SM2_Z256_POINT public_key;
	sm2_z256_point_from_bytes(&public_key, pub_key);
	return sm2_key_set_public_key(sm2_key, &public_key);
}

//C1||C3||C2
void SM2_CIPHERTEXT_to_u8(const SM2_CIPHERTEXT* c, uint8_t* out, int* outlen)
{
	*outlen = 96 + c->ciphertext_size;
	memcpy(out, c->point.x, 32);
	memcpy(out + 32, c->point.y, 32);
	memcpy(out + 64, c->hash, 32);
	memcpy(out + 96, c->ciphertext, c->ciphertext_size);
}
void u8_to_SM2_CIPHERTEXT(const uint8_t* in, int inlen, SM2_CIPHERTEXT* c)
{
	if (inlen < 96) {
		fprintf(stderr, "Invalid ciphertext length\n");
		return;
	}
	memcpy(c->point.x, in, 32);
	memcpy(c->point.y, in + 32, 32);
	memcpy(c->hash, in + 64, 32);
	c->ciphertext_size = inlen - 96;
	memcpy(c->ciphertext, in + 96, c->ciphertext_size);
}

void sm2_compute_pub_key(const uint8_t priv_key[32], uint8_t pub_key[64])
{
	SM2_KEY sm2_key;
	sm2_set_key(&sm2_key, priv_key);
	sm2_z256_point_to_bytes(&(sm2_key.public_key), pub_key);
}
int sm2_enc(const uint8_t pub_key[64], const uint8_t* plain, int plain_len, uint8_t* cipher, int* cipher_len)
{
	SM2_KEY sm2_key;
	SM2_CIPHERTEXT sm2_ciphertext;

	int pub_key_valid = sm2_set_pub_key(&sm2_key, pub_key);
	int enc_success = sm2_do_encrypt(&sm2_key, plain, plain_len, &sm2_ciphertext);
	SM2_CIPHERTEXT_to_u8(&sm2_ciphertext, cipher, cipher_len);

	return pub_key_valid == 1 && enc_success == 1;
}
int sm2_dec(const uint8_t priv_key[32], uint8_t* cipher, int cipher_len, uint8_t* plain, size_t* plain_len)
{
	SM2_KEY sm2_key;
	SM2_CIPHERTEXT sm2_ciphertext;

	sm2_set_key(&sm2_key, priv_key);

	u8_to_SM2_CIPHERTEXT(cipher, cipher_len, &sm2_ciphertext);
	int dec_success = sm2_do_decrypt(&sm2_key, &sm2_ciphertext, plain, plain_len);
	return dec_success == 1;
}


void sm2_compute_e(const SM2_KEY* key, const uint8_t* IDA, size_t IDA_len, const uint8_t* M, size_t M_len, uint8_t e[32])
{
	SM3_CTX sm3_ctx;

	uint8_t id[256];
	memset(id, 0, sizeof(id));
	memcpy(id, IDA, IDA_len);

	uint8_t z[32];
	sm2_compute_z(z, &key->public_key, reinterpret_cast<const char*>(id), IDA_len);

	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, z, sizeof(z));
	sm3_update(&sm3_ctx, M, M_len);
	sm3_finish(&sm3_ctx, e);
}
int sm2_sign_ida(const uint8_t priv_key[32], const uint8_t* ida, int ida_len, const uint8_t* msg, int msg_len, uint8_t signature[64])
{
	SM2_KEY sm2_key;
	sm2_set_key(&sm2_key, priv_key);

	uint8_t dgst[32] = { /* some hash value */ };
	sm2_compute_e(&sm2_key, ida, ida_len, msg, msg_len, dgst);
	//print_u8("e", dgst, sizeof(dgst));

	SM2_SIGNATURE sig;
	int sign_success = sm2_do_sign(&sm2_key, dgst, &sig);
	memcpy(signature, sig.r, 32);
	memcpy(signature + 32, sig.s, 32);

	return sign_success;
}

int sm2_verify_ida(const uint8_t pub_key[64], const uint8_t* ida, int ida_len, const uint8_t* msg, int msg_len, const uint8_t signature[64])
{
	SM2_KEY sm2_key;

	int pub_key_valid = sm2_set_pub_key(&sm2_key, (uint8_t*)pub_key);

	uint8_t dgst[32] = { /* some hash value */ };
	sm2_compute_e(&sm2_key, ida, ida_len, msg, msg_len, dgst);
	//print_u8("e", dgst, sizeof(dgst));

	SM2_SIGNATURE sig;
	memcpy(sig.r, signature, 32);
	memcpy(sig.s, signature + 32, 32);

	int verify = sm2_do_verify(&sm2_key, dgst, &sig);

	return (pub_key_valid == 1) && (verify == 1);
}

int sm2_sign_hash(const uint8_t priv_key[32], const uint8_t hash[32], uint8_t signature[64])
{
	SM2_KEY sm2_key;
	sm2_set_key(&sm2_key, priv_key);

	SM2_SIGNATURE sig;
	int sign_success = sm2_do_sign(&sm2_key, hash, &sig);
	memcpy(signature, sig.r, 32);
	memcpy(signature + 32, sig.s, 32);

	return sign_success;
}

int sm2_verify_hash(const uint8_t pub_key[64], const uint8_t hash[32], const uint8_t signature[64])
{
	SM2_KEY sm2_key;

	int pub_key_valid = sm2_set_pub_key(&sm2_key, (uint8_t*)pub_key);

	SM2_SIGNATURE sig;
	memcpy(sig.r, signature, 32);
	memcpy(sig.s, signature + 32, 32);

	int verify = sm2_do_verify(&sm2_key, hash, &sig);

	return (pub_key_valid == 1) && (verify == 1);
}