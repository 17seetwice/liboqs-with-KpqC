// SPDX-License-Identifier: MIT

#ifndef OQS_KEM_SMAUGT_H
#define OQS_KEM_SMAUGT_H

#include <oqs/oqs.h>

#ifdef OQS_ENABLE_KEM_smaugt_1
#define OQS_KEM_smaugt_1_length_secret_key 832
#define OQS_KEM_smaugt_1_length_public_key 672
#define OQS_KEM_smaugt_1_length_ciphertext 672
#define OQS_KEM_smaugt_1_length_shared_secret 32
#define OQS_KEM_smaugt_1_length_keypair_seed 0
OQS_KEM *OQS_KEM_smaugt_1_new(void);
OQS_API OQS_STATUS OQS_KEM_smaugt_1_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_smaugt_1_keypair_derand(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed);
OQS_API OQS_STATUS OQS_KEM_smaugt_1_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_smaugt_1_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#ifdef OQS_ENABLE_KEM_smaugt_3
#define OQS_KEM_smaugt_3_length_secret_key 1312
#define OQS_KEM_smaugt_3_length_public_key 1088
#define OQS_KEM_smaugt_3_length_ciphertext 992
#define OQS_KEM_smaugt_3_length_shared_secret 32
#define OQS_KEM_smaugt_3_length_keypair_seed 0
OQS_KEM *OQS_KEM_smaugt_3_new(void);
OQS_API OQS_STATUS OQS_KEM_smaugt_3_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_smaugt_3_keypair_derand(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed);
OQS_API OQS_STATUS OQS_KEM_smaugt_3_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_smaugt_3_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#ifdef OQS_ENABLE_KEM_smaugt_5
#define OQS_KEM_smaugt_5_length_secret_key 1728
#define OQS_KEM_smaugt_5_length_public_key 1440
#define OQS_KEM_smaugt_5_length_ciphertext 1376
#define OQS_KEM_smaugt_5_length_shared_secret 32
#define OQS_KEM_smaugt_5_length_keypair_seed 0
OQS_KEM *OQS_KEM_smaugt_5_new(void);
OQS_API OQS_STATUS OQS_KEM_smaugt_5_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_smaugt_5_keypair_derand(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed);
OQS_API OQS_STATUS OQS_KEM_smaugt_5_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_smaugt_5_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif



#endif // OQS_KEM_SMAUGT_H
