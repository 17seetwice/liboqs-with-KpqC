#ifndef OQS_KEM_SMAUG_H
#define OQS_KEM_SMAUG_H

#include <oqs/oqs.h>

#ifdef OQS_ENABLE_KEM_smaug_1
#define OQS_KEM_smaug1_SECRETKEYBYTES 160 + 672
#define OQS_KEM_smaug1_PUBLICKEYBYTES 672
#define OQS_KEM_smaug1_CIPHERTEXTBYTES 672
#define OQS_KEM_smaug1_BYTES 32
#define OQS_KEM_smaug1_SEED_BYTES 0

OQS_KEM *OQS_KEM_smaug1_new(void);
OQS_API OQS_STATUS OQS_KEM_smaug1_keypair(uint8_t *pk, uint8_t *sk);
OQS_API OQS_STATUS OQS_KEM_smaug1_encaps(uint8_t *ct, uint8_t *ss,
        const uint8_t *pk);
OQS_API OQS_STATUS OQS_KEM_smaug1_decaps(uint8_t *ss, const uint8_t *ctxt,
        const uint8_t *sk);
OQS_API OQS_STATUS OQS_KEM_smaug1_keypair_derand(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed);
#endif

#ifdef OQS_ENABLE_KEM_smaug_3
#define OQS_KEM_smaug3_SECRETKEYBYTES 224 + 1088
#define OQS_KEM_smaug3_PUBLICKEYBYTES 1088
#define OQS_KEM_smaug3_CIPHERTEXTBYTES 992
#define OQS_KEM_smaug3_BYTES 32
#define OQS_KEM_smaug3_SEED_BYTES 0

OQS_KEM *OQS_KEM_smaug3_new(void);
OQS_API OQS_STATUS OQS_KEM_smaug3_keypair(uint8_t *pk, uint8_t *sk);
OQS_API OQS_STATUS OQS_KEM_smaug3_encaps(uint8_t *ct, uint8_t *ss,
        const uint8_t *pk);
OQS_API OQS_STATUS OQS_KEM_smaug3_decaps(uint8_t *ss, const uint8_t *ctxt,
        const uint8_t *sk);
OQS_API OQS_STATUS OQS_KEM_smaug3_keypair_derand(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed);
#endif

#ifdef OQS_ENABLE_KEM_smaug_5
#define OQS_KEM_smaug5_SECRETKEYBYTES 288 + 1440
#define OQS_KEM_smaug5_PUBLICKEYBYTES 1440
#define OQS_KEM_smaug5_CIPHERTEXTBYTES 1376
#define OQS_KEM_smaug5_BYTES 32
#define OQS_KEM_smaug5_SEED_BYTES 0

OQS_KEM *OQS_KEM_smaug5_new(void);
OQS_API OQS_STATUS OQS_KEM_smaug5_keypair(uint8_t *pk, uint8_t *sk);
OQS_API OQS_STATUS OQS_KEM_smaug5_encaps(uint8_t *ct, uint8_t *ss,
        const uint8_t *pk);
OQS_API OQS_STATUS OQS_KEM_smaug5_decaps(uint8_t *ss, const uint8_t *ctxt,
        const uint8_t *sk);
OQS_API OQS_STATUS OQS_KEM_smaug5_keypair_derand(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed);
#endif

#endif // KEM_SMAUG_H
