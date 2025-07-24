#ifndef OQS_KEM_NTRUPLUS_H
#define OQS_KEM_NTRUPLUS_H

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_KEM_ntruplus_kem576)
#define OQS_KEM_ntruplus_kem576_length_public_key 864
#define OQS_KEM_ntruplus_kem576_length_secret_key 1760
#define OQS_KEM_ntruplus_kem576_length_ciphertext 864
#define OQS_KEM_ntruplus_kem576_length_shared_secret 32
#define OQS_KEM_ntruplus_kem576_length_keypair_seed 0
OQS_KEM *OQS_KEM_ntruplus_kem576_new(void);
OQS_API OQS_STATUS OQS_KEM_ntruplus_kem576_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_ntruplus_kem576_keypair_derand(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed);
OQS_API OQS_STATUS OQS_KEM_ntruplus_kem576_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_ntruplus_kem576_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
#endif

#if defined(OQS_ENABLE_KEM_ntruplus_kem768)
#define OQS_KEM_ntruplus_kem768_length_public_key 1152
#define OQS_KEM_ntruplus_kem768_length_secret_key 2336
#define OQS_KEM_ntruplus_kem768_length_ciphertext 1152
#define OQS_KEM_ntruplus_kem768_length_shared_secret 32
#define OQS_KEM_ntruplus_kem768_length_keypair_seed 0
OQS_KEM *OQS_KEM_ntruplus_kem768_new(void);
OQS_API OQS_STATUS OQS_KEM_ntruplus_kem768_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_ntruplus_kem768_keypair_derand(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed);
OQS_API OQS_STATUS OQS_KEM_ntruplus_kem768_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_ntruplus_kem768_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
#endif

#if defined(OQS_ENABLE_KEM_ntruplus_kem864)
#define OQS_KEM_ntruplus_kem864_length_public_key 1296
#define OQS_KEM_ntruplus_kem864_length_secret_key 2624
#define OQS_KEM_ntruplus_kem864_length_ciphertext 1296
#define OQS_KEM_ntruplus_kem864_length_shared_secret 32
#define OQS_KEM_ntruplus_kem864_length_keypair_seed 0
OQS_KEM *OQS_KEM_ntruplus_kem864_new(void);
OQS_API OQS_STATUS OQS_KEM_ntruplus_kem864_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_ntruplus_kem864_keypair_derand(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed);
OQS_API OQS_STATUS OQS_KEM_ntruplus_kem864_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_ntruplus_kem864_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
#endif

#if defined(OQS_ENABLE_KEM_ntruplus_kem1152)
#define OQS_KEM_ntruplus_kem1152_length_public_key 1728
#define OQS_KEM_ntruplus_kem1152_length_secret_key 3488
#define OQS_KEM_ntruplus_kem1152_length_ciphertext 1728
#define OQS_KEM_ntruplus_kem1152_length_shared_secret 32
#define OQS_KEM_ntruplus_kem1152_length_keypair_seed 0
OQS_KEM *OQS_KEM_ntruplus_kem1152_new(void);
OQS_API OQS_STATUS OQS_KEM_ntruplus_kem1152_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_ntruplus_kem1152_keypair_derand(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed);
OQS_API OQS_STATUS OQS_KEM_ntruplus_kem1152_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_ntruplus_kem1152_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
#endif


#endif // KEM_NTRUPLUS_H
