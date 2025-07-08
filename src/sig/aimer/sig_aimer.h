#ifndef OQS_SIG_AIMER_H
#define OQS_SIG_AIMER_H

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_SIG_aimer_128f_ref)

#define OQS_SIG_aimer_128f_ref_length_public_key 32
#define OQS_SIG_aimer_128f_ref_length_secret_key 48
#define OQS_SIG_aimer_128f_ref_length_signature 5888

OQS_SIG *OQS_SIG_aimer_128f_ref_new(void);
OQS_API OQS_STATUS OQS_SIG_aimer_128f_ref_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_128f_ref_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_128f_ref_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif

#if defined(OQS_ENABLE_SIG_aimer_192f_ref)

#define OQS_SIG_aimer_192f_ref_length_public_key 48
#define OQS_SIG_aimer_192f_ref_length_secret_key 72
#define OQS_SIG_aimer_192f_ref_length_signature 13056

OQS_SIG *OQS_SIG_aimer_192f_ref_new(void);
OQS_API OQS_STATUS OQS_SIG_aimer_192f_ref_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_192f_ref_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_192f_ref_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif

#endif
