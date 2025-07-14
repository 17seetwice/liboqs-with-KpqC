#ifndef OQS_SIG_HAETAE_H
#define OQS_SIG_HAETAE_H

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_SIG_haetae_120)

#define OQS_SIG_haetae_120_length_public_key 992
#define OQS_SIG_haetae_120_length_secret_key 1408
#define OQS_SIG_haetae_120_length_signature 1474

OQS_SIG *OQS_SIG_haetae_120_new(void);
OQS_API OQS_STATUS OQS_SIG_haetae_120_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_haetae_120_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_haetae_120_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_haetae_120_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_haetae_120_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_haetae_180)

#define OQS_SIG_haetae_180_length_public_key 1472
#define OQS_SIG_haetae_180_length_secret_key 2112
#define OQS_SIG_haetae_180_length_signature 2349

OQS_SIG *OQS_SIG_haetae_180_new(void);
OQS_API OQS_STATUS OQS_SIG_haetae_180_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_haetae_180_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_haetae_180_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_haetae_180_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_haetae_180_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_haetae_260)

#define OQS_SIG_haetae_180_length_public_key 2080
#define OQS_SIG_haetae_180_length_secret_key 2752
#define OQS_SIG_haetae_180_length_signature 2948

OQS_SIG *OQS_SIG_haetae_260_new(void);
OQS_API OQS_STATUS OQS_SIG_haetae_260_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_haetae_260_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_haetae_260_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_haetae_260_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_haetae_260_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#endif
