#ifndef OQS_SIG_AIMER_H
#define OQS_SIG_AIMER_H

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_SIG_aimer_128f)

#define OQS_SIG_aimer_128f_length_public_key 32
#define OQS_SIG_aimer_128f_length_secret_key 48
#define OQS_SIG_aimer_128f_length_signature 5888

OQS_SIG *OQS_SIG_aimer_128f_new(void);
OQS_API OQS_STATUS OQS_SIG_aimer_128f_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_128f_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_128f_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_aimer_128f_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_128f_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_aimer_192f)

#define OQS_SIG_aimer_192f_length_public_key 48
#define OQS_SIG_aimer_192f_length_secret_key 72
#define OQS_SIG_aimer_192f_length_signature 13056

OQS_SIG *OQS_SIG_aimer_192f_new(void);
OQS_API OQS_STATUS OQS_SIG_aimer_192f_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_192f_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_192f_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_aimer_192f_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_192f_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);

#endif

#if defined(OQS_ENABLE_SIG_aimer_256f)

#define OQS_SIG_aimer_256f_length_public_key 64
#define OQS_SIG_aimer_256f_length_secret_key 96
#define OQS_SIG_aimer_256f_length_signature 25120

OQS_SIG *OQS_SIG_aimer_256f_new(void);
OQS_API OQS_STATUS OQS_SIG_aimer_256f_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_256f_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_256f_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_aimer_256f_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_256f_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif


#if defined(OQS_ENABLE_SIG_aimer_128s)

#define OQS_SIG_aimer_128s_length_public_key 32
#define OQS_SIG_aimer_128s_length_secret_key 48
#define OQS_SIG_aimer_128s_length_signature 4160

OQS_SIG *OQS_SIG_aimer_128s_new(void);
OQS_API OQS_STATUS OQS_SIG_aimer_128s_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_128s_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_128s_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_aimer_128s_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_128s_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_aimer_192s)

#define OQS_SIG_aimer_192s_length_public_key 48
#define OQS_SIG_aimer_192s_length_secret_key 72
#define OQS_SIG_aimer_192s_length_signature 9120

OQS_SIG *OQS_SIG_aimer_192s_new(void);
OQS_API OQS_STATUS OQS_SIG_aimer_192s_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_192s_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_192s_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_aimer_192s_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_192s_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);

#endif

#if defined(OQS_ENABLE_SIG_aimer_256s)

#define OQS_SIG_aimer_256s_length_public_key 64
#define OQS_SIG_aimer_256s_length_secret_key 96
#define OQS_SIG_aimer_256s_length_signature 17056

OQS_SIG *OQS_SIG_aimer_256s_new(void);
OQS_API OQS_STATUS OQS_SIG_aimer_256s_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_256s_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_256s_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_aimer_256s_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_aimer_256s_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif


#endif
