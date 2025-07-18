#include <stdlib.h>
#include <oqs/oqs.h>
#include "aimer_256f/api.h"

#if defined(OQS_ENABLE_SIG_aimer_256f)

OQS_SIG *OQS_SIG_aimer_256f_new(void) {
	OQS_SIG *sig = OQS_MEM_malloc(sizeof(OQS_SIG));
	if (sig == NULL) return NULL;

	sig->method_name = OQS_SIG_alg_aimer_256f;
	sig->alg_version = "https://github.com/samsungsds-research-papers/AIMer";

	sig->claimed_nist_level = 5;
	sig->euf_cma = true;
	sig->suf_cma = true;
	sig->sig_with_ctx_support = true;

	sig->length_public_key = OQS_SIG_aimer_256f_length_public_key;
	sig->length_secret_key = OQS_SIG_aimer_256f_length_secret_key;
	sig->length_signature = OQS_SIG_aimer_256f_length_signature;

	sig->keypair = OQS_SIG_aimer_256f_keypair;
	sig->sign = OQS_SIG_aimer_256f_sign;
	sig->verify = OQS_SIG_aimer_256f_verify;
	sig->sign_with_ctx_str = OQS_SIG_aimer_256f_sign_with_ctx_str;
	sig->verify_with_ctx_str=OQS_SIG_aimer_256f_verify_with_ctx_str;

	return sig;
}

extern int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);

OQS_API OQS_STATUS OQS_SIG_aimer_256f_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (OQS_STATUS) crypto_sign_keypair(public_key, secret_key);
}

OQS_API OQS_STATUS OQS_SIG_aimer_256f_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	return (OQS_STATUS) crypto_sign_signature(signature, signature_len, message, message_len, secret_key);

}

OQS_API OQS_STATUS OQS_SIG_aimer_256f_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	return (OQS_STATUS) crypto_sign_verify(message, message_len, signature, signature_len, public_key);

}

OQS_API OQS_STATUS OQS_SIG_aimer_256f_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key){

	if (ctx_str == NULL && ctx_str_len == 0) {
		return OQS_SIG_aimer_256f_sign(signature, signature_len, message, message_len, secret_key);
	} else {
		return OQS_ERROR;
	}	
}

OQS_API OQS_STATUS OQS_SIG_aimer_256f_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key){}

	if (ctx_str == NULL && ctx_str_len == 0) {
		return OQS_SIG_aimer_256f_verify(message, message_len, signature, signature_len, public_key);
	} else {
		return OQS_ERROR;
	}
#endif

