#include <stdlib.h>
#include <oqs/oqs.h>

#include "aimer_192f_ref/api.h"
#if defined(OQS_ENABLE_SIG_aimer_192f_ref)

OQS_SIG *OQS_SIG_aimer_192f_ref_new(void) {
	OQS_SIG *sig = OQS_MEM_malloc(sizeof(OQS_SIG));
	if (sig == NULL) return NULL;

	sig->method_name = OQS_SIG_alg_aimer_192f_ref;
	sig->alg_version = "https://github.com/samsungsds-research-papers/AIMer";

	sig->claimed_nist_level = 3;
	sig->euf_cma = true;
	sig->suf_cma = false;
	sig->sig_with_ctx_support = false;

	sig->length_public_key = OQS_SIG_aimer_192f_ref_length_public_key;
	sig->length_secret_key = OQS_SIG_aimer_192f_ref_length_secret_key;
	sig->length_signature = OQS_SIG_aimer_192f_ref_length_signature;

	sig->keypair = OQS_SIG_aimer_192f_ref_keypair;
	sig->sign = OQS_SIG_aimer_192f_ref_sign;
	sig->verify = OQS_SIG_aimer_192f_ref_verify;

	return sig;
}

extern int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);

OQS_API OQS_STATUS OQS_SIG_aimer_192f_ref_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (OQS_STATUS) crypto_sign_keypair(public_key, secret_key);
}

OQS_API OQS_STATUS OQS_SIG_aimer_192f_ref_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	return (OQS_STATUS) crypto_sign_signature(signature, signature_len, message, message_len, secret_key);

}

OQS_API OQS_STATUS OQS_SIG_aimer_192f_ref_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	return (OQS_STATUS) crypto_sign_verify(message, message_len, signature, signature_len, public_key);

}

#endif
