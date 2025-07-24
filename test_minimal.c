#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>

int main() {
    printf("Testing AIMER128F keypair generation...\n");
    
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_aimer_128f);
    if (sig == NULL) {
        printf("Failed to create AIMER128F signature object\n");
        return 1;
    }
    
    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    
    if (public_key == NULL || secret_key == NULL) {
        printf("Memory allocation failed\n");
        OQS_SIG_free(sig);
        return 1;
    }
    
    printf("Calling keypair generation...\n");
    OQS_STATUS rc = OQS_SIG_keypair(sig, public_key, secret_key);
    
    if (rc == OQS_SUCCESS) {
        printf("Keypair generation succeeded!\n");
    } else {
        printf("Keypair generation failed!\n");
    }
    
    free(public_key);
    free(secret_key);
    OQS_SIG_free(sig);
    
    return (rc == OQS_SUCCESS) ? 0 : 1;
}
