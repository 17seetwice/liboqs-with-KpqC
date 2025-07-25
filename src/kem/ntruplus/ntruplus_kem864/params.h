#ifndef PARAMS_H
#define PARAMS_H

#ifndef NTRUPLUS_MODE
#define NTRUPLUS_MODE 864	/* Change this for different security strengths */
#endif

/* Don't change parameters below this line */
#if   (NTRUPLUS_MODE == 576)
#define NTRUPLUS_NAMESPACE(s) ntruplus_kem576_##s
#define NTRUPLUS_N 576
#define NTRUPLUS_POLYBYTES 864
#elif (NTRUPLUS_MODE == 768)
#define NTRUPLUS_NAMESPACE(s) ntruplus_kem768_##s
#define NTRUPLUS_N 768
#define NTRUPLUS_POLYBYTES 1152
#elif (NTRUPLUS_MODE == 864)
#define NTRUPLUS_NAMESPACE(s) ntruplus_kem864_##s
#define NTRUPLUS_N 864
#define NTRUPLUS_POLYBYTES 1296
#elif (NTRUPLUS_MODE == 1152)
#define NTRUPLUS_NAMESPACE(s) ntruplus_kem1152_##s
#define NTRUPLUS_N 1152
#define NTRUPLUS_POLYBYTES 1728
#else
#error "NTRUPLUS_MODE must be in {576,768,864,1152}"
#endif

#define NTRUPLUS_Q 3457

#define NTRUPLUS_SYMBYTES  32   /* size in bytes of hashes, and seeds */
#define NTRUPLUS_SSBYTES   32   /* size in bytes of shared key */

#define NTRUPLUS_PUBLICKEYBYTES  NTRUPLUS_POLYBYTES
#define NTRUPLUS_SECRETKEYBYTES  ((NTRUPLUS_POLYBYTES << 1) + NTRUPLUS_SYMBYTES)
#define NTRUPLUS_CIPHERTEXTBYTES  NTRUPLUS_POLYBYTES

#endif
