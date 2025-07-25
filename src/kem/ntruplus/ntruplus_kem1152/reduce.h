#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>

#define QINV 12929 // q^(-1) mod 2^16

#define montgomery_reduce NTRUPLUS_NAMESPACE(montgomery_reduce)
#define ntruplus_barrett_reduce NTRUPLUS_NAMESPACE(ntruplus_barrett_reduce)

int16_t montgomery_reduce(int32_t a);
int16_t ntruplus_barrett_reduce(int16_t a);

#endif
