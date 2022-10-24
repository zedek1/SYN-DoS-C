#ifndef RAND_CMWC_H
#define RAND_CMWC_H

#include <stdint.h>

// 2 .c files use this meaning redefinition is not static
static unsigned int PHI = 0x9e3779b9;
static unsigned long int Q[4096], c = 362436;

void init_rand(unsigned long int x);
unsigned long int rand_cmwc(void);

#endif //RAND_CMWC_HXX