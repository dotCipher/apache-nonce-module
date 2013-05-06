// Standard libs / File Control
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

// GNU GMP C library
#include <gmp.h>

// GNU GCrypt library
#include <gcrypt.h>
#define GCRYPT_NO_DEPRECATED 1

// Base64 Handling
#include "libs/cencode.c"

// External call declaration
char *nonce_rand_gen();

// Internal call declaration
char *init_rand_str();
