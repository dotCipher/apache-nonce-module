// GNU GMP C library
#include <gmp.h>

// GNU GCrypt library
#include <gcrypt.h>

#ifndef NONCE_RAND_H
#define NONCE_RAND_H
// Base64 Handling

typedef enum
{
	step_A, step_B, step_C
} base64_encodestep;

typedef struct
{
	base64_encodestep step;
	char result;
	int stepcount;
} base64_encodestate;

void base64_init_encodestate(base64_encodestate* state_in);

char base64_encode_value(char value_in);

int base64_encode_block(const char* plaintext_in, int length_in, char* code_out, base64_encodestate* state_in);

int base64_encode_blockend(char* code_out, base64_encodestate* state_in);

// External call declaration
extern char *nonce_rand_gen(void);

// Internal call declaration
char *init_rand_str(void);
#endif
