#include "nonce_rand.h"
#include <fcntl.h>

/* Must install GMP library */
/* Must install LIBGCRYPT library */

/* Base64 encoding functionality */

const int CHARS_PER_LINE = 72;

void base64_init_encodestate(base64_encodestate* state_in)
{
	state_in->step = step_A;
	state_in->result = 0;
	state_in->stepcount = 0;
}

char base64_encode_value(char value_in)
{
	static const char* encoding = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	if (value_in > 63) return '=';
	return encoding[(int)value_in];
}

int base64_encode_block(const char* plaintext_in, int length_in, char* code_out, base64_encodestate* state_in)
{
	const char* plainchar = plaintext_in;
	const char* const plaintextend = plaintext_in + length_in;
	char* codechar = code_out;
	char result;
	char fragment;
	
	result = state_in->result;
	
	switch (state_in->step)
	{
		while (1)
		{
	case step_A:
			if (plainchar == plaintextend)
			{
				state_in->result = result;
				state_in->step = step_A;
				return codechar - code_out;
			}
			fragment = *plainchar++;
			result = (fragment & 0x0fc) >> 2;
			*codechar++ = base64_encode_value(result);
			result = (fragment & 0x003) << 4;
	case step_B:
			if (plainchar == plaintextend)
			{
				state_in->result = result;
				state_in->step = step_B;
				return codechar - code_out;
			}
			fragment = *plainchar++;
			result |= (fragment & 0x0f0) >> 4;
			*codechar++ = base64_encode_value(result);
			result = (fragment & 0x00f) << 2;
	case step_C:
			if (plainchar == plaintextend)
			{
				state_in->result = result;
				state_in->step = step_C;
				return codechar - code_out;
			}
			fragment = *plainchar++;
			result |= (fragment & 0x0c0) >> 6;
			*codechar++ = base64_encode_value(result);
			result  = (fragment & 0x03f) >> 0;
			*codechar++ = base64_encode_value(result);
			
			++(state_in->stepcount);
			if (state_in->stepcount == CHARS_PER_LINE/4)
			{
				*codechar++ = '\n';
				state_in->stepcount = 0;
			}
		}
	}
	/* control should not reach here */
	return codechar - code_out;
}

int base64_encode_blockend(char* code_out, base64_encodestate* state_in)
{
	char* codechar = code_out;
	
	switch (state_in->step)
	{
	case step_B:
		*codechar++ = base64_encode_value(state_in->result);
		*codechar++ = '=';
		*codechar++ = '=';
		break;
	case step_C:
		*codechar++ = base64_encode_value(state_in->result);
		*codechar++ = '=';
		break;
	case step_A:
		break;
	}
	*codechar++ = '\0';
	
	return codechar - code_out;
}

/* Main Nonce gen functionality */

char *init_rand_str(void){
	unsigned int min_digits, max_digits;
	unsigned long seed;
	int dev_random_fd;
	char *rand_str;
	gmp_randstate_t rstate;
	mpz_t rmin, rmax, rnum;
	
	min_digits = 30;
	max_digits = 50;
	
	mpz_init(rmin);
	mpz_ui_pow_ui(rmin, 10, min_digits-1);
	
	mpz_init(rmax);
	mpz_ui_pow_ui(rmax, 10, max_digits);
	
	gmp_randinit_mt(rstate);
	
	mpz_init(rnum);
	
	dev_random_fd = open("/dev/random", O_RDONLY);
	read(dev_random_fd, &seed, sizeof(seed));
	close(dev_random_fd);
	
	gmp_randseed_ui(rstate, seed);
	mpz_urandomm(rnum, rstate, rmax);
	
	rand_str = (char *)malloc(mpz_sizeinbase(rnum, 10)+2);
	mpz_get_str(rand_str, 10, rnum);
	gmp_randclear(rstate);
	return rand_str;
}

extern char *nonce_rand_gen(void){
	/* Declare all used variables */
	base64_encodestate b64_state;
	mpz_t rmin, rmax, rnum;
	unsigned char *hash;
	char *encoded_nonce;
	char *r_str;
	int hash_size, r1, r2, i;
	
	/* Use GMP to make random hash */
	r_str = init_rand_str();
	
	/* Use GNU GCrypt to hash then base64 encode value */
	hash_size = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
	hash = (char*)malloc(sizeof(char)*hash_size);
	gcry_md_hash_buffer(GCRY_MD_SHA256, hash, r_str,strlen(r_str));
	free(r_str);
	
	/* Convert to Base64 */
	encoded_nonce = (char*)malloc(((sizeof(char)*hash_size)*2)+1);
	base64_init_encodestate(&b64_state);
	
	r1 = base64_encode_block(hash, hash_size, encoded_nonce, &b64_state);
	r2 = base64_encode_blockend(encoded_nonce+r1, &b64_state);
		
	base64_init_encodestate(&b64_state);
	free(hash);
	
	return encoded_nonce;
}


/*int main(int argc, char *argv[]){*/
/*	// Do not need to malloc, but need to free*/
/*	char *nonce;*/
/*	nonce = nonce_rand_gen();*/
/*	printf("%s\n", nonce);*/
/*	free(nonce);*/
/*	return 0;*/
/*}*/

