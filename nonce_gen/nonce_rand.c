#include "nonce_rand.h"

/* Must install GMP library */
/* Must install LIBGCRYPT library */


char *init_rand_str(){
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

char *nonce_rand_gen(){
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

