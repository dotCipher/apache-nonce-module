# Makefile for testing
# by: Cody Moore

#### MAIN RULES ####
all: nonce_rand

nonce_rand: nonce_rand.c nonce_rand.h
	gcc -o nonce_rand nonce_rand.c nonce_rand.h -lgmp `libgcrypt-config --cflags --libs`

#### CLEAN RULE ####
clean:
	rm -f nonce_rand
