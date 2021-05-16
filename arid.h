#ifndef ARID_H_
#define ARID_H_

# ifndef OPENSSL_NO_STDIO
	#include <stdio.h>
	#include <stdlib.h>
	#include <sys/time.h>
	#include <time.h>
	#include <string.h>
	#include <assert.h>
	#include <stdbool.h>
	#include <mavlink.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <netdb.h>
	#include <unistd.h>
	#include <fcntl.h>
# endif

#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>

#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"


#define AES_KEYLENGTH 		128
#define MAV_BUFFER_LENGTH	2041

typedef struct __attribute__((packed))
{
	int 			ID;
	int32_t 		lat;
	int32_t 		lon;
	int32_t 		alt;
	int16_t 		vx;
	int16_t 		vy;
	int16_t 		vz;
	uint32_t	 	ts;
	int32_t 		ctrl_lat;
	int32_t 		ctrl_lon;
	int32_t 		ctrl_alt;
	uint8_t			em_status; //emergency status
	BIGNUM 			*v; //nonce
} data;

void ARID_init();

static int setupKey(BIGNUM **prv, EC_POINT **pbl, BIGNUM *q, const EC_POINT *G, EC_GROUP *curve, BN_CTX *ctx);

static void hex_print(const void*, size_t);

void getPadOneTimeKey(int, int, EC_GROUP *, BN_CTX *, unsigned char *);

void unPadKey(char *, unsigned int , unsigned char *);

void encrypt_decrypt(EVP_CIPHER_CTX *, char *, char *, unsigned char *, unsigned char *, bool);

void clean(EC_GROUP *g, BN_CTX *c, EVP_MD_CTX *h, EVP_CIPHER_CTX *enc);

double print_time(struct timeval *s, struct timeval *e);

void digest(EVP_MD_CTX *ctx, const EVP_MD *ptr, char *buffer, unsigned char *dig);

int elgamal_encrypt(char **, char *, int , const EC_POINT *, EC_GROUP *, BN_CTX *, BIGNUM *);

int elgamal_decrypt(char **, char *, int , BIGNUM *, EC_GROUP *, BN_CTX *);

int initialize_UDP(int *, struct sockaddr_in *, struct sockaddr_in *, int , int );

#endif