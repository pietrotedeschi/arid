/*
 * Copyright 2020-2021. All Rights Reserved.
 *
 * Licensed under the ARID license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/pietrotedeschi/arid/blob/master/LICENSE
 */

#include "arid.h"

#define EC_NID NID_secp160r1              //160 EC
#define BUFFER_LENGTH 4 + 40 + 9 + 4 + 10 //ID + Signature in DER + TS + BIGNUM

// #define EC_NID NID_secp192k1 //192 EC
// #define BUFFER_LENGTH		        4+48+9+4+10 //ID + Signature in DER + TS + BIGNUM

// #define EC_NID NID_secp224k1 //224 EC
// #define BUFFER_LENGTH		        4+56+9+4+10 //ID + Signature in DER + TS + BIGNUM

// #define EC_NID NID_secp256k1              //256 EC
// #define BUFFER_LENGTH 4 + 64 + 9 + 4 + 10 //ID + Signature in DER + TS + BIGNUM

int main()
{
    ARID_init();

    // System Parameters
    BN_CTX *ctx;
    EC_GROUP *curve;
    const EC_POINT *G;
    BIGNUM *q = NULL;

    ctx = BN_CTX_new();
    q = BN_new();

    // Read the generator and order of the curve
    curve = EC_GROUP_new_by_curve_name(EC_NID);
    G = EC_GROUP_get0_generator(curve);
    EC_GROUP_get_order(curve, q, ctx);

    BIGNUM *prime = BN_new();
    EC_GROUP_get_curve_GFp(curve, prime, NULL, NULL, ctx);
    int curve_size = BN_num_bits(prime);          // Curve size in bits
    int curve_size_byte = BN_num_bits(prime) / 8; // Curve size in bytes
    unsigned int Lf = (curve_size + 7) / 8;

    if (curve_size < 160)
    {
        fprintf(stderr, "Skip the curve %s (degree = %d)\n",
                OBJ_nid2sn(EC_NID), curve_size);
        exit(-1);
    }

    // Set the compression form
    EC_GROUP_set_point_conversion_form(curve, POINT_CONVERSION_UNCOMPRESSED);

    // Precompute multiples of G (faster multiplications)
    EC_GROUP_precompute_mult(curve, ctx);

    // Hashing Function
    EVP_MD_CTX *hashctx;
    hashctx = EVP_MD_CTX_create();
    const EVP_MD *hashptr = EVP_get_digestbyname("SHA256");

    // AES-128-CBC Initialization Vector
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, sizeof(iv));

    unsigned char cm[BUFFER_LENGTH]; //ciphertext/plaintext
    EVP_CIPHER_CTX *en_ctx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_init(en_ctx);

    //Crypto Material Authority (in a real deplyment, the keys are pre-generated)
    BIGNUM *prv_Auth = NULL; //Private Key Auth
    EC_POINT *pbl_Auth;      //Public Key Auth
    setupKey(&prv_Auth, &pbl_Auth, q, G, curve, ctx);

    //Material & Crypto Material UAV
    int ID = 0xFECAFECA; // Real UAV Identity (4 bytes)
    uint8_t es = 11;     // emergency status

    BIGNUM *prv_A = NULL;        //Private Key UAV
    EC_POINT *pbl_A;             //Public Key UAV
    unsigned int padLen;         //Pad Length
    unsigned int encLen, decLen; //ElGamal Parameters

    //char *encData, *decData;
    unsigned char aes_key[curve_size_byte + 1]; // AES Symmetric Key
    memset(aes_key, 0, curve_size_byte + 1);

    //Crypto Material UAV (in a real deplyment, the keys are pre-generated)
    setupKey(&prv_A, &pbl_A, q, G, curve, ctx);

    float lat, lon, alt;
    time_t ts;
    BIGNUM *v = NULL;

    EC_KEY *ec_key_prv_A = EC_KEY_new();
    EC_KEY_set_group(ec_key_prv_A, curve);
    EC_KEY_set_private_key(ec_key_prv_A, prv_A);

    /*TEST SOCKET*/
    ECDSA_SIG *sig = NULL;
    int sock;
    struct sockaddr_in locAddr;
    struct sockaddr_in targetAddr;
    uint8_t buf[MAV_BUFFER_LENGTH];
    ssize_t recsize;
    socklen_t fromlen;
    int local_port = 14550; //Listening port
    int dest_port = 14551;  //Sending port

    int i;
    unsigned int temp = 0;

    mavlink_channel_t chan = MAVLINK_COMM_0; // Variable of type mavlink channel
    mavlink_message_t msg;                   // Variable of type mavlink message
    mavlink_status_t status;                 // Variable of type mavlink status
    mavlink_global_position_int_t gps_position;

    mavlink_message_t msg_brd;
    uint8_t mav[262];
    unsigned char dp[AES_KEYLENGTH / 8 + 1];
    unsigned char buffer[256];
    unsigned char h[EVP_MAX_MD_SIZE];
    unsigned char pay[262] = "";
#ifdef DEBUG
    int n = 1;
#endif

    /* Init the socket to receive datagram and support UDP protocol */
    if (initialize_UDP(&sock, &locAddr, &targetAddr, local_port, dest_port) == -1)
    {
        return -1;
    }

    for (;;)
    {
        memset(buf, 0, MAV_BUFFER_LENGTH);
        recsize = recvfrom(sock, (void *)buf, MAV_BUFFER_LENGTH, 0, (struct sockaddr *)&locAddr, &fromlen); // reception
        /* Something received */
        if (recsize > 0)
        {
#ifdef DEBUG
            printf("Bytes Received : %d\n", (int)recsize); //Size
#endif
            /* For each part of the tram */
            for (i = 0; i < recsize; ++i)
            {
                temp = buf[i];
#ifdef DEBUG
                printf("%02x ", (unsigned char)temp); //Field of the tram in hexadecimal
#endif

                /* Parse the tram in order to get a mavlink message */
                if (mavlink_parse_char(chan, buf[i], &msg, &status))
                {
                    /* Information about the packet received */
                    //printf("\nReceived packet: SYS: %d, COMP: %d, LEN: %d, MSG ID: %d\n\n", msg.sysid, msg.compid, msg.len, msg.msgid);
                    if (msg.msgid == MAVLINK_MSG_ID_GLOBAL_POSITION_INT) //If the message is of type SYS_STATUS
                    {

                        clock_t start = clock();

                        /* Decode informations of the message and put it in the variable */
                        mavlink_msg_global_position_int_decode(&msg, &gps_position);
#ifdef DEBUG
                        printf("LAT:%d, LON:%d, ALT:%d, TIME:%d", gps_position.lat, gps_position.lon, gps_position.alt, gps_position.time_boot_ms);
#endif

                        v = BN_new();
                        BN_rand_range(v, q);

                        //Proof of Concept --- Controller coordinates fixed
                        data info = {ID, gps_position.lat, gps_position.lon, gps_position.alt, gps_position.vx, gps_position.vy, gps_position.vz, gps_position.time_boot_ms, gps_position.lat, gps_position.lon, gps_position.alt, es, v}; // Put the data into a structure

                        memset(buffer, 0, 256);
                        snprintf(buffer, sizeof(data), "%X%d%d%d%d%d%d%d%d%d%d%d%s", info.ID, info.lat, info.lon, info.alt, info.vx, info.vy, info.vz, info.ts, info.lat, info.lon, info.alt, info.em_status, BN_bn2hex(info.v));

                        memset(h, 0, EVP_MAX_MD_SIZE);
                        digest(hashctx, hashptr, buffer, h);

                        sig = ECDSA_SIG_new();
                        sig = ECDSA_do_sign(h, EVP_MAX_MD_SIZE, ec_key_prv_A);
                        if (NULL == sig)
                        {
                            printf(RED "[ERROR] Failed to generate EC Signature\n" RESET);
                        }

                        /* Generate One Time Key and Pad the Key for Elgamal Encryption */
                        memset(aes_key, 0, curve_size_byte + 1);
                        getPadOneTimeKey(Lf, curve_size, curve, ctx, aes_key);

                        /* ElGamal Encryption */
                        char *encData = NULL;
#ifdef DEBUG
                        printf("\n< Encrypt >\n");
#endif
                        encLen = elgamal_encrypt(&encData, aes_key, Lf, pbl_Auth, curve, ctx, prime);
                        if (!encLen)
                        {
                            printf(RED "[ERROR] Encrypt error\n" RESET);
                            return 1;
                        }

#ifdef DEBUG
                        hex_print(encData, encLen);
                        printf("\n");
                        printf(" Encrypt length = %d\n", encLen);
#endif
                        /* Generate Pseudonym */
                        unsigned char pseudonym[BUFFER_LENGTH];
                        memset(pseudonym, 0, sizeof(pseudonym));

                        uint8_t *sig_p = NULL;
                        int32_t sig_size = i2d_ECDSA_SIG(sig, &sig_p); // Signature in DER format

                        memcpy(pseudonym, &ID, sizeof(int));
                        memcpy(pseudonym + sizeof(int), sig_p, sig_size);
                        memcpy(pseudonym + sizeof(int) + sig_size, &ts, sizeof(uint32_t));
                        memcpy(pseudonym + sizeof(int) + sig_size + sizeof(uint32_t), &v, 10);

                        memset(cm, 0, BUFFER_LENGTH);
                        encrypt_decrypt(en_ctx, aes_key, iv, pseudonym, cm, true); //Encrypt (for the UAV part)
                        memset(mav, 0, 262);
                        memset(pay, 0, 262);

                        memcpy(pay, cm, BUFFER_LENGTH);
                        memcpy(pay + BUFFER_LENGTH, encData, encLen);
                        memcpy(pay + BUFFER_LENGTH + encLen, (char *)&gps_position.lat, sizeof(gps_position.lat));
                        memcpy(pay + BUFFER_LENGTH + encLen + sizeof(int32_t) * 1, (char *)&gps_position.lon, sizeof(gps_position.lon));
                        memcpy(pay + BUFFER_LENGTH + encLen + sizeof(int32_t) * 2, (char *)&gps_position.alt, sizeof(gps_position.alt));
                        memcpy(pay + BUFFER_LENGTH + encLen + sizeof(int32_t) * 3, (char *)&gps_position.vx, sizeof(gps_position.vx));
                        memcpy(pay + BUFFER_LENGTH + encLen + sizeof(int32_t) * 3 + sizeof(int16_t) * 1, (char *)&gps_position.vy, sizeof(gps_position.vy));
                        memcpy(pay + BUFFER_LENGTH + encLen + sizeof(int32_t) * 3 + sizeof(int16_t) * 2, (char *)&gps_position.vz, sizeof(gps_position.vz));
                        memcpy(pay + BUFFER_LENGTH + encLen + sizeof(int32_t) * 3 + sizeof(int16_t) * 3, (char *)&gps_position.lat, sizeof(gps_position.lat));
                        memcpy(pay + BUFFER_LENGTH + encLen + sizeof(int32_t) * 4 + sizeof(int16_t) * 3, (char *)&gps_position.lon, sizeof(gps_position.lon));
                        memcpy(pay + BUFFER_LENGTH + encLen + sizeof(int32_t) * 5 + sizeof(int16_t) * 3, (char *)&gps_position.alt, sizeof(gps_position.alt));
                        memcpy(pay + BUFFER_LENGTH + encLen + sizeof(int32_t) * 6 + sizeof(int16_t) * 3, (char *)&gps_position.time_boot_ms, sizeof(gps_position.time_boot_ms));
                        memcpy(pay + BUFFER_LENGTH + encLen + sizeof(int32_t) * 7 + sizeof(int16_t) * 3, &es, sizeof(es));

                        printf(YEL "[INFO] Sending ARID Packet\n" RESET);
                        mavlink_msg_arid_protocol_pack(0, 0, &msg_brd, 0, 0, 0, pay);
                        uint16_t len = mavlink_msg_to_send_buffer(mav, &msg_brd);
                        int bytes_sent = sendto(sock, mav, len, 0, (struct sockaddr *)&targetAddr, sizeof(struct sockaddr_in));
#ifdef DEBUG
                        clock_t stop = clock();
                        double elapsed = (double)(stop - start) * 1000.0 / CLOCKS_PER_SEC;
                        printf(RED "%d,%f\n" RESET, n, elapsed);
#endif

#ifdef DEBUG
                        printf("\n-------------------ELGAMAL DECRYPT------------------\n");

                        /* decrypt */
                        char *decData = NULL;
                        printf("\n< Decrypt >\n");
                        decLen = elgamal_decrypt(&decData, encData, (curve_size_byte + 1) * 2, prv_Auth, curve, ctx);
                        printf(" Decrypt length = %d\n", decLen);

                        memset(dp, 0, AES_KEYLENGTH / 8 + 1);
                        unPadKey(decData, decLen, dp);
                        printf("\n< KEY >\n");
                        hex_print(dp, AES_KEYLENGTH / 8);

                        encrypt_decrypt(en_ctx, dp, iv, cm, pseudonym, false); //Decrypt (for the Authority part)
#endif
                    }
                }
            }
        }
    }

    // Close the socket:
    close(sock);
    clean(curve, ctx, hashctx, en_ctx);
    return 0;
}

void ARID_init()
{
    // makes all algorithms available to the EVP* routines
    OpenSSL_add_all_algorithms();
    // load the error strings for ERR_error_string
    ERR_load_crypto_strings();

    // seed PRNG
    if (RAND_load_file("/dev/urandom", 256) < 64)
    {
        printf(RED "[ERROR] Can't seed PRNG!\n" RESET);
        abort();
    }
}

void clean(EC_GROUP *grp, BN_CTX *ctx, EVP_MD_CTX *htx, EVP_CIPHER_CTX *enctx)
{
    fflush(stdout);
    BN_CTX_free(ctx);
    EC_GROUP_free(grp);
    EVP_MD_CTX_destroy(htx);
    CRYPTO_cleanup_all_ex_data();
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_set_id_callback(NULL);
    EVP_CIPHER_CTX_cleanup(enctx);
    EVP_CIPHER_CTX_free(enctx);
}

static void hex_print(const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    if (NULL == data)
        printf("NULL");
    else
    {
        size_t i = 0;
        for (; i < len; ++i)
            printf("%02X", *p++);
    }
    printf("\n");
}

void getPadOneTimeKey(int Lf, int curve_size, EC_GROUP *curve, BN_CTX *ctx, unsigned char *key)
{
    /* Generate One Time Key and Pad it*/
    EC_POINT *M = NULL;
    BIGNUM *m = NULL;
    int rv = 0;
#ifdef DEBUG
    printf(GRN "[INFO] Degree = %d\n" RESET, curve_size);
    printf(GRN "[INFO] Field length = %d\n" RESET, Lf);
#endif

#ifdef DEBUG
    printf("\n< Generate Message (EC Point) >\n");
#endif
    /* message with some random data */
    if ((AES_KEYLENGTH / 8) - 1 > Lf)
    {
        fprintf(stderr, RED "[ERROR] Data length error (> Field length)\n" RESET);
    }

    unsigned int padLen = Lf - (AES_KEYLENGTH / 8);
#ifdef DEBUG
    printf("PADLEN:%d\n", padLen);
#endif
    m = BN_new();
    M = EC_POINT_new(curve);
    do
    {
        /* AES ONE TIME SYMMETRIC KEY GENERATION */
        if (!RAND_pseudo_bytes(key, (AES_KEYLENGTH / 8)))
        {
            fprintf(stderr, RED "[ERROR] Unable to get random data\n" RESET);
        }
        /* M || 8000...00 */
        key[(AES_KEYLENGTH / 8)] = 0x80;
        for (int i = 1; i <= padLen; i++)
        {
            key[(AES_KEYLENGTH / 8) + i] = 0x00;
        }
        BN_bin2bn(key, Lf, m);
#ifdef DEBUG
        printf(" m = ");
        BN_print_fp(stdout, m);
        puts("");
#endif
        rv = EC_POINT_set_compressed_coordinates_GFp(curve, M, m, 1, ctx);
    } while (rv == 0);
#ifdef DEBUG
    printf(GRN "[INFO] AES Key:\n" RESET);
    hex_print(key, 16);
    printf("\n");
    printf(GRN "[INFO] Data (Padding):\n" RESET);
    hex_print(data, Lf);
#endif
}

void unPadKey(char *decData, unsigned int decLen, unsigned char *pl)
{
    char *dp;
    if (!decLen)
    {
        printf(RED "[ERROR] Decrypt error\n" RESET);
        exit(-1);
    }
    dp = decData + 1;
    decLen--;

    /* Unpadding */
    unsigned int padLen = 0;
    for (unsigned int i = decLen - 1; i > 0; i--)
    {
        if (dp[i] == 0x00)
        {
            padLen++;
        }
        else if (dp[i] == 0x80)
        {
            padLen++;
            break;
        }
    }
    decLen -= padLen;

#ifdef DEBUG
    printf(GRN "[INFO] Decrypted DATA:\n" RESET);
    hex_print(dp, decLen);
    printf("\n");
#endif
    strncpy(pl, dp, decLen);
}

void encrypt_decrypt(EVP_CIPHER_CTX *ectx, char *key, char *iv, unsigned char *in, unsigned char *out, bool ENCRYPT)
{
    int otl1, otl2;

    if (ENCRYPT)
    {
#ifdef DEBUG
        printf(GRN "[INFO] Original:\t" RESET);
        hex_print(in, BUFFER_LENGTH);
#endif

        EVP_EncryptInit(ectx, EVP_aes_128_cbc(), key, iv);
        EVP_EncryptUpdate(ectx, out, &otl1, in, BUFFER_LENGTH);
        EVP_EncryptFinal(ectx, out + otl1, &otl2);
#ifdef DEBUG
        printf(GRN "[INFO] Ciphertext length: %d\n" RESET, otl1 + otl2);
        printf(GRN "[INFO] Encrypt:\t" RESET);
        hex_print(out, BUFFER_LENGTH);
#endif
    }
    else
    {
        EVP_DecryptInit(ectx, EVP_aes_128_cbc(), key, iv);
        EVP_DecryptUpdate(ectx, out, &otl1, in, BUFFER_LENGTH);
        EVP_DecryptFinal(ectx, out + otl1, &otl2);
#ifdef DEBUG
        printf("text length: %d\n", otl1 + otl2);
        printf("decrypt:\t");
        printf("%s\n", out);
        printf("DECRYPTION:\t");
        hex_print(out, BUFFER_LENGTH);
#endif
    }
}

static int setupKey(BIGNUM **prv, EC_POINT **pbl, BIGNUM *q, const EC_POINT *G, EC_GROUP *curve, BN_CTX *ctx)
{
    *pbl = EC_POINT_new(curve);
    *prv = BN_new();

    BN_rand_range(*prv, q);
    EC_POINT_mul(curve, *pbl, NULL, G, *prv, ctx);

    return 0;
}

void digest(EVP_MD_CTX *hctx, const EVP_MD *hptr, char *data, unsigned char *hash)
{
    unsigned int ol = 0;
    EVP_DigestInit_ex(hctx, hptr, NULL);
    EVP_DigestUpdate(hctx, data, strlen(data));
    EVP_DigestFinal_ex(hctx, hash, &ol);
#ifdef DEBUG
    hex_print(hash, ol);
#endif
    fflush(stdout);
    EVP_MD_CTX_init(hctx);
}

/**
 * ElGamal Encryption
 */
int elgamal_encrypt(char **encData, char *data, int dataLen, const EC_POINT *ecpubl, EC_GROUP *group, BN_CTX *ctx, BIGNUM *p)
{
    BIGNUM *r = NULL, *m;
    EC_POINT *C1 = NULL, *C2 = NULL;
    EC_POINT *Tmp = NULL, *M;
    const EC_POINT *Pkey;
    int c1Len, c2Len;
    int rv;

    EC_GROUP_get_curve_GFp(group, p, NULL, NULL, ctx);

    /* C1 = r*G */
    C1 = EC_POINT_new(group);

    /* generate random number r */
    r = BN_new();
    M = EC_POINT_new(group);
    m = BN_new();
    do
    {
        if (!BN_rand_range(r, p))
        {
            return 0;
        }
    } while (BN_is_zero(r));

    EC_POINT_mul(group, C1, r, NULL, NULL, ctx);

    /* C2 = r*P + M */
    /* M */
    BN_bin2bn(data, dataLen, m);
    rv = EC_POINT_set_compressed_coordinates_GFp(group, M, m, 1, ctx);

    C2 = EC_POINT_new(group);
    Tmp = EC_POINT_new(group);
    Pkey = ecpubl;
    EC_POINT_mul(group, Tmp, NULL, Pkey, r, ctx);
    EC_POINT_add(group, C2, Tmp, M, ctx);

    /* cipher text C = (C1, C2) */
    c1Len = EC_POINT_point2oct(group, C1, POINT_CONVERSION_COMPRESSED,
                               NULL, 0, ctx);

    c2Len = EC_POINT_point2oct(group, C2, POINT_CONVERSION_COMPRESSED,
                               NULL, 0, ctx);

    *encData = OPENSSL_malloc(c1Len + c2Len);
    EC_POINT_point2oct(group, C1, POINT_CONVERSION_COMPRESSED,
                       *encData, c1Len, ctx);
    EC_POINT_point2oct(group, C2, POINT_CONVERSION_COMPRESSED,
                       *encData + c1Len, c2Len, ctx);

    //BN_clear_free(p);
    BN_clear_free(r);
    BN_clear_free(m);
    EC_POINT_free(C1);
    EC_POINT_free(C2);
    EC_POINT_free(M);
    EC_POINT_free(Tmp);
    // BN_CTX_free(ctx);

    return (c1Len + c2Len);
}

/**
 * ElGamal Decryption
 */
int elgamal_decrypt(char **decData, char *encData, int encLen, BIGNUM *prvKey, EC_GROUP *group, BN_CTX *ctx)
{
    int rv;
    EC_POINT *C1 = NULL, *C2 = NULL;
    EC_POINT *M = NULL, *Tmp = NULL;

    C1 = EC_POINT_new(group);
    C2 = EC_POINT_new(group);
    ctx = BN_CTX_new();

    /* C1 */
    rv = EC_POINT_oct2point(group, C1, encData, encLen / 2, ctx);
    if (!rv)
    {
        fprintf(stderr, RED "[ERROR] EC_POINT_oct2point error (C1)\n" RESET);
        return 0;
    }

    /* C2 */
#ifdef DEBUG
    printHex("C2", encData + encLen / 2, encLen / 2);
#endif
    rv = EC_POINT_oct2point(group, C2, encData + encLen / 2, encLen / 2,
                            ctx);
    if (!rv)
    {
        fprintf(stderr, RED "[ERROR] EC_POINT_oct2point error (C2)\n" RESET);
        return 0;
    }
    Tmp = EC_POINT_new(group);
    M = EC_POINT_new(group);

    /* M = C2 - x C1 */
    EC_POINT_mul(group, Tmp, NULL, C1, prvKey, ctx);
    EC_POINT_invert(group, Tmp, ctx);
    EC_POINT_add(group, M, C2, Tmp, ctx);

    /* Output M */
    rv = EC_POINT_point2oct(group, M, POINT_CONVERSION_COMPRESSED, NULL, 0,
                            ctx);

#ifdef DEBUG
    printf(" Point converted length = %d\n", rv);
#endif
    *decData = OPENSSL_malloc(rv);
    EC_POINT_point2oct(group, M, POINT_CONVERSION_COMPRESSED, *decData,
                       rv, ctx);
    EC_POINT_free(C1);
    EC_POINT_free(C2);
    EC_POINT_free(M);
    EC_POINT_free(Tmp);
    //BN_CTX_free(ctx);
    return rv;
}

int initialize_UDP(int *sock, struct sockaddr_in *locAddr, struct sockaddr_in *targetAddr, int local_port, int dest_port)
{

    memset(locAddr, 0, sizeof(locAddr));
    locAddr->sin_family = AF_INET;
    locAddr->sin_addr.s_addr = INADDR_ANY;
    locAddr->sin_port = htons(local_port);

    memset(targetAddr, 0, sizeof(targetAddr));
    targetAddr->sin_family = AF_INET;
    //targetAddr->sin_addr.s_addr = INADDR_BROADCAST;
    targetAddr->sin_addr.s_addr = inet_addr("10.1.1.255");
    targetAddr->sin_port = htons(dest_port);

    *sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int broadcastEnable = 1;
    setsockopt(*sock, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));
    setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &broadcastEnable, sizeof(broadcastEnable));

    if (-1 == bind(*sock, (struct sockaddr *)locAddr, sizeof(struct sockaddr)))
    {
        perror(RED "[ERROR] Bind failed." RESET);
        close(*sock);
        return -1;
    }

    /* Initialization listenning done */
    printf(GRN "[INFO] Congratulations! Connection established with the UAV.\n[INFO] UDPin: 0.0.0.0:%d\n" RESET, ntohs(locAddr->sin_port));

/* Attempt to make it non blocking */
#if (defined __QNX__) | (defined __QNXNTO__)
    if (fcntl(*sock, F_SETFL, O_NONBLOCK | FASYNC) < 0)
#else
    if (fcntl(*sock, F_SETFL, O_NONBLOCK | O_ASYNC) < 0)
#endif
    {
        fprintf(stderr, RED "[ERROR] Setting non blocking: %s\n" RESET, strerror(errno));
        close(*sock);
        return -1;
    }
}
