#ifndef TOKEN_H
#define TOKEN_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>

int get_pkey(unsigned char **key, size_t *key_len);

int get_tk_hash(char** tk_hash);

int verify_tk_hash(char* tk_hash);

int gen_32byte_token(unsigned char* tk);

void uchar_to_hex(const unsigned char* uchar, size_t uchar_size, char* hex);

void hex_to_uchar(const char* hex, unsigned char* uchar, size_t uchar_size);

#endif