#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define TOKEN_SIZE 32
#define HASH_SIZE 32
#define KEY_FILE "secret.key"  // File containing the secret key

char* generate_token_and_hash();
int verify_token_and_hash(const char* token_hash);
void uchar_to_hex(const unsigned char* uchar, size_t size, char* hex);
void hex_to_uchar(const char* hex, unsigned char* uchar, size_t size);
char* load_secret_key_from_file(const char* file_path);

char* generate_token_and_hash() {
    unsigned char token[TOKEN_SIZE];
    unsigned char hash[HASH_SIZE];
    unsigned int hash_len = HASH_SIZE;
    char* result = NULL;

    char* secret_key = load_secret_key_from_file(KEY_FILE);
    if (!secret_key) {
        return NULL;
    }

    if (RAND_bytes(token, TOKEN_SIZE) != 1) {
        free(secret_key);
        return NULL;
    }

    HMAC(EVP_sha256(), secret_key, strlen(secret_key), token, TOKEN_SIZE, hash, &hash_len);

    char token_hex[TOKEN_SIZE * 2 + 1];
    char hash_hex[HASH_SIZE * 2 + 1];
    uchar_to_hex(token, TOKEN_SIZE, token_hex);
    uchar_to_hex(hash, HASH_SIZE, hash_hex);

    result = (char*) malloc(TOKEN_SIZE * 2 + HASH_SIZE * 2 + 2);
    if (result) {
        sprintf(result, "%s.%s", token_hex, hash_hex);
    }

    free(secret_key);
    return result; 
}

int verify_token_and_hash(const char* token_hash) {
    char* token_hex = NULL;
    char* hash_hex = NULL;
    unsigned char token[TOKEN_SIZE];
    unsigned char original_hash[HASH_SIZE];
    unsigned char computed_hash[HASH_SIZE];
    unsigned int hash_len = HASH_SIZE;

    char* secret_key = load_secret_key_from_file(KEY_FILE);
    if (!secret_key) {
        return 0;
    }

    token_hex = strtok(strdup(token_hash), ".");
    hash_hex = strtok(NULL, ".");

    if (!token_hex || !hash_hex) {
        free(secret_key);
        return 0;
    }

    hex_to_uchar(token_hex, token, TOKEN_SIZE);
    hex_to_uchar(hash_hex, original_hash, HASH_SIZE);

    HMAC(EVP_sha256(), secret_key, strlen(secret_key), token, TOKEN_SIZE, computed_hash, &hash_len);

    free(secret_key);

    return CRYPTO_memcmp(computed_hash, original_hash, HASH_SIZE) == 0;
}

void uchar_to_hex(const unsigned char* uchar, size_t size, char* hex) {
    for (size_t i = 0; i < size; ++i) {
        sprintf(hex + (i * 2), "%02x", uchar[i]);
    }
    hex[size * 2] = '\0'; 
}

void hex_to_uchar(const char* hex, unsigned char* uchar, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        sscanf(hex + (i * 2), "%2hhx", &uchar[i]);
    }
}

char* load_secret_key_from_file(const char* file_path) {
    FILE* file = fopen(file_path, "r");
    if (!file) {
        printf("Failed to open key file: %s\n", file_path);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* secret_key = (char*) malloc(file_size + 1);
    if (!secret_key) {
        fclose(file);
        return NULL;
    }

    fread(secret_key, 1, file_size, file);
    secret_key[file_size] = '\0';

    fclose(file);
    return secret_key;
}

int main() {
    char* token_hash = generate_token_and_hash();
    if (token_hash) {
        printf("Generated Token.Hash: %s\n", token_hash);
    } else {
        printf("Failed to generate token.\n");
        return 1;
    }

    if (verify_token_and_hash(token_hash)) {
        printf("Token and hash verified successfully.\n");
    } else {
        printf("Token and hash verification failed.\n");
    }

    free(token_hash);  // Free the allocated memory
    return 0;
}
