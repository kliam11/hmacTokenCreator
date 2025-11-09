#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define TOKEN_SIZE 32   // 32 bytes token
#define HASH_SIZE 32    // 32 bytes HMAC-SHA256
#define KEY_FILE "secret.key"  // File containing the secret key

// Function prototypes
char* generate_token_and_hash();
int verify_token_and_hash(const char* token_hash);
void uchar_to_hex(const unsigned char* uchar, size_t size, char* hex);
void hex_to_uchar(const char* hex, unsigned char* uchar, size_t size);
char* load_secret_key_from_file(const char* file_path);

// Generates a token and its HMAC hash, returns token.hash as a string
char* generate_token_and_hash() {
    unsigned char token[TOKEN_SIZE];
    unsigned char hash[HASH_SIZE];
    unsigned int hash_len = HASH_SIZE;
    char* result = NULL;

    // Load the secret key from the file
    char* secret_key = load_secret_key_from_file(KEY_FILE);
    if (!secret_key) {
        return NULL;  // Failed to load secret key
    }

    // Generate random token
    if (RAND_bytes(token, TOKEN_SIZE) != 1) {
        free(secret_key);
        return NULL; // Failed to generate token
    }

    // Generate HMAC hash of the token using the secret key
    HMAC(EVP_sha256(), secret_key, strlen(secret_key), token, TOKEN_SIZE, hash, &hash_len);

    // Convert token and hash to hexadecimal format
    char token_hex[TOKEN_SIZE * 2 + 1];
    char hash_hex[HASH_SIZE * 2 + 1];
    uchar_to_hex(token, TOKEN_SIZE, token_hex);
    uchar_to_hex(hash, HASH_SIZE, hash_hex);

    // Concatenate token and hash with a dot separator
    result = (char*) malloc(TOKEN_SIZE * 2 + HASH_SIZE * 2 + 2);  // Allocating space
    if (result) {
        sprintf(result, "%s.%s", token_hex, hash_hex);
    }

    free(secret_key);  // Free the loaded secret key
    return result;  // Return token.hash string
}

// Verifies if the given token and hash are valid
int verify_token_and_hash(const char* token_hash) {
    char* token_hex = NULL;
    char* hash_hex = NULL;
    unsigned char token[TOKEN_SIZE];
    unsigned char original_hash[HASH_SIZE];
    unsigned char computed_hash[HASH_SIZE];
    unsigned int hash_len = HASH_SIZE;

    // Load the secret key from the file
    char* secret_key = load_secret_key_from_file(KEY_FILE);
    if (!secret_key) {
        return 0;  // Failed to load secret key
    }

    // Split the input into token and hash
    token_hex = strtok(strdup(token_hash), ".");
    hash_hex = strtok(NULL, ".");

    if (!token_hex || !hash_hex) {
        free(secret_key);
        return 0;  // Invalid format
    }

    // Convert hex back to binary
    hex_to_uchar(token_hex, token, TOKEN_SIZE);
    hex_to_uchar(hash_hex, original_hash, HASH_SIZE);

    // Recompute the hash of the token using the secret key
    HMAC(EVP_sha256(), secret_key, strlen(secret_key), token, TOKEN_SIZE, computed_hash, &hash_len);

    free(secret_key);  // Free the loaded secret key

    // Compare the original hash with the newly computed hash
    return CRYPTO_memcmp(computed_hash, original_hash, HASH_SIZE) == 0;
}

// Helper function to convert binary data to hexadecimal string
void uchar_to_hex(const unsigned char* uchar, size_t size, char* hex) {
    for (size_t i = 0; i < size; ++i) {
        sprintf(hex + (i * 2), "%02x", uchar[i]);
    }
    hex[size * 2] = '\0';  // Null-terminate the string
}

// Helper function to convert hexadecimal string back to binary data
void hex_to_uchar(const char* hex, unsigned char* uchar, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        sscanf(hex + (i * 2), "%2hhx", &uchar[i]);
    }
}

// Loads the secret key from a file
char* load_secret_key_from_file(const char* file_path) {
    FILE* file = fopen(file_path, "r");
    if (!file) {
        printf("Failed to open key file: %s\n", file_path);
        return NULL;
    }

    // Find out the file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory for the secret key
    char* secret_key = (char*) malloc(file_size + 1);
    if (!secret_key) {
        fclose(file);
        return NULL;
    }

    // Read the secret key from the file
    fread(secret_key, 1, file_size, file);
    secret_key[file_size] = '\0';  // Null-terminate the secret key

    fclose(file);
    return secret_key;
}

int main() {
    // Generate a token and hash
    char* token_hash = generate_token_and_hash();
    if (token_hash) {
        printf("Generated Token.Hash: %s\n", token_hash);
    } else {
        printf("Failed to generate token.\n");
        return 1;
    }

    // Verify the token and hash
    if (verify_token_and_hash(token_hash)) {
        printf("Token and hash verified successfully.\n");
    } else {
        printf("Token and hash verification failed.\n");
    }

    free(token_hash);  // Free the allocated memory
    return 0;
}
