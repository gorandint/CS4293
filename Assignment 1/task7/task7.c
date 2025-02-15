#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

const char *IV_HEX = "aabbccddeeff00998877665544332211";
const char *CIPHERTEXT_HEX = "764aa26b55a4da654df6b19e4bce00f4ed05e09346fb0e762583cb7da2ac93a2";
const char *PLAINTEXT = "This is a top secret.";
const size_t KEY_SIZE = 16;
const size_t BLOCK_SIZE = 16;
const size_t CIPHERTEXT_SIZE = 32;

void hex_to_bytes(const char *hex, unsigned char *bytes) {
    for (size_t i = 0; i < strlen(hex) / 2; i++) {
        sscanf(&hex[2 * i], "%2hhx", &bytes[i]);
    }
}

void pad_key(const char *word, unsigned char *key) {
    size_t len = strlen(word);
    memcpy(key, word, len);
    memset(key + len, '#', KEY_SIZE - len);
}

int decrypt(const unsigned char *ciphertext, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int len;
    int plaintext_len;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        return 0;

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, CIPHERTEXT_SIZE))
        return 0;
    plaintext_len = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        return 0;
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    plaintext[plaintext_len] = '\0';
    return plaintext_len;
}

int main() {
    FILE *file = fopen("words.txt", "r");
    if (!file) {
        fprintf(stderr, "Could not open words.txt\n");
        return 1;
    }

    unsigned char iv[BLOCK_SIZE];
    unsigned char ciphertext[CIPHERTEXT_SIZE];
    unsigned char key[KEY_SIZE];
    unsigned char decrypted_text[CIPHERTEXT_SIZE];

    hex_to_bytes(IV_HEX, iv);
    hex_to_bytes(CIPHERTEXT_HEX, ciphertext);

    char word[KEY_SIZE];
    int len;
    while (fgets(word, sizeof(word), file)) {
        word[strcspn(word, "\n")] = '\0';
        len = strlen(word);

        if (len == 0)
            continue;
        if (word[len - 1] == '\r') {
            word[len - 1] = '\0';
            len--;
        }
        if (len == 0 || len > KEY_SIZE)
            continue;

        pad_key(word, key);

        if (decrypt(ciphertext, key, iv, decrypted_text) > 0) {
            if (strcmp((char *)decrypted_text, PLAINTEXT) == 0) {
                printf("%s\n", word);
                fclose(file);
                return 0;
            }
        }
    }

    fclose(file);
    printf("Key not found\n");
    return 1;
}