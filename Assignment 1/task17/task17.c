#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

const char* ca_pk_n_hex = "D081C13923C2B1D1ECF757DD55243691202248F7FCCA520AB0AB3F33B5B08407F6DF4E7AB0FB98223D01AC56FB716DB2EEB9A00F5277AB9893BE338AEB875EC7AAB0CA698F43086A3F22BF333946D594F2E24C0522D9678091F1044A0E9B7CA2C9D26CFD3C0984BDFD6B149A811DE78A83EF6116754798133B0D901698BF8AE22732539999C3FB961C35F762ED8CBD4971D24343A1A1E3212A2370A8753DB26C4606616F1867E4297EB23CC1C55F091E6E444EEC2199581548F455482AB734B405E37C498C0058DE3A96CC39DC613355CE2A2E3FD19962E8AAE6347631AAAF79299678CB8114AF69DAFB04B9598344AA094FB4D42C019D9B94316B2DA1CFC1E5";
const char* ca_pk_e_hex = "010001";
const char* ca_sign_hex = "44f7833bfb6d3b0e9b7418db4f272415b3aea1c8f2946564046650bb2c5282d83840fe6aac130651a3ff449ff837ae695684cda6cd832307111f29819ab2c4da138a448d9b4ca189136e3f41622e3c4bc5b2ccf173e49a066ff9826d85ea6a7918c5c4bd4d38dc2581d2698367d87fa7015b385a02e38e4c4cf5a5c2ed9548ef39fa9abfb29ebe342f2560d5002833af59bf5a3a7b627e3ee5db440750c29d5d3cd79d8848e7fa4695c6dfc19af4e05faee227160896595603454926a5759826dfce6bdc13ffad29b440e60d1718c15edf197b724c28b9b2c83bd21f43a5f3a48cc9f2b44229b74866c12b86307d90fd8657fb54fbbb4ce74f64c0eeb6dc2a86";
const char* body_sha256_hex = "71acc1c7e4f4873a4d250354a84174640eb303096dad3b2cb0f1628b315fbb7b";

void printBN(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int hex2bin(const char* hex, unsigned char* bin, size_t bin_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || bin_len < hex_len / 2) {
        return -1;
    }

    for (size_t i = 0; i < hex_len / 2; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bin[i]);
    }

    return 0;
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new(), *e = BN_new(), *sign = BN_new(), *body_sha256 = BN_new();

    BN_hex2bn(&n, ca_pk_n_hex);
    BN_hex2bn(&e, ca_pk_e_hex);
    BN_hex2bn(&sign, ca_sign_hex);
    BN_hex2bn(&body_sha256, body_sha256_hex);

    BIGNUM *decrypted = BN_new();
    BN_mod_exp(decrypted, sign, e, n, ctx);
    BN_mask_bits(decrypted, 256); // 32 bytes = 256 bits
    printBN("body_sha256 = ", body_sha256);
    printBN("decrypted = ", decrypted);

    if (BN_cmp(body_sha256, decrypted) == 0) {
        printf("Valid\n");
    } else {
        printf("Invalid\n");
    }

    return 0;
}