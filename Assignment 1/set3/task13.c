#include <stdio.h>
#include <openssl/bn.h>

const char *n_hex = "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5";
const char *e_hex = "010001";
const char *d_hex = "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D";
const char *msg_hex = "4120746f702073656372657421";

void printBN(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new(), *e = BN_new(), *d = BN_new(), *msg = BN_new(), *c = BN_new();

    BN_hex2bn(&n, n_hex);
    BN_hex2bn(&e, e_hex);
    BN_hex2bn(&d, d_hex);
    BN_hex2bn(&msg, msg_hex);

    BN_mod_exp(c, msg, e, n, ctx);
    printBN("c = ", c);

    BIGNUM *decrypted = BN_new();
    BN_mod_exp(decrypted, c, d, n, ctx);
    printBN("decrypted = ", decrypted);
    if (BN_cmp(msg, decrypted) == 0) {
        printf("Valid\n");
    } else {
        printf("Invalid\n");
    }

    return 0;
}