#include <stdio.h>
#include <openssl/bn.h>

const char *n_hex = "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115";
const char *e_hex = "010001";
const char *msg_hex = "4C61756E63682061206D697373696C652E"; // Launch a missile.
const char *s_hex = "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F";

void printBN(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new(), *e = BN_new(), *msg = BN_new(), *s = BN_new();

    BN_hex2bn(&n, n_hex);
    BN_hex2bn(&e, e_hex);
    BN_hex2bn(&msg, msg_hex);
    BN_hex2bn(&s, s_hex);

    BIGNUM *decrypted = BN_new();
    BN_mod_exp(decrypted, s, e, n, ctx);
    printBN("decrypted = ", decrypted);
    if (BN_cmp(msg, decrypted) == 0) {
        printf("Valid\n");
    } else {
        printf("Invalid\n");
    }

    return 0;
}