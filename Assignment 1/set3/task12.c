#include <stdio.h>
#include <openssl/bn.h>

const char *p_hex = "F7E75FDC469067FFDC4E847C51F452DF";
const char *q_hex = "E85CED54AF57E53E092113E62F436F4F";
const char *e_hex = "0D88C3";

void printBN(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new(), *q = BN_new(), *n = BN_new(), *e = BN_new(), *d = BN_new();

    BN_hex2bn(&p, p_hex);
    BN_hex2bn(&q, q_hex);
    BN_hex2bn(&e, e_hex);

    BN_mul(n, p, q, ctx);
    printBN("n = ", n);

    BIGNUM *p_minus_1 = BN_dup(p);
    BIGNUM *q_minus_1 = BN_dup(q);
    BN_sub_word(p_minus_1, 1);
    BN_sub_word(q_minus_1, 1);

    BIGNUM *phi = BN_new();
    BN_mul(phi, p_minus_1, q_minus_1, ctx);

    BN_mod_inverse(d, e, phi, ctx);
    printBN("d = ", d);

    return 0;
}