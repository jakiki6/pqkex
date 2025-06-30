#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>

#include "pqkex.h"

void randombytes(void *buf, int count) {
    getrandom(buf, count, 0);
}

int main(void) {
    for (int i = 0; i < 10; i++) {
        uint8_t pub[PQKEX_PKSIZE];
        uint8_t priv[PQKEX_SKSIZE];
        uint8_t ct[PQKEX_CTSIZE];
        uint8_t key1[PQKEX_SSSIZE];
        uint8_t key2[PQKEX_SSSIZE];

        pqkex_keygen(&pub, &priv);

        for (int j = 0; j < 10; j++) {
            pqkex_encaps(&pub, &ct, &key1);
            pqkex_decaps(&priv, &ct, &key2);

            if (memcmp(key1, key2, PQKEX_SSSIZE) != 0) {
                printf("Key exchange failure:\nkey1 = ");
                for (int j = 0; j < 64; j++) printf("%02hhx", key1[j]);
                printf("\nkey2 = ");
                for (int j = 0; j < 64; j++) printf("%02hhx", key2[j]);
                printf("\n");
                return 1;
            }
        }
    }
}
