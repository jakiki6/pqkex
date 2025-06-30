#pragma once

#define PQKEX_SKSIZE 1795
#define PQKEX_PKSIZE 1190
#define PQKEX_CTSIZE 1071
#define PQKEX_SSSIZE 64

void pqkex_keygen(void *pub, void *priv);
void pqkex_encaps(void *pub, void *ct, void *key);
void pqkex_decaps(void *priv, void *ct, void *key);
