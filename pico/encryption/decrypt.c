#include "encryption.h"
#include <stdio.h>

// gcc -o decrypt decrypt.c encryption.o aes.o -m32 -lcrypto

int main(int argc, char *argv[]) {

    if(argc != 3) {
        printf("Usage: %s <arg1> <arg2>\n", argv[0]);
        return 1;
    }

    char* pass = decrypt(argv[1], argv[2]);
    printf("%s\n", pass);

    return 0;
}

