#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/err.h>

#define AES_KEY_LENGTH 32 // 256 bits
#define BUFFER_SIZE 16    // AES block size

unsigned char aes_key[AES_KEY_LENGTH];   // Key for AES encryption/decryption

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Function to decrypt data using AES-256
void aes_decrypt(const unsigned char *input, unsigned char *output) {
    AES_KEY dec_key;
    if (AES_set_decrypt_key(aes_key, AES_KEY_LENGTH * 8, &dec_key) != 0)
        handleErrors();

    AES_decrypt(input, output, &dec_key);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *filename = argv[1];
    char new_filename[strlen(filename) + 1];
    strcpy(new_filename, filename);
    strcpy(strrchr(new_filename, '.'), ".dec");

    FILE *inputFile = fopen(filename, "rb");
    if (!inputFile) {
        perror("Failed to open input file");
        return EXIT_FAILURE;
    }

    FILE *outputFile = fopen(new_filename, "wb");
    if (!outputFile) {
        perror("Failed to open output file");
        fclose(inputFile);
        return EXIT_FAILURE;
    }

    printf("Enter password: ");
    char password[AES_KEY_LENGTH + 1];
    fgets(password, AES_KEY_LENGTH + 1, stdin);
    password[strcspn(password, "\n")] = 0; // Remove newline character
    strncpy((char *)aes_key, password, AES_KEY_LENGTH);

    unsigned char buffer[BUFFER_SIZE];
    size_t read_bytes;
    while ((read_bytes = fread(buffer, 1, BUFFER_SIZE, inputFile)) > 0) {
        unsigned char decryptedBuffer[BUFFER_SIZE];
        aes_decrypt(buffer, decryptedBuffer);
        fwrite(decryptedBuffer, 1, BUFFER_SIZE, outputFile);
    }

    fclose(inputFile);
    fclose(outputFile);

    remove(filename); // Remove original file

    printf("Decryption completed successfully.\n");

    return EXIT_SUCCESS;
}
