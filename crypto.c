#include <windows.h>  // Include this for HINSTANCE, LPSTR, etc.
#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/blowfish.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define AES_128_KEY_LENGTH 16 // 128 bits
#define AES_256_KEY_LENGTH 32 // 256 bits
#define DES_KEY_LENGTH 8      // 64 bits
#define BUFFER_SIZE 16        // AES block size

unsigned char aes_128_key[AES_128_KEY_LENGTH];   // Key for AES-128 encryption/decryption
unsigned char aes_256_key[AES_256_KEY_LENGTH];   // Key for AES-256 encryption/decryption
unsigned char des_key[DES_KEY_LENGTH];           // Key for DES encryption/decryption
unsigned char blowfish_key[16];                  // Key for Blowfish encryption/decryption

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Function to encrypt data using AES-128
void aes_128_encrypt(const unsigned char *input, unsigned char *output) {
    AES_KEY enc_key;
    if (AES_set_encrypt_key(aes_128_key, AES_128_KEY_LENGTH * 8, &enc_key) != 0)
        handleErrors();

    AES_encrypt(input, output, &enc_key);
}

// Function to decrypt data using AES-128
void aes_128_decrypt(const unsigned char *input, unsigned char *output) {
    AES_KEY dec_key;
    if (AES_set_decrypt_key(aes_128_key, AES_128_KEY_LENGTH * 8, &dec_key) != 0)
        handleErrors();

    AES_decrypt(input, output, &dec_key);
}

// Function to encrypt data using AES-256
void aes_256_encrypt(const unsigned char *input, unsigned char *output) {
    AES_KEY enc_key;
    if (AES_set_encrypt_key(aes_256_key, AES_256_KEY_LENGTH * 8, &enc_key) != 0)
        handleErrors();

    AES_encrypt(input, output, &enc_key);
}

// Function to decrypt data using AES-256
void aes_256_decrypt(const unsigned char *input, unsigned char *output) {
    AES_KEY dec_key;
    if (AES_set_decrypt_key(aes_256_key, AES_256_KEY_LENGTH * 8, &dec_key) != 0)
        handleErrors();

    AES_decrypt(input, output, &dec_key);
}

// Function to encrypt data using DES
void des_encrypt(const unsigned char *input, unsigned char *output) {
    DES_key_schedule ks;
    DES_set_key((DES_cblock *)des_key, &ks);
    DES_ecb_encrypt((DES_cblock *)input, (DES_cblock *)output, &ks, DES_ENCRYPT);
}

// Function to decrypt data using DES
void des_decrypt(const unsigned char *input, unsigned char *output) {
    DES_key_schedule ks;
    DES_set_key((DES_cblock *)des_key, &ks);
    DES_ecb_encrypt((DES_cblock *)input, (DES_cblock *)output, &ks, DES_DECRYPT);
}

// Function to encrypt data using Blowfish
void blowfish_encrypt(const unsigned char *input, unsigned char *output) {
    BF_KEY bf_key;
    BF_set_key(&bf_key, sizeof(blowfish_key), blowfish_key);
    BF_ecb_encrypt(input, output, &bf_key, BF_ENCRYPT);
}

// Function to decrypt data using Blowfish
void blowfish_decrypt(const unsigned char *input, unsigned char *output) {
    BF_KEY bf_key;
    BF_set_key(&bf_key, sizeof(blowfish_key), blowfish_key);
    BF_ecb_encrypt(input, output, &bf_key, BF_DECRYPT);
}

// Function to encrypt data using XOR (not secure)
void xor_encrypt(const unsigned char *input, unsigned char *output, const char *key) {
    size_t len = strlen(key);
    for (size_t i = 0; i < BUFFER_SIZE; ++i) {
        output[i] = input[i] ^ key[i % len];
    }
}

// Function to decrypt data using XOR (not secure)
void xor_decrypt(const unsigned char *input, unsigned char *output, const char *key) {
    xor_encrypt(input, output, key); // XOR decryption is the same as encryption
}

// Function to encrypt data using NXOR (not secure)
void nxor_encrypt(const unsigned char *input, unsigned char *output, const char *key) {
    size_t len = strlen(key);
    for (size_t i = 0; i < BUFFER_SIZE; ++i) {
        output[i] = ~(input[i] ^ key[i % len]);
    }
}

// Function to decrypt data using NXOR (not secure)
void nxor_decrypt(const unsigned char *input, unsigned char *output, const char *key) {
    size_t len = strlen(key);
    for (size_t i = 0; i < BUFFER_SIZE; ++i) {
        output[i] = ~input[i] ^ key[i % len];
    }
}

// Function to flip all bits (NOT encryption)
void not_encrypt(const unsigned char *input, unsigned char *output) {
    for (size_t i = 0; i < BUFFER_SIZE; ++i) {
        output[i] = ~input[i];
    }
}

// Function to decrypt data using NOT encryption (flips all bits again)
void not_decrypt(const unsigned char *input, unsigned char *output) {
    not_encrypt(input, output); // NOT decryption is the same as encryption
}

// Encrypt the selected input file based on the chosen method and password
void on_encrypt(GtkWidget *widget, gpointer data) {
    GtkWidget **widgets = (GtkWidget **)data;
    const gchar *input_filename = gtk_entry_get_text(GTK_ENTRY(widgets[0]));
    const gchar *output_filename = gtk_entry_get_text(GTK_ENTRY(widgets[1]));
    const gchar *password = gtk_entry_get_text(GTK_ENTRY(widgets[2]));
    const gchar *method_name = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(widgets[3]));

    FILE *inputFile = fopen(input_filename, "rb");
    if (!inputFile) {
        perror("Failed to open input file\n");
        abort();
    }

    FILE *outputFile = fopen(output_filename, "wb");
    if (!outputFile) {
        perror("Failed to open output file\n");
        fclose(inputFile);
        abort();
    }

    unsigned char buffer[BUFFER_SIZE];
    unsigned char encryptedBuffer[BUFFER_SIZE];

    if (strcmp(method_name, "AES-128") == 0) {
        strncpy((char *)aes_128_key, password, AES_128_KEY_LENGTH);
        memset(aes_256_key, 0x00, sizeof(aes_256_key));
        memset(des_key, 0x00, sizeof(des_key));
        memset(blowfish_key, 0x00, sizeof(blowfish_key));
        while (fread(buffer, sizeof(unsigned char), BUFFER_SIZE, inputFile)) {
            aes_128_encrypt(buffer, encryptedBuffer);
            fwrite(encryptedBuffer, sizeof(unsigned char), BUFFER_SIZE, outputFile);
        }
    } else if (strcmp(method_name, "AES-256") == 0) {
        strncpy((char *)aes_256_key, password, AES_256_KEY_LENGTH);
        memset(aes_128_key, 0x00, sizeof(aes_128_key));
        memset(des_key, 0x00, sizeof(des_key));
        memset(blowfish_key, 0x00, sizeof(blowfish_key));
        while (fread(buffer, sizeof(unsigned char), BUFFER_SIZE, inputFile)) {
            aes_256_encrypt(buffer, encryptedBuffer);
            fwrite(encryptedBuffer, sizeof(unsigned char), BUFFER_SIZE, outputFile);
        }
    } else if (strcmp(method_name, "DES") == 0) {
        strncpy((char *)des_key, password, DES_KEY_LENGTH);
        memset(aes_128_key, 0x00, sizeof(aes_128_key));
        memset(aes_256_key, 0x00, sizeof(aes_256_key));
        memset(blowfish_key, 0x00, sizeof(blowfish_key));
        while (fread(buffer, sizeof(unsigned char), BUFFER_SIZE, inputFile)) {
            des_encrypt(buffer, encryptedBuffer);
            fwrite(encryptedBuffer, sizeof(unsigned char), BUFFER_SIZE, outputFile);
        }
    } else if (strcmp(method_name, "Blowfish") == 0) {
        strncpy((char *)blowfish_key, password, sizeof(blowfish_key));
        memset(aes_128_key, 0x00, sizeof(aes_128_key));
        memset(aes_256_key, 0x00, sizeof(aes_256_key));
        memset(des_key, 0x00, sizeof(des_key));
        while (fread(buffer, sizeof(unsigned char), BUFFER_SIZE, inputFile)) {
            blowfish_encrypt(buffer, encryptedBuffer);
            fwrite(encryptedBuffer, sizeof(unsigned char), BUFFER_SIZE, outputFile);
        }
    } else if (strcmp(method_name, "NXOR") == 0) {
        while (fread(buffer, sizeof(unsigned char), BUFFER_SIZE, inputFile)) {
            nxor_encrypt(buffer, encryptedBuffer, password);
            fwrite(encryptedBuffer, sizeof(unsigned char), BUFFER_SIZE, outputFile);
        }
    } else if (strcmp(method_name, "NOT") == 0) {
        while (fread(buffer, sizeof(unsigned char), BUFFER_SIZE, inputFile)) {
            not_encrypt(buffer, encryptedBuffer);
            fwrite(encryptedBuffer, sizeof(unsigned char), BUFFER_SIZE, outputFile);
        }
    }

    fclose(inputFile);
    fclose(outputFile);
    printf("Encryption completed successfully.\n");
}

// Decrypt the selected input file based on the chosen method and password
void on_decrypt(GtkWidget *widget, gpointer data) {
    GtkWidget **widgets = (GtkWidget **)data;
    const gchar *input_filename = gtk_entry_get_text(GTK_ENTRY(widgets[0]));
    const gchar *output_filename = gtk_entry_get_text(GTK_ENTRY(widgets[1]));
    const gchar *password = gtk_entry_get_text(GTK_ENTRY(widgets[2]));
    const gchar *method_name = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(widgets[3]));

    FILE *inputFile = fopen(input_filename, "rb");
    if (!inputFile) {
        perror("Failed to open input file\n");
        abort();
    }

    FILE *outputFile = fopen(output_filename, "wb");
    if (!outputFile) {
        perror("Failed to open output file\n");
        fclose(inputFile);
        abort();
    }

    unsigned char buffer[BUFFER_SIZE];
    unsigned char decryptedBuffer[BUFFER_SIZE];

    if (strcmp(method_name, "AES-128") == 0) {
        strncpy((char *)aes_128_key, password, AES_128_KEY_LENGTH);
        memset(aes_256_key, 0x00, sizeof(aes_256_key));
        memset(des_key, 0x00, sizeof(des_key));
        memset(blowfish_key, 0x00, sizeof(blowfish_key));
        while (fread(buffer, sizeof(unsigned char), BUFFER_SIZE, inputFile)) {
            aes_128_decrypt(buffer, decryptedBuffer);
            fwrite(decryptedBuffer, sizeof(unsigned char), BUFFER_SIZE, outputFile);
        }
    } else if (strcmp(method_name, "AES-256") == 0) {
        strncpy((char *)aes_256_key, password, AES_256_KEY_LENGTH);
        memset(aes_128_key, 0x00, sizeof(aes_128_key));
        memset(des_key, 0x00, sizeof(des_key));
        memset(blowfish_key, 0x00, sizeof(blowfish_key));
        while (fread(buffer, sizeof(unsigned char), BUFFER_SIZE, inputFile)) {
            aes_256_decrypt(buffer, decryptedBuffer);
            fwrite(decryptedBuffer, sizeof(unsigned char), BUFFER_SIZE, outputFile);
        }
    } else if (strcmp(method_name, "DES") == 0) {
        strncpy((char *)des_key, password, DES_KEY_LENGTH);
        memset(aes_128_key, 0x00, sizeof(aes_128_key));
        memset(aes_256_key, 0x00, sizeof(aes_256_key));
        memset(blowfish_key, 0x00, sizeof(blowfish_key));
        while (fread(buffer, sizeof(unsigned char), BUFFER_SIZE, inputFile)) {
            des_decrypt(buffer, decryptedBuffer);
            fwrite(decryptedBuffer, sizeof(unsigned char), BUFFER_SIZE, outputFile);
        }
    } else if (strcmp(method_name, "Blowfish") == 0) {
        strncpy((char *)blowfish_key, password, sizeof(blowfish_key));
        memset(aes_128_key, 0x00, sizeof(aes_128_key));
        memset(aes_256_key, 0x00, sizeof(aes_256_key));
        memset(des_key, 0x00, sizeof(des_key));
        while (fread(buffer, sizeof(unsigned char), BUFFER_SIZE, inputFile)) {
            blowfish_decrypt(buffer, decryptedBuffer);
            fwrite(decryptedBuffer, sizeof(unsigned char), BUFFER_SIZE, outputFile);
        }
    } else if (strcmp(method_name, "XOR") == 0) {
        while (fread(buffer, sizeof(unsigned char), BUFFER_SIZE, inputFile)) {
            xor_decrypt(buffer, decryptedBuffer, password);
            fwrite(decryptedBuffer, sizeof(unsigned char), BUFFER_SIZE, outputFile);
        }
    } else if (strcmp(method_name, "NXOR") == 0) {
        while (fread(buffer, sizeof(unsigned char), BUFFER_SIZE, inputFile)) {
            nxor_decrypt(buffer, decryptedBuffer, password);
            fwrite(decryptedBuffer, sizeof(unsigned char), BUFFER_SIZE, outputFile);
        }
    } else if (strcmp(method_name, "NOT") == 0) {
        while (fread(buffer, sizeof(unsigned char), BUFFER_SIZE, inputFile)) {
            not_decrypt(buffer, decryptedBuffer);
            fwrite(decryptedBuffer, sizeof(unsigned char), BUFFER_SIZE, outputFile);
        }
    }

    fclose(inputFile);
    fclose(outputFile);
    printf("Decryption completed successfully.\n");
}

int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    int argc = 0;
    char **argv = NULL;

    gtk_init(&argc, &argv);

    memset(aes_128_key, 0x00, sizeof(aes_128_key));
    memset(aes_256_key, 0x00, sizeof(aes_256_key));
    memset(des_key, 0x00, sizeof(des_key));
    memset(blowfish_key, 0x00, sizeof(blowfish_key));

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Secure File Encryptor/Decryptor");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 200);
    gtk_window_set_resizable(GTK_WINDOW(window), FALSE);

    GtkWidget *grid = gtk_grid_new();
    gtk_container_add(GTK_CONTAINER(window), grid);
    gtk_widget_set_margin_top(grid, 3);
    gtk_widget_set_margin_bottom(grid, 3);
    gtk_widget_set_margin_start(grid, 3);
    gtk_widget_set_margin_end(grid, 3);

    GtkWidget **widgets = g_malloc(5 * sizeof(GtkWidget *));
    widgets[0] = gtk_entry_new();  // Entry for input file
    widgets[1] = gtk_entry_new();  // Entry for output file
    widgets[2] = gtk_entry_new();  // Entry for password
    widgets[3] = gtk_combo_box_text_new();  // Combo box for method selection
    widgets[4] = window;  // Main window reference for dialogs

    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(widgets[3]), NULL, "AES-128");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(widgets[3]), NULL, "AES-256");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(widgets[3]), NULL, "DES");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(widgets[3]), NULL, "Blowfish");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(widgets[3]), NULL, "XOR");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(widgets[3]), NULL, "NXOR");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(widgets[3]), NULL, "NOT");

    GtkWidget *input_label = gtk_label_new("Input File:");
    gtk_grid_attach(GTK_GRID(grid), input_label, 0, 0, 1, 1);
    gtk_widget_set_margin_top(input_label, 3);
    gtk_widget_set_margin_bottom(input_label, 3);
    gtk_widget_set_margin_start(input_label, 3);
    gtk_widget_set_margin_end(input_label, 3);

    gtk_grid_attach(GTK_GRID(grid), widgets[0], 1, 0, 2, 1);
    gtk_widget_set_margin_top(widgets[0], 3);
    gtk_widget_set_margin_bottom(widgets[0], 3);
    gtk_widget_set_margin_start(widgets[0], 3);
    gtk_widget_set_margin_end(widgets[0], 3);

    GtkWidget *output_label = gtk_label_new("Output File:");
    gtk_grid_attach(GTK_GRID(grid), output_label, 0, 1, 1, 1);
    gtk_widget_set_margin_top(output_label, 3);
    gtk_widget_set_margin_bottom(output_label, 3);
    gtk_widget_set_margin_start(output_label, 3);
    gtk_widget_set_margin_end(output_label, 3);

    gtk_grid_attach(GTK_GRID(grid), widgets[1], 1, 1, 2, 1);
    gtk_widget_set_margin_top(widgets[1], 3);
    gtk_widget_set_margin_bottom(widgets[1], 3);
    gtk_widget_set_margin_start(widgets[1], 3);
    gtk_widget_set_margin_end(widgets[1], 3);

    GtkWidget *password_label = gtk_label_new("Password:");
    gtk_grid_attach(GTK_GRID(grid), password_label, 0, 2, 1, 1);
    gtk_widget_set_margin_top(password_label, 3);
    gtk_widget_set_margin_start(password_label, 3);
    gtk_widget_set_margin_end(password_label, 3);

    gtk_grid_attach(GTK_GRID(grid), widgets[2], 1, 2, 2, 1);
    gtk_widget_set_margin_top(widgets[2], 3);
    gtk_widget_set_margin_bottom(widgets[2], 3);
    gtk_widget_set_margin_start(widgets[2], 3);
    gtk_widget_set_margin_end(widgets[2], 3);

    GtkWidget *method_label = gtk_label_new("Method:");
    gtk_grid_attach(GTK_GRID(grid), method_label, 0, 3, 1, 1);
    gtk_widget_set_margin_top(method_label, 3);
    gtk_widget_set_margin_bottom(method_label, 3);
    gtk_widget_set_margin_start(method_label, 3);
    gtk_widget_set_margin_end(method_label, 3);

    gtk_grid_attach(GTK_GRID(grid), widgets[3], 1, 3, 2, 1);
    gtk_widget_set_margin_top(widgets[3], 3);
    gtk_widget_set_margin_bottom(widgets[3], 3);
    gtk_widget_set_margin_start(widgets[3], 3);
    gtk_widget_set_margin_end(widgets[3], 3);

    GtkWidget *encrypt_decrypt_label = gtk_label_new("Encrypt/Decrypt:");
    gtk_grid_attach(GTK_GRID(grid), encrypt_decrypt_label, 0, 4, 1, 1);
    gtk_widget_set_margin_top(encrypt_decrypt_label, 3);
    gtk_widget_set_margin_bottom(encrypt_decrypt_label, 3);
    gtk_widget_set_margin_start(encrypt_decrypt_label, 3);
    gtk_widget_set_margin_end(encrypt_decrypt_label, 3);

    GtkWidget *button_encrypt = gtk_button_new_with_label("Encrypt");
    g_signal_connect(button_encrypt, "clicked", G_CALLBACK(on_encrypt), widgets);
    gtk_grid_attach(GTK_GRID(grid), button_encrypt, 1, 4, 1, 1);
    gtk_widget_set_margin_top(button_encrypt, 3);
    gtk_widget_set_margin_bottom(button_encrypt, 3);
    gtk_widget_set_margin_start(button_encrypt, 3);
    gtk_widget_set_margin_end(button_encrypt, 3);

    GtkWidget *button_decrypt = gtk_button_new_with_label("Decrypt");
    g_signal_connect(button_decrypt, "clicked", G_CALLBACK(on_decrypt), widgets);
    gtk_grid_attach(GTK_GRID(grid), button_decrypt, 2, 4, 1, 1);
    gtk_widget_set_margin_top(button_decrypt, 3);
    gtk_widget_set_margin_bottom(button_decrypt, 3);
    gtk_widget_set_margin_start(button_decrypt, 3);
    gtk_widget_set_margin_end(button_decrypt, 3);

    // Ensure the buttons have the same width
    gtk_widget_set_hexpand(button_encrypt, TRUE);
    gtk_widget_set_hexpand(button_decrypt, TRUE);

    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    gtk_widget_show_all(window);
    gtk_main();

    g_free(widgets); // Free allocated memory

    return EXIT_SUCCESS;
}
