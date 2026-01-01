#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
// Buffer size for reading files
#define BUFFER_SIZE 4096
#define SALT_SIZE 16
#define PBKDF2_ITERATIONS 100000
// Function to handle errors
void handleErrors() {
    fprintf(stderr, "Encryption/Decryption failed.\n");
    exit(1);
}

// Read password from terminal without echoing characters
void read_hidden_password(char *buffer, size_t size) {
    struct termios oldt, newt;
    printf("Enter password: ");
    fflush(stdout);

    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    fgets(buffer, size, stdin);

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");

    // remove newline if present
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') buffer[len - 1] = '\0';
}

// Encrypt or decrypt function using AES-256-CBC
void process_file(const char *in_file, const char *out_file, const char *password, int encrypt) {
      // We do NOT modify the file directly on disk byte-by-byte.
     // We write to a temporary file safely, then replace the original.
    // This simulates "same file" behavior but avoids corruption risk.

    FILE *fin = fopen(in_file, "rb");

    // temporary file path
    char temp_path[1024];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", out_file);

    FILE *fout = fopen(temp_path, "wb");

    if (!fin || !fout) {
        printf("File open error.\n");
        exit(1);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

       unsigned char salt[SALT_SIZE];

    if (encrypt) {
        if (!RAND_bytes(salt, sizeof(salt))) {
            printf("Salt generation failed.\n");
            exit(1);
        }
        // write "Salted__" header similar to OpenSSL format
        fwrite("Salted__", 1, 8, fout);
        fwrite(salt, 1, SALT_SIZE, fout);
    } else {
        // read and verify header during decryption
        char header[8];
        fread(header, 1, 8, fin);
        if (memcmp(header, "Salted__", 8) != 0) {
            printf("Invalid file format (missing salt header)\n");
            exit(1);
        }
        fread(salt, 1, SALT_SIZE, fin);
    }

    unsigned char derived[48];

    if (!PKCS5_PBKDF2_HMAC(
            password, strlen(password),
            salt, sizeof(salt),
            PBKDF2_ITERATIONS,
            EVP_sha256(),
            sizeof(derived),
            derived)) {
        handleErrors();
    }

    unsigned char key[32];
    unsigned char iv[16];
    memcpy(key, derived, 32);
    memcpy(iv, derived + 32, 16);

    if (encrypt) {
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();
    } else {
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();
    }

    unsigned char buffer_in[BUFFER_SIZE];
    unsigned char buffer_out[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int len;
    int out_len;

    // Determine total file size for progress display
    struct stat st;
    stat(in_file, &st);
    long total = st.st_size;
    long processed = 0;

    printf("Processing: ");
    fflush(stdout);

    while ((len = fread(buffer_in, 1, BUFFER_SIZE, fin)) > 0) {
        if (encrypt)
            EVP_EncryptUpdate(ctx, buffer_out, &out_len, buffer_in, len);
        else
            EVP_DecryptUpdate(ctx, buffer_out, &out_len, buffer_in, len);

        fwrite(buffer_out, 1, out_len, fout);

        processed += len;

        // progress bar 
        float percent = (float)processed / (float)total;
        int width = 30;
        int filled = (int)(percent * width);

        printf("\r[");
        for (int i = 0; i < width; i++) {
            if (i < filled) printf("█");
            else printf("·");
        }
        printf("] %3d%%", (int)(percent * 100));
        fflush(stdout);
    }

    printf("\n");

    if (encrypt)
        EVP_EncryptFinal_ex(ctx, buffer_out, &out_len);
    else
        EVP_DecryptFinal_ex(ctx, buffer_out, &out_len);

    fwrite(buffer_out, 1, out_len, fout);

    EVP_CIPHER_CTX_free(ctx);
    fclose(fin);
    fclose(fout);

    // Replace original file with processed temp file
    remove(out_file);
    rename(temp_path, out_file);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage:\n");
        printf("Encrypt:   ./locker enc file.txt\n");
        printf("Decrypt:   ./locker dec file.txt\n");
        return 1;
    }

    int encrypt = strcmp(argv[1], "enc") == 0;

    char password[256];
    read_hidden_password(password, sizeof(password));

    process_file(argv[2], argv[2], password, encrypt);

    printf("Done.\n");
    return 0;
}