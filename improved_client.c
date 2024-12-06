#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>

#define SERVER_IP "127.0.0.1"
#define PORT 5555
#define BUFFER_SIZE 1024
#define AES_KEY_LENGTH 32  // 256-bit key

// AES encryption/decryption function
void aes_encrypt_decrypt(const unsigned char *input, unsigned char *output, int input_len, const unsigned char *key, int is_encrypt) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        perror("EVP_CIPHER_CTX_new failed");
        exit(1);
    }

    if (EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL, is_encrypt) != 1) {
        perror("EVP_CipherInit_ex failed");
        exit(1);
    }

    if (EVP_CipherUpdate(ctx, output, &len, input, input_len) != 1) {
        perror("EVP_CipherUpdate failed");
        exit(1);
    }
    ciphertext_len = len;

    if (EVP_CipherFinal_ex(ctx, output + len, &len) != 1) {
        perror("EVP_CipherFinal_ex failed");
        exit(1);
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    const unsigned char key[AES_KEY_LENGTH] = "thisisaverysecretkey1234567890abcdef";  // 256-bit key
    const char *message = "Hello from client!";

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Failed to create socket");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    // Connect to server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        exit(1);
    }

    // Send authentication message
    send(sock, "vpn_shared_secret", strlen("vpn_shared_secret"), 0);

    // Receive server response
    int bytes_received = recv(sock, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) {
        perror("Authentication failed or server closed connection");
        close(sock);
        exit(1);
    }
    buffer[bytes_received] = '\0';
    if (strcmp(buffer, "AUTH_SUCCESS") != 0) {
        printf("Authentication failed\n");
        close(sock);
        exit(1);
    }

    printf("Authentication successful\n");

    // Encrypt and send message to server
    aes_encrypt_decrypt((unsigned char *)message, (unsigned char *)buffer, strlen(message), key, 1);
    send(sock, buffer, strlen(message), 0);

    // Receive encrypted message from server
    bytes_received = recv(sock, buffer, sizeof(buffer), 0);
    if (bytes_received < 0) {
        perror("Receive failed");
        close(sock);
        exit(1);
    }

    // Decrypt message
    aes_encrypt_decrypt(buffer, buffer, bytes_received, key, 0);
    printf("Received from server: %s\n", buffer);

    close(sock);
    return 0;
}
