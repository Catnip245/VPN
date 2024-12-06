#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <openssl/evp.h>

#define TUN_DEVICE "/dev/net/tun"
#define SERVER_PORT 5555
#define BUFFER_SIZE 2048
#define AES_KEY_LENGTH 32  // 256-bit key
#define AES_BLOCK_SIZE 16  // AES block size (128 bits)
#define SHARED_KEY "vpn_shared_secret" // Shared key for client authentication
#define MAX_SESSIONS 5

typedef struct {
    int client_sock;
    struct sockaddr_in client_addr;
} vpn_session_t;

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

// TUN interface creation
int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd = open(TUN_DEVICE, O_RDWR);
    if (fd < 0) {
        perror("TUN interface open failed");
        exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("TUN setup failed");
        close(fd);
        exit(1);
    }

    printf("TUN interface %s created successfully.\n", dev);
    return fd;
}

// Client authentication
int authenticate_client(int client_sock) {
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(client_sock, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) {
        perror("Client authentication failed");
        return 0; 
    }

    buffer[bytes_received] = '\0';
    if (strcmp(buffer, SHARED_KEY) == 0) {
        printf("Client authentication successful\n");
        send(client_sock, "AUTH_SUCCESS", strlen("AUTH_SUCCESS"), 0);
        return 1;
    } else {
        printf("Client authentication failed: Key mismatch\n");
        send(client_sock, "AUTH_FAILURE", strlen("AUTH_FAILURE"), 0);
        return 0; 
    }
}

// Handle client session
void handle_session(vpn_session_t *session, int tun_fd, const unsigned char *key) {
    char buffer[BUFFER_SIZE];
    int bytes_read;

    while (1) {
        // Read from TUN interface
        bytes_read = read(tun_fd, buffer, sizeof(buffer));
        if (bytes_read < 0) {
            perror("TUN read failed");
            break;
        }
        printf("[TUN] Packet received: %d bytes\n", bytes_read);

        // Encrypt and send to client
        aes_encrypt_decrypt((unsigned char *)buffer, (unsigned char *)buffer, bytes_read, key, 1);
        if (write(session->client_sock, buffer, bytes_read) < 0) {
            perror("Client send failed");
            break;
        }

        // Read from client
        bytes_read = read(session->client_sock, buffer, sizeof(buffer));
        if (bytes_read <= 0) {
            printf("Client connection closed\n");
            break;
        }

        // Decrypt and write to TUN interface
        aes_encrypt_decrypt((unsigned char *)buffer, (unsigned char *)buffer, bytes_read, key, 0);
        if (write(tun_fd, buffer, bytes_read) < 0) {
            perror("TUN write failed");
            break;
        }
    }

    close(session->client_sock);
    free(session);
}

int main() {
    int server_sock, tun_fd;
    struct sockaddr_in server_addr;
    vpn_session_t *sessions[MAX_SESSIONS] = {NULL};

    // AES key for encryption
    const unsigned char key[AES_KEY_LENGTH] = "thisisaverysecretkey12345678";  // 256-bit key
    // Set up TUN interface
    char tun_name[IFNAMSIZ] = "tun0";
    tun_fd = tun_alloc(tun_name);

    // Create server socket
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        close(tun_fd);
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Binding failed");
        close(server_sock);
        close(tun_fd);
        exit(1);
    }

    if (listen(server_sock, MAX_SESSIONS) < 0) {
        perror("Listen failed");
        close(server_sock);
        close(tun_fd);
        exit(1);
    }

    printf("VPN server running on port %d...\n", SERVER_PORT);

    // Accept client connections
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_addr_len);

        if (client_sock < 0) {
            perror("Client connection failed");
            continue;
        }

        printf("Client connection request accepted\n");

        // Authenticate client
        if (!authenticate_client(client_sock)) {
            close(client_sock);
            continue;
        }

        // Initialize session
        vpn_session_t *session = malloc(sizeof(vpn_session_t));
        if (!session) {
            perror("Memory allocation failed");
            close(client_sock);
            continue;
        }
        session->client_sock = client_sock;
        session->client_addr = client_addr;

        // Handle client session
        handle_session(session, tun_fd, key);
    }

    close(tun_fd);
    close(server_sock);
    return 0;
}
