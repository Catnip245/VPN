#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_IP "127.0.0.1"
#define PORT 5555
#define BUFFER_SIZE 1024

// XOR 암호화 함수 (간단한 예시)
void xor_encrypt_decrypt(char *data, size_t length, char key) {
    for (size_t i = 0; i < length; i++) {
        data[i] ^= key;  // XOR 연산으로 암호화/복호화
    }
}

int main() {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    char key = 'K';  // XOR 암호화 키 (서버와 동일하게 K 사용)
    const char *message = "Hello from client!";

    // 소켓 생성
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Failed to create socket");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    // 서버에 연결
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        exit(1);
    }

    printf("Connected to server\n");

    // 메시지 보내기 (암호화 후 전송)
    strncpy(buffer, message, sizeof(buffer));
    xor_encrypt_decrypt(buffer, strlen(buffer), key);  // 암호화
    send(sock, buffer, strlen(buffer), 0);

    // 서버로부터 응답 받기 (복호화)
    int bytes_received = recv(sock, buffer, sizeof(buffer), 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        xor_encrypt_decrypt(buffer, bytes_received, key);  // 복호화
        printf("Received from server: %s\n", buffer);
    }

    // 연결 종료
    close(sock);
    return 0;
}
