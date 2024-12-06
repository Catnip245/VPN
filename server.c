#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#define TUN_DEVICE "/dev/net/tun"
#define SERVER_PORT 5555
#define BUFFER_SIZE 2048
#define XOR_KEY 'K' // XOR 암호화 키
#define SHARED_KEY "vpn_shared_secret" // 사전 공유 키
#define MAX_SESSIONS 5

typedef struct {
    int client_sock;
    struct sockaddr_in client_addr;
} vpn_session_t;

// XOR 암호화 함수
void xor_encrypt_decrypt(char *data, size_t length, char key) {
    for (size_t i = 0; i < length; i++) {
        data[i] ^= key; // XOR 연산으로 암호화/복호화
    }
}

// TUN 인터페이스 생성 및 설정
int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd = open(TUN_DEVICE, O_RDWR);
    if (fd < 0) {
        perror("TUN 인터페이스 열기 실패");
        exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN 모드 및 프로토콜 정보 생략
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("TUN 설정 실패");
        close(fd);
        exit(1);
    }

    printf("TUN 인터페이스 %s 생성 완료.\n", dev);
    return fd;
}

// 클라이언트 인증
int authenticate_client(int client_sock) {
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(client_sock, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) {
        perror("클라이언트 인증 실패");
        return 0; // 인증 실패
    }

    buffer[bytes_received] = '\0';
    if (strcmp(buffer, SHARED_KEY) == 0) {
        printf("클라이언트 인증 성공\n");
        send(client_sock, "AUTH_SUCCESS", strlen("AUTH_SUCCESS"), 0);
        return 1; // 인증 성공
    } else {
        printf("클라이언트 인증 실패: 키 불일치\n");
        send(client_sock, "AUTH_FAILURE", strlen("AUTH_FAILURE"), 0);
        return 0; // 인증 실패
    }
}

// 클라이언트 세션 처리
void handle_session(vpn_session_t *session, int tun_fd) {
    char buffer[BUFFER_SIZE];
    int bytes_read;

    while (1) {
        // TUN 인터페이스에서 읽기
        bytes_read = read(tun_fd, buffer, sizeof(buffer));
        if (bytes_read < 0) {
            perror("TUN 읽기 실패");
            break;
        }
        printf("[TUN] 패킷 수신: %d 바이트\n", bytes_read);

        // 암호화하여 클라이언트로 전송
        xor_encrypt_decrypt(buffer, bytes_read, XOR_KEY);
        if (write(session->client_sock, buffer, bytes_read) < 0) {
            perror("클라이언트 전송 실패");
            break;
        }

        // 클라이언트로부터 데이터 수신
        bytes_read = read(session->client_sock, buffer, sizeof(buffer));
        if (bytes_read <= 0) {
            printf("클라이언트 연결 종료\n");
            break;
        }

        // 복호화 후 TUN 인터페이스로 쓰기
        xor_encrypt_decrypt(buffer, bytes_read, XOR_KEY);
        if (write(tun_fd, buffer, bytes_read) < 0) {
            perror("TUN 쓰기 실패");
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

    // TUN 인터페이스 설정
    char tun_name[IFNAMSIZ] = "tun0";
    tun_fd = tun_alloc(tun_name);

    // 서버 소켓 생성
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("소켓 생성 실패");
        close(tun_fd);
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    // 소켓 바인딩
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("바인딩 실패");
        close(server_sock);
        close(tun_fd);
        exit(1);
    }

    // 연결 대기
    if (listen(server_sock, MAX_SESSIONS) < 0) {
        perror("연결 대기 실패");
        close(server_sock);
        close(tun_fd);
        exit(1);
    }

    printf("VPN 서버가 %d 포트에서 실행 중...\n", SERVER_PORT);

    // 클라이언트 연결 처리
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_addr_len);

        if (client_sock < 0) {
            perror("클라이언트 연결 실패");
            continue;
        }

        printf("클라이언트 연결 요청 수락됨\n");

        // 클라이언트 인증
        if (!authenticate_client(client_sock)) {
            close(client_sock);
            continue; // 인증 실패 시 연결 종료
        }

        // 세션 초기화
        vpn_session_t *session = malloc(sizeof(vpn_session_t));
        if (!session) {
            perror("메모리 할당 실패");
            close(client_sock);
            continue;
        }
        session->client_sock = client_sock;
        session->client_addr = client_addr;

        // 세션 처리
        handle_session(session, tun_fd);
    }

    close(tun_fd);
    close(server_sock);
    return 0;
}
