#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>  // ICMPv6头文件
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>

// 构造ICMP Echo请求报文
void build_icmp6_echo(struct icmp6_hdr *icmp6_hdr) {
    icmp6_hdr->icmp6_type = ICMP6_ECHO_REQUEST;  // ICMPv6 Echo请求
    icmp6_hdr->icmp6_code = 0;
    icmp6_hdr->icmp6_id = htons(getpid());       // 使用进程ID作为标识
    icmp6_hdr->icmp6_seq = 0;                    // 序列号
    // ICMPv6不需要计算校验和，由内核自动处理
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("使用方法: %s <目标IP>\n", argv[0]);
        return 1;
    }

    // 创建原始套接字
    int sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sockfd < 0) {
        perror("socket创建失败");
        return 1;
    }

    // 设置接收超时
    struct timeval tv;
    tv.tv_sec = 1;  // 1秒超时
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("设置超时失败");
        return 1;
    }

    struct sockaddr_in6 dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, argv[1], &dest_addr.sin6_addr) <= 0) {
        printf("IPv6地址无效\n");
        return 1;
    }

    // 构造ICMPv6报文
    struct icmp6_hdr icmp6_hdr;
    build_icmp6_echo(&icmp6_hdr);

    // 发送ICMPv6报文
    if (sendto(sockfd, &icmp6_hdr, sizeof(icmp6_hdr), 0, 
        (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
        perror("发送失败");
        return 1;
    }

    printf("ICMPv6 Echo请求已发送到 %s\n", argv[1]);

    // 接收响应
    char recv_buf[1024];
    struct sockaddr_in6 from_addr;
    socklen_t from_len = sizeof(from_addr);
    
    int bytes_received = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0,
                                 (struct sockaddr*)&from_addr, &from_len);
    
    if (bytes_received < 0) {
        if (errno == EAGAIN) {
            printf("接收超时\n");
        } else {
            perror("接收失败");
        }
        close(sockfd);
        return 1;
    }

    // 解析接收到的数据
    struct icmp6_hdr *icmp6_reply = (struct icmp6_hdr *)recv_buf;

    if (icmp6_reply->icmp6_type == ICMP6_ECHO_REPLY) {
        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &from_addr.sin6_addr, addr_str, INET6_ADDRSTRLEN);
        printf("收到来自 %s 的ICMPv6 Echo响应\n", addr_str);
        printf("ICMPv6 ID: %d\n", ntohs(icmp6_reply->icmp6_id));
        printf("ICMPv6 序列号: %d\n", ntohs(icmp6_reply->icmp6_seq));
    } else {
        printf("收到未知类型的ICMPv6响应: %d\n", icmp6_reply->icmp6_type);
    }

    close(sockfd);
    return 0;
}
