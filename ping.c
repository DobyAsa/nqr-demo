#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <stdbool.h>
#include <pcap.h>

bool attch_icmp_filter(int sockfd, int id) {
    // 初始化pcap
    char errbuf[PCAP_ERRBUF_SIZE];
    // 使用pcap_open_dead替代NULL
    pcap_t *handle = pcap_open_dead(DLT_RAW, 65535);
    if (handle == NULL) {
        fprintf(stderr, "Error creating pcap handle: %s\n", errbuf);
        return false;
    }
    // const char *filter_exp = "icmp[4:2] == 0 or icmp[4:2] == 1";
    char filter_exp[64];
    snprintf(filter_exp, sizeof(filter_exp), "icmp[4:2] == %d", ntohs(id));
    printf("filter_exp: %s\n", filter_exp);
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return false;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &fp, sizeof(fp)) < 0) {
        perror("Error attaching BPF filter to socket");
        pcap_freecode(&fp);
        pcap_close(handle);
        return false;
    }
    pcap_freecode(&fp);
    pcap_close(handle);
    return true;
}

// ICMP报文校验和计算
unsigned short calculate_checksum(unsigned short *addr, int len) {
    unsigned int sum = 0;
    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)addr;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

// 构造ICMP Echo请求报文
void build_icmp_echo(struct icmp *icmp_hdr) {
    icmp_hdr->icmp_type = ICMP_ECHO;    // Echo请求
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_id = htons(1);       // 使用进程ID作为标识
    icmp_hdr->icmp_seq = 0;             // 序列号
    icmp_hdr->icmp_cksum = 0;           // 校验和初始化为0
    icmp_hdr->icmp_cksum = calculate_checksum((unsigned short *)icmp_hdr, sizeof(struct icmp));
}

// 构造ICMP Timestamp请求报文
void build_icmp_timestamp(struct icmp *icmp_hdr) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    icmp_hdr->icmp_type = ICMP_TSTAMP;    // Timestamp请求
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_id = 1;
    icmp_hdr->icmp_seq = 0;
    // 设置发送时间戳（毫秒）
    icmp_hdr->icmp_otime = htonl((tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000);
    icmp_hdr->icmp_rtime = 0;
    icmp_hdr->icmp_ttime = 0;
    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_cksum = calculate_checksum((unsigned short *)icmp_hdr, sizeof(struct icmp));
}

// 新增：解析ICMP响应函数
void parse_icmp_response(char *recv_buf, struct sockaddr_in *from_addr) {
    struct ip *ip_hdr = (struct ip *)recv_buf;
    struct icmp *icmp_reply = (struct icmp *)(recv_buf + (ip_hdr->ip_hl << 2));

    if (icmp_reply->icmp_type == ICMP_ECHOREPLY) {
        printf("收到来自 %s 的ICMP Echo响应\n", inet_ntoa(from_addr->sin_addr));
        printf("ICMP ID: %d\n", ntohs(icmp_reply->icmp_id));
        printf("ICMP 序列号: %d\n", ntohs(icmp_reply->icmp_seq));
    } else if (icmp_reply->icmp_type == ICMP_TSTAMPREPLY) {
        printf("收到来自 %s 的ICMP Timestamp响应\n", inet_ntoa(from_addr->sin_addr));
        printf("ICMP ID: %d\n", ntohs(icmp_reply->icmp_id));
        printf("发送时间: %u ms\n", ntohl(icmp_reply->icmp_otime));
        printf("接收时间: %u ms\n", ntohl(icmp_reply->icmp_rtime));
        printf("传输时间: %u ms\n", ntohl(icmp_reply->icmp_ttime));
    } else {
        printf("收到未知类型的ICMP响应: %d\n", icmp_reply->icmp_type);
    }
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("使用方法: %s <目标IP>\n", argv[0]);
        return 1;
    }

    // 创建原始套接字
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
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

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, argv[1], &dest_addr.sin_addr) <= 0) {
        printf("IP地址无效\n");
        return 1;
    }

    // 构造ICMP报文
    struct icmp icmp_hdr;
    // 这里可以选择使用Echo或Timestamp请求
    build_icmp_echo(&icmp_hdr);
    // build_icmp_timestamp(&icmp_hdr);

    if (!attch_icmp_filter(sockfd, icmp_hdr.icmp_id)) {
        perror("附加BPF过滤器失败");
        return 1;
    }

    // 发送ICMP报文
    if (sendto(sockfd, &icmp_hdr, sizeof(icmp_hdr), 0, 
        (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
        perror("发送失败");
        return 1;
    }

    printf("ICMP Echo请求已发送到 %s\n", argv[1]);

    // 使用select监听套接字
    fd_set readfds;
    struct timeval timeout;
    int max_attempts = 5; // 最大尝试次数
    int attempts = 0;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        
        timeout.tv_sec = 1;  // 1秒超时
        timeout.tv_usec = 0;

        int ready = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
        
        if (ready < 0) {
            perror("select错误");
            break;
        } else if (ready == 0) {
            printf("等待响应超时\n");
            attempts++;
            continue;
        }

        if (FD_ISSET(sockfd, &readfds)) {
            char recv_buf[1024];
            struct sockaddr_in from_addr;
            socklen_t from_len = sizeof(from_addr);
            
            int bytes_received = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0,
                                        (struct sockaddr*)&from_addr, &from_len);
            
            if (bytes_received < 0) {
                perror("接收失败");
                break;
            }

            parse_icmp_response(recv_buf, &from_addr);
            //break;  // 成功接收到响应后退出循环
        }
    }

    if (attempts >= max_attempts) {
        printf("达到最大尝试次数，目标主机可能不可达\n");
    }

    close(sockfd);
    return 0;
}
