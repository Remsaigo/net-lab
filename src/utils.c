#include "utils.h"

#include "net.h"
#include "ip.h"
#include <stdio.h>
#include <string.h>
/**
 * @brief ip转字符串
 *
 * @param ip ip地址
 * @return char* 生成的字符串
 */
char *iptos(uint8_t *ip) {
    static char output[3 * 4 + 3 + 1];
    sprintf(output, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return output;
}

/**
 * @brief mac转字符串
 *
 * @param mac mac地址
 * @return char* 生成的字符串
 */
char *mactos(uint8_t *mac) {
    static char output[2 * 6 + 5 + 1];
    sprintf(output, "%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return output;
}

/**
 * @brief 时间戳转字符串
 *
 * @param timestamp 时间戳
 * @return char* 生成的字符串
 */
char *timetos(time_t timestamp) {
    static char output[20];
    struct tm *utc_time = gmtime(&timestamp);
    sprintf(output, "%04d-%02d-%02d %02d:%02d:%02d", utc_time->tm_year + 1900, utc_time->tm_mon + 1, utc_time->tm_mday, utc_time->tm_hour, utc_time->tm_min, utc_time->tm_sec);
    return output;
}

/**
 * @brief ip前缀匹配
 *
 * @param ipa 第一个ip
 * @param ipb 第二个ip
 * @return uint8_t 两个ip相同的前缀长度
 */
uint8_t ip_prefix_match(uint8_t *ipa, uint8_t *ipb) {
    uint8_t count = 0;
    for (size_t i = 0; i < 4; i++) {
        uint8_t flag = ipa[i] ^ ipb[i];
        for (size_t j = 0; j < 8; j++) {
            if (flag & (1 << 7))
                return count;
            else
                count++, flag <<= 1;
        }
    }
    return count;
}

/**
 * @brief 计算16位校验和
 *
 * @param buf 要计算的数据包
 * @param len 要计算的长度
 * @return uint16_t 校验和
 */
uint16_t checksum16(uint16_t *data, size_t len) {
    // Step1 按 16 位分组相加
    uint32_t sum = 0;
    size_t i;
    
    // 计算有多少个完整的16位数据
    size_t word_count = len / 2;
    
    // 依次相加每个16位数据
    for (i = 0; i < word_count; i++) {
        sum += data[i];
    }
    
    // Step2 如果最后还剩 8 个 bit 值，也要将这个 8bit 值与之前的和相加
    if (len % 2 == 1) {
        // 如果长度是奇数，还有一个字节需要处理
        // 将这个字节放在高8位，低8位补0
        uint8_t *byte_data = (uint8_t *)data;
        sum += (uint16_t)(byte_data[len - 1] << 8);
    }
    
    // Step3 循环处理高 16 位
    while (sum > 0xFFFF) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // Step4 取反得到校验和
    return (uint16_t)(~sum);
}

#pragma pack(1)
typedef struct peso_hdr {
    uint8_t src_ip[4];     // 源IP地址
    uint8_t dst_ip[4];     // 目的IP地址
    uint8_t placeholder;   // 必须置0,用于填充对齐
    uint8_t protocol;      // 协议号
    uint16_t total_len16;  // 整个数据包的长度
} peso_hdr_t;
#pragma pack()

/**
 * @brief 计算传输层协议（如TCP/UDP）的校验和
 *
 * @param protocol  传输层协议号（如NET_PROTOCOL_UDP、NET_PROTOCOL_TCP）
 * @param buf       待计算的数据包缓冲区
 * @param src_ip    源IP地址
 * @param dst_ip    目的IP地址
 * @return uint16_t 计算得到的16位校验和
 */
uint16_t transport_checksum(uint8_t protocol, buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip) {
    // Step1: 增加 UDP 伪头部
    buf_add_header(buf, sizeof(peso_hdr_t));

    // Step2: 暂存 IP 头部
    // 将被UDP伪头部覆盖的IP头部拷贝出来暂存
    ip_hdr_t temp_ip_hdr;
    memcpy(&temp_ip_hdr, buf->data - (sizeof(ip_hdr_t) - sizeof(peso_hdr_t)), sizeof(ip_hdr_t));
    
    // Step3: 填写 UDP 伪头部字段
    peso_hdr_t *peso_hdr = (peso_hdr_t *)buf->data;
    memcpy(peso_hdr->src_ip, src_ip, NET_IP_LEN);
    memcpy(peso_hdr->dst_ip, dst_ip, NET_IP_LEN);
    peso_hdr->protocol = protocol;
    peso_hdr->placeholder = 0;
    // UDP长度 = 总数据包长度 - 伪头部长度
    uint16_t udp_len = buf->len - sizeof(peso_hdr_t);
    peso_hdr->total_len16 = swap16(udp_len);
    
    // Step4: 计算 UDP 校验和
    // 对包含UDP伪头部、UDP头部和UDP数据的整个数据块进行校验和计算
    uint16_t checksum;
    if(buf->len % 2 == 0) {
        checksum = checksum16((uint16_t *)buf->data, buf->len);
    } else {
        buf_add_padding(buf, 1);
        checksum = checksum16((uint16_t *)buf->data, buf->len);
        buf_remove_padding(buf, 1);
    }
    
    // Step5: 恢复 IP 头部
    memcpy(buf->data - (sizeof(ip_hdr_t) - sizeof(peso_hdr_t)), &temp_ip_hdr, sizeof(ip_hdr_t));
    
    // Step6: 去掉 UDP 伪头部
    buf_remove_header(buf, sizeof(peso_hdr_t));
    
    // Step7: 返回校验和值
    return checksum;
}