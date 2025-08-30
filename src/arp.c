#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // Step1. 初始化缓冲区
    buf_init(&txbuf, sizeof(arp_pkt_t));
    
    // Step2. 填写ARP报头
    arp_pkt_t *arp_pkt = (arp_pkt_t *)txbuf.data;
    
    // 复制初始化模板到缓冲区
    memcpy(arp_pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    
    // 设置目标IP地址
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);
    
    // Step3. 设置操作类型为ARP_REQUEST
    arp_pkt->opcode16 = swap16(ARP_REQUEST);
    
    // Step4. 发送 ARP 报文
    // 调用 ethernet_out 函数将 ARP 报文发送出去
    // ARP 请求报文为广播报文，目标 MAC 地址设置为广播地址
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // Step1. 初始化缓冲区
    buf_init(&txbuf, sizeof(arp_pkt_t));
    
    // Step2. 填写 ARP 报头首部
    arp_pkt_t *arp_pkt = (arp_pkt_t *)txbuf.data;
    memcpy(arp_pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    // 设置操作类型为 ARP_REPLY（注意字节序转换）
    arp_pkt->opcode16 = swap16(ARP_REPLY);
    // 设置目标IP地址（要回应给谁）
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);
    // 设置目标MAC地址（要回应给谁的MAC地址）
    memcpy(arp_pkt->target_mac, target_mac, NET_MAC_LEN);
    
    // Step3. 发送 ARP 报文
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // Step1. 检查数据长度，若数据长度小于 ARP 头部长度，则认为数据包不完整，将其丢弃
    if (buf->len < sizeof(arp_pkt_t)) {
        return;
    }    
    arp_pkt_t *arp_pkt = (arp_pkt_t *)buf->data;
    
    // Step2. 报头检查
    // 检查硬件类型
    if (swap16(arp_pkt->hw_type16) != ARP_HW_ETHER) {
        return;
    }
    // 检查上层协议类型（应该是IP协议）
    if (swap16(arp_pkt->pro_type16) != NET_PROTOCOL_IP) {
        return;
    }
    // 检查MAC硬件地址长度（应该是6字节）
    if (arp_pkt->hw_len != NET_MAC_LEN) {
        return;
    }
    // 检查IP协议地址长度（应该是4字节）
    if (arp_pkt->pro_len != NET_IP_LEN) {
        return;
    }
    // 获取操作类型（转换为主机字节序）
    uint16_t opcode = swap16(arp_pkt->opcode16);
    // 检查操作类型（应该是REQUEST或REPLY）
    if (opcode != ARP_REQUEST && opcode != ARP_REPLY) {
        return;
    }
    
    // Step3. 更新 ARP 表项
    map_set(&arp_table, arp_pkt->sender_ip, arp_pkt->sender_mac);
    
    // Step4. 查看缓存情况
    buf_t *cached_buf = map_get(&arp_buf, arp_pkt->sender_ip);
    
    if (cached_buf != NULL) {
        // 若有缓存，说明 ARP 分组队列里面有待发送的数据包
        // 将缓存的数据包 arp_buf 发送给以太网层
        ethernet_out(cached_buf, arp_pkt->sender_mac, NET_PROTOCOL_IP);
        // 将这个缓存的数据包删除
        map_delete(&arp_buf, arp_pkt->sender_ip);
        
    } else {
        // 若该接收报文的 IP 地址没有对应的 arp_buf 缓存
        // 判断接收到的报文是否为 ARP_REQUEST 请求报文
        if (opcode == ARP_REQUEST) {
            // 检查目标IP是否是本机IP
            if (memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN) == 0) {
                // 若是，则认为是请求本主机 MAC 地址的 ARP 请求报文
                // 调用 arp_resp() 函数回应一个响应报文
                arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);
            }
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // Step1. 查找 ARP 表
    uint8_t *mac = map_get(&arp_table, ip);
    
    // Step2. 若能找到该 IP 地址对应的 MAC 地址，则将数据包直接发送给以太网层
    if (mac != NULL) {
        // 调用 ethernet_out 函数将数据包发出
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
        return;
    }
    
    // Step3. 若未找到对应的 MAC 地址，需进一步判断 arp_buf 中是否已经有包
    // 检查 arp_buf 中是否已经有缓存的数据包
    buf_t *cached_buf = map_get(&arp_buf, ip);
    
    if (cached_buf != NULL) {
        // 若有包，说明正在等待该 IP 回应 ARP 请求，此时不能再发送 ARP 请求
        // 丢弃当前数据包，因为已经有一个数据包在等待同一个IP的ARP回应
        return;
    } else {
        // 若没有包，则需要缓存当前数据包并发送ARP请求
        
        // 调用 map_set() 函数将来自 IP 层的数据包缓存到 arp_buf 中
        map_set(&arp_buf, ip, buf);
        
        // 调用 arp_req() 函数，发送一个请求目标 IP 地址对应的 MAC 地址的 ARP request 报文
        arp_req(ip);
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}