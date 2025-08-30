#include "ethernet.h"

#include "arp.h"
#include "driver.h"
#include "ip.h"
#include "utils.h"
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    // Step1: 数据长度检查
    // 判断数据长度是否小于以太网头部长度
    if (buf->len < sizeof(ether_hdr_t)) {
        // 数据包不完整，丢弃处理
        return;
    }
    
    // 获取以太网帧头指针，用于后续协议类型判断
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    
    // 提取协议类型（转换为主机字节序）
    net_protocol_t protocol = swap16(hdr->protocol16);
    
    // Step2: 移除以太网包头
    buf_remove_header(buf, sizeof(ether_hdr_t));
    
    // Step3: 向上层传递数据包
    // 根据协议类型将数据包传递给相应的上层协议处理函数
    net_in(buf, protocol, hdr->src);
}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
    // Step1: 数据长度检查与填充
    if (buf->len < ETHERNET_MIN_TRANSPORT_UNIT) {
        buf_add_padding(buf, ETHERNET_MIN_TRANSPORT_UNIT - buf->len);
    }
    
    // Step2: 添加以太网包头
    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    
    // Step3: 填写目的MAC地址
    memcpy(hdr->dst, mac, NET_MAC_LEN);
    
    // Step4: 填写源MAC地址，即本机的MAC地址
    memcpy(hdr->src, net_if_mac, NET_MAC_LEN);
    
    // Step5: 填写协议类型 protocol
    hdr->protocol16 = swap16(protocol);
    
    // Step6: 发送数据帧
    // 调用驱动层封装好的 driver_send() 发送函数
    driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
