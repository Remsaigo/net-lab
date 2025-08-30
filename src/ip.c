#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // Step1 检查数据包长度
    // 若数据包的长度小于 IP 头部长度，表明该数据包不完整，将其丢弃
    if (buf->len < sizeof(ip_hdr_t)) {
        return;
    }
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    
    // Step2 进行报头检测
    // 检查IP头部的版本号是否为 IPv4
    if (ip_hdr->version != IP_VERSION_4) {
        return;
    }
    
    // 获取总长度（转换为主机字节序）
    uint16_t total_len = swap16(ip_hdr->total_len16);
    // 检查总长度字段是否小于或等于收到的数据包长度
    if (total_len > buf->len) {
        return;
    }
    
    // Step3 校验头部校验和
    // 先把头部校验和字段用其他变量保存起来
    uint16_t original_checksum = ip_hdr->hdr_checksum16;
    // 将该头部校验和字段置为 0
    ip_hdr->hdr_checksum16 = 0;
    // 调用 checksum16 函数来计算头部校验和
    uint16_t calculated_checksum = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));
    // 将计算结果与 IP 头部原本的首部校验和字段进行对比
    if (calculated_checksum != original_checksum) {
        // 若不一致，说明数据包在传输过程中可能出现损坏，将其丢弃
        return;
    }
    // 若一致，则再将该头部校验和字段恢复成原来的值
    ip_hdr->hdr_checksum16 = original_checksum;
    
    // Step4 对比目的 IP 地址是否为本机的 IP 地址
    if (memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0) {
        // 若不是，说明该数据包并非发送给本机，将其丢弃
        return;
    }
    
    // Step5 去除填充字段
    // 如果接收到的数据包的长度大于 IP 头部的总长度字段，说明该数据包存在填充字段
    if (buf->len > total_len) {
        buf_remove_padding(buf, buf->len - total_len);
    }
    
    // Step6 去掉 IP 报头
    buf_remove_header(buf, sizeof(ip_hdr_t));
    
    // Step7 向上层传递数据包
    int result = net_in(buf, ip_hdr->protocol, ip_hdr->src_ip);

    // 若遇到不能识别的协议类型（通过net_in的返回结果判断）
    if (result < 0) {
        // 在发出 ICMP 协议报文前，需重新加入 IP 报头，以确保报文格式的完整性
        buf_add_header(buf, sizeof(ip_hdr_t));
        
        // 调用 icmp_unreachable() 函数返回 ICMP 协议不可达信息
        icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // Step1 增加头部缓存空间
    buf_add_header(buf, sizeof(ip_hdr_t));
    
    // Step2 填写头部字段
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    // 版本号（IPv4）
    ip_hdr->version = IP_VERSION_4;
    // 首部长度（以4字节为单位）
    ip_hdr->hdr_len = sizeof(ip_hdr_t) / 4;
    // 区分服务（服务类型）
    ip_hdr->tos = 0;
    // 总长度（包括头部和数据，转换为网络字节序）
    ip_hdr->total_len16 = swap16(buf->len);
    // 数据包标识（转换为网络字节序）
    ip_hdr->id16 = swap16(id);
    // 设置分片标志和偏移量
    uint16_t flags_and_offset = offset;
    if (mf) {
        flags_and_offset |= IP_MORE_FRAGMENT;  // 设置MF标志
    }
    ip_hdr->flags_fragment16 = swap16(flags_and_offset);
    // 生存时间
    ip_hdr->ttl = IP_DEFALUT_TTL;
    // 上层协议类型
    ip_hdr->protocol = protocol;
    // 源IP地址（本机IP）
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    // 目标IP地址
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);
    
    // Step3 计算并填写校验和
    // 先把 IP 头部的首部校验和字段填为 0
    ip_hdr->hdr_checksum16 = 0;
    // 调用 checksum16 函数计算校验和
    ip_hdr->hdr_checksum16 = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));
    
    // Step4 发送数据
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // IP协议最大负载包长（MTU - IP头部长度）
    const uint16_t max_payload = 1500 - sizeof(ip_hdr_t);
    
    // Step1 检查从上层传递下来的数据报包长是否大于 IP 协议最大负载包长
    static int packet_id = 0; // 数据包ID，每个数据包递增
    int current_id = packet_id++;
    if (buf->len <= max_payload) {
        // 直接发送
        ip_fragment_out(buf, ip, protocol, current_id, 0, 0);
        return;
    }
    
    // Step2 若数据报包长超过 IP 协议最大负载包长，则需要进行分片发送

    uint16_t remaining_len = buf->len;
    uint16_t data_offset = 0;
    uint16_t fragment_offset = 0; // 分片偏移量（以8字节为单位）
    buf_t ip_buf;
    
    while (remaining_len > 0) {
        // 计算当前分片的大小
        uint16_t fragment_size;
        int mf; // MF标志
        
        if (remaining_len > max_payload) {
            // 不是最后一个分片
            fragment_size = max_payload;
            mf = 1; // 设置MF标志，表示还有更多分片
        } else {
            // 最后一个分片
            fragment_size = remaining_len;
            mf = 0; // 清除MF标志，表示这是最后一个分片
        }
        
        // 首先调用 buf_init() 初始化一个 ip_buf
        buf_init(&ip_buf, fragment_size);
        
        // 将数据复制到分片缓冲区
        memcpy(ip_buf.data, buf->data + data_offset, fragment_size);
        
        // 调用 ip_fragment_out() 函数发送出去
        ip_fragment_out(&ip_buf, ip, protocol, current_id, fragment_offset, mf);
        
        // 更新偏移和剩余长度
        data_offset += fragment_size;
        remaining_len -= fragment_size;
        fragment_offset += fragment_size / 8;
    }
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}