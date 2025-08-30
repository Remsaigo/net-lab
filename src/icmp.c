#include "icmp.h"

#include "ip.h"
#include "net.h"

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    // Step1: 初始化并封装数据
    // 初始化发送缓冲区
    buf_init(&txbuf, req_buf->len);
    // 获取接收到的ICMP报头
    icmp_hdr_t *req_icmp_hdr = (icmp_hdr_t *)req_buf->data;
    // 在发送缓冲区中构造ICMP报头
    icmp_hdr_t *resp_icmp_hdr = (icmp_hdr_t *)txbuf.data;
    // 设置ICMP响应报头字段
    resp_icmp_hdr->type = ICMP_TYPE_ECHO_REPLY;  // 回显应答类型 (0)
    resp_icmp_hdr->code = 0;                     // 代码字段为0
    resp_icmp_hdr->checksum16 = 0;
    resp_icmp_hdr->id16 = req_icmp_hdr->id16;        // 复制请求报文的标识符
    resp_icmp_hdr->seq16 = req_icmp_hdr->seq16;      // 复制请求报文的序列号
    
    // 复制数据部分（从请求报文的数据部分开始）
    size_t data_len = req_buf->len - sizeof(icmp_hdr_t);
    if (data_len > 0) {
        memcpy(txbuf.data + sizeof(icmp_hdr_t), 
               req_buf->data + sizeof(icmp_hdr_t), 
               data_len);
    }
    
    // Step2: 填写校验和
    // 计算整个ICMP报文的校验和
    resp_icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);
    
    // Step3: 发送数据报
    // 调用ip_out函数发送ICMP响应报文
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // Step1: 检查数据包长度是否足够包含ICMP头部
    if (buf->len < sizeof(icmp_hdr_t)) {
        // 数据包长度不足，丢弃数据包
        return;
    }
    
    // Step2: 查看ICMP类型
    icmp_hdr_t *icmp_header = (icmp_hdr_t *)buf->data;
    // 检查ICMP类型是否为回显请求
    if (icmp_header->type == ICMP_TYPE_ECHO_REQUEST) {
        // Step3: 回送回显应答
        icmp_resp(buf, src_ip);
    }
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // Step1: 初始化并填写报头
    // 计算ICMP报文总长度：ICMP头部 + IP头部 + IP数据报前8字节
    size_t ip_hdr_len = sizeof(ip_hdr_t);
    size_t icmp_data_len = ip_hdr_len + 8; // IP头部 + 前8字节数据
    size_t total_len = sizeof(icmp_hdr_t) + icmp_data_len;
    // 初始化发送缓冲区
    buf_init(&txbuf, total_len);
    // 构造ICMP报头
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr->type = ICMP_TYPE_UNREACH;      // 目标不可达类型
    icmp_hdr->code = code;                   // 具体的错误代码
    icmp_hdr->checksum16 = 0;                // 校验和先设为0，后续计算
    icmp_hdr->id16 = 0;
    icmp_hdr->seq16 = 0;
    
    // Step2: 填写数据与校验和
    // 填写ICMP数据部分
    uint8_t *icmp_data = txbuf.data + sizeof(icmp_hdr_t);

    // 1. 复制完整的原始IP头部
    memcpy(icmp_data, recv_buf->data, ip_hdr_len);
    // 2. 复制原始IP数据报的前8字节数据
    memcpy(icmp_data + ip_hdr_len, 
            recv_buf->data + ip_hdr_len, 
            8);
    // 计算ICMP校验和
    icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);
    
    // Step3: 发送数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}