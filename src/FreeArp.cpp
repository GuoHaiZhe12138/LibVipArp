/**
 * @file FreeArp.cpp
 * @brief 免费ARP发送器实现文件
 * 
 * 本文件实现了FreeArpPoster类的所有功能，包括：
 * 1. 免费ARP报文发送（RFC 5227）
 * 2. ARP冲突检测实现（RFC 5227）
 * 3. 原始套接字操作和网络接口管理
 * 
 * @author GuoHaiZhe
 * @date 2026-02-11
 * @version 1.0
 */

#include "Utils.hpp"
#include <sys/socket.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <poll.h>
#include <chrono>

namespace tools{

/**
 * @brief 发送免费ARP报文
 * @param device 网络接口名称
 * @param ip 要宣告的IP地址
 * @param times 发送次数（通常5次）
 * @return true 成功, false 失败
 * 
 * 功能说明：
 * 1. 创建AF_PACKET原始套接字，直接发送以太网帧
 * 2. 获取网络接口的索引和MAC地址
 * 3. 构造免费的ARP请求报文（sender_ip = target_ip）
 * 4. 发送指定次数的ARP报文，间隔5ms
 * 
 * 免费ARP的作用：
 * 1. 更新网络中其他主机的ARP缓存
 * 2. 宣告本机对IP地址的所有权
 * 3. 检测IP地址冲突（与其他主机的免费ARP相互作用）
 */
bool FreeArpPoster::PostFreeARP(const std::string& device, const std::string& ip, uint8_t times) {
    int freeArpFd{-1};                 ///< 原始套接字文件描述符
    unsigned int deviceIndex{0};       ///< 网络接口索引
    unsigned char deviceMac[6]{0};     ///< 网络接口MAC地址
    ArpPacket arpPacket;               ///< ARP报文结构

    // 创建原始套接字，用于发送以太网级别的ARP报文
    freeArpFd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    // 初始化工具结构体
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, device.c_str(), IFNAMSIZ - 1);
    // 获取设备索引
    if(ioctl(freeArpFd, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("ioctl get index failed");
        close(freeArpFd);
        return false;
    }
    deviceIndex = ifr.ifr_ifindex;

    // 获取MAC
    if (ioctl(freeArpFd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl get mac failed");
        close(freeArpFd);
        return false;
    }
    std::memcpy(deviceMac, ifr.ifr_hwaddr.sa_data, 6);

    // arp报文填充
    unsigned char dest_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    unsigned char target_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char target_ip[4] = {0};
    if(inet_pton(AF_INET, ip.c_str(), target_ip) != 1)
    {
        perror("ip trans failed");
        close(freeArpFd);
        return false;
    }

    std::memcpy(arpPacket.dest_mac, dest_mac, 6);
    std::memcpy(arpPacket.src_mac, deviceMac, 6);
    arpPacket.eth_type = htons(ETH_P_ARP);
    arpPacket.hw_type = htons(1);
    arpPacket.proto_type = htons(ETH_P_IP);
    arpPacket.hw_len = 0x06;
    arpPacket.proto_len = 0x04;
    arpPacket.opcode = htons(1);
    std::memcpy(arpPacket.sender_mac, deviceMac, 6);
    std::memcpy(arpPacket.sender_ip, target_ip, 4);
    std::memcpy(arpPacket.target_mac, target_mac, 6);
    std::memcpy(arpPacket.target_ip, target_ip, 4);

    // 构造发送arp需要的结构体
    struct sockaddr_ll addr;
    std::memset(&addr, 0, sizeof(addr));

    addr.sll_family   = AF_PACKET;
    addr.sll_ifindex  = deviceIndex;
    addr.sll_halen    = 6;
    std::memcpy(addr.sll_addr, dest_mac, 6);

    // 发送arp报文
    for(uint8_t i = 0 ; i < times ; i++)
    {
        ssize_t bytes = sendto(freeArpFd, &arpPacket, sizeof(arpPacket), 0, 
                       (struct sockaddr*)&addr, sizeof(addr));
        if(!(bytes > 0))
        {
            std::cout << "send empty" << std::endl;
        }
        usleep(5000);
    }

    close(freeArpFd);
    return true;
}

bool FreeArpPoster::ArpProbe(const std::string& device, const std::string& ip) {
    int freeArpFd{-1};
    unsigned int deviceIndex{0};
    unsigned char deviceMac[6]{0};
    ArpPacket arpPacket;

    // 创建socket连接
    freeArpFd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    // 初始化工具结构体
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, device.c_str(), IFNAMSIZ - 1);
    // 获取设备索引
    if(ioctl(freeArpFd, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("ioctl get index failed");
        close(freeArpFd);
        return false;
    }
    deviceIndex = ifr.ifr_ifindex;

    // 获取MAC
    if (ioctl(freeArpFd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl get mac failed");
        close(freeArpFd);
        return false;
    }
    std::memcpy(deviceMac, ifr.ifr_hwaddr.sa_data, 6);

    // arp报文填充
    unsigned char dest_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    unsigned char target_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char empty_ipv4[4] = {0, 0, 0, 0};
    unsigned char target_ip[4] = {0};
    if(inet_pton(AF_INET, ip.c_str(), target_ip) != 1)
    {
        perror("ip trans failed");
        close(freeArpFd);
        return false;
    }

    std::memcpy(arpPacket.dest_mac, dest_mac, 6);
    std::memcpy(arpPacket.src_mac, deviceMac, 6);
    arpPacket.eth_type = htons(ETH_P_ARP);
    arpPacket.hw_type = htons(1);
    arpPacket.proto_type = htons(ETH_P_IP);
    arpPacket.hw_len = 0x06;
    arpPacket.proto_len = 0x04;
    arpPacket.opcode = htons(1);
    std::memcpy(arpPacket.sender_mac, deviceMac, 6);
    std::memcpy(arpPacket.sender_ip, empty_ipv4, 4);
    std::memcpy(arpPacket.target_mac, target_mac, 6);
    std::memcpy(arpPacket.target_ip, target_ip, 4);

    // 构造发送arp需要的结构体
    struct sockaddr_ll addr;
    std::memset(&addr, 0, sizeof(addr));

    addr.sll_family   = AF_PACKET;
    addr.sll_ifindex  = deviceIndex;
    addr.sll_halen    = 6;
    std::memcpy(addr.sll_addr, dest_mac, 6);

    // 发送arp报文
    for(uint8_t i = 0 ; i <= 1 ; i++)
    {
        ssize_t bytes = sendto(freeArpFd, &arpPacket, sizeof(arpPacket), 0, 
                       (struct sockaddr*)&addr, sizeof(addr));
        if(!(bytes > 0))
        {
            std::cout << "send empty" << std::endl;
        }
        usleep(500);
    }

    // --- 监听回复逻辑 ---
    struct pollfd pfd;
    pfd.fd = freeArpFd;
    pfd.events = POLLIN;

    // 设置探测的总等待时间：1000ms
    int timeout_ms = 1000;
    auto start_time = std::chrono::steady_clock::now();

    while (true) {
        // 计算剩余可用时间
        auto now = std::chrono::steady_clock::now();
        int elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
        int remaining = timeout_ms - elapsed;

        if (remaining <= 0) break; // 时间到，没有冲突

        // 阻塞等待数据
        int ret = poll(&pfd, 1, remaining);
        if (ret < 0) {
            perror("poll error");
            break;
        }
        if (ret == 0) break; // 超时

        // 读取数据包
        ArpPacket recvPkt;
        ssize_t bytes = recv(freeArpFd, &recvPkt, sizeof(recvPkt), 0);
        if (bytes < (ssize_t)sizeof(ArpPacket)) continue;

        // 过滤逻辑：
        // 1. 必须是 ARP 报文 
        // 2. 检查 sender_ip 是否等于我们要探测的 target_ip
        if (std::memcmp(recvPkt.sender_ip, target_ip, 4) == 0 &&
            recvPkt.opcode == htons(2)) {
            // 冲突
            std::cout << "Conflict detected! IP " << ip << " is already used by " 
                      << std::hex 
                      << (int)recvPkt.src_mac[0] << ":" << (int)recvPkt.src_mac[1] << ":"
                      << (int)recvPkt.src_mac[2] << ":" << (int)recvPkt.src_mac[3] << ":"
                      << (int)recvPkt.src_mac[4] << ":" << (int)recvPkt.src_mac[5] 
                      << std::dec << std::endl;
            
            close(freeArpFd);
            return false; // 返回 false 表示有冲突，不可设置 IP
        }
    }
    
    close(freeArpFd);
    return true;

}

}
