/**
 * @file VipManager.cpp
 * @brief VIP管理器实现文件
 * 
 * 本文件实现了VipManager类的所有功能，包括：
 * 1. 通过Linux netlink接口管理IP地址
 * 2. ARP冲突检测实现 (RFC 5227)
 * 3. VIP地址的添加、删除和查询
 * 4. 免费ARP周期性发送集成
 * 
 * @author GuoHaiZhe
 * @date 2026-02-11
 * @version 1.0
 */

#include "VipManager.hpp"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "Utils.hpp"

namespace tools{

/**
 * @brief VipManager构造函数
 * @param device 网络接口名称 (如 "eth0")
 * 
 * 初始化netlink socket，绑定到内核路由子系统，
 * 获取设备索引，并初始化免费ARP定时器。
 */
VipManager::VipManager(const std::string& device) {
        // 创建netlink socket，用于与内核路由子系统通信
        netlinkFd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (netlinkFd < 0) {
            perror("Failed to create netlink socket");
            return;
        }

        // 绑定socket到当前进程
        sockaddr_nl local;
        memset(&local, 0, sizeof(local));
        local.nl_family = AF_NETLINK;
        local.nl_pid = getpid();
        local.nl_groups = 0;  // 不加入任何组播组
        if (bind(netlinkFd, (struct sockaddr*)&local, sizeof(local)) < 0) {
            perror("Failed to bind netlink socket");
            close(netlinkFd);
            netlinkFd = -1;
            return;
        }

        // 获取网络接口索引，用于后续netlink消息
        deviceIndex = if_nametoindex(device.c_str());
        if (deviceIndex == 0) {
            perror("if_nametoindex");
            close(netlinkFd);
            return;
        }

        // 初始化免费ARP定时器（使用默认参数，后续动态配置）
        freeArp_ = std::make_unique<FreeArpScheduler>(
                    "", "0.0.0.0", std::chrono::seconds(60)
                    );
    }

VipManager::~VipManager() {
        if (netlinkFd >= 0) {
            close(netlinkFd);
        }
    }

/**
 * @brief 编辑VIP地址 (内部通用方法)
 * @param ip IP地址
 * @param maskLen 子网掩码长度
 * @param isAdd true为添加, false为删除
 * @return true 成功, false 失败
 * 
 * 通过Linux netlink接口与内核通信，添加或删除IP地址。
 * 使用RTM_NEWADDR/RTM_DELADDR消息类型，设置IFA_LOCAL和IFA_ADDRESS属性。
 * 发送消息后等待内核的ACK确认，确保操作成功。
 */
bool VipManager::editVip(const std::string& ip, uint8_t maskLen, bool isAdd) {
        // 准备缓冲区
        char sendBuf[128];
        char recvBuf[512];
        memset(sendBuf, 0, sizeof(sendBuf));
        memset(recvBuf, 0, sizeof(recvBuf));

        // 构建最外层的 netlink 消息头
        struct nlmsghdr* nlh = (struct nlmsghdr*)sendBuf;
        nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
        nlh->nlmsg_type = isAdd ? RTM_NEWADDR : RTM_DELADDR;  // 添加新地址或删除地址
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | (isAdd ? NLM_F_CREATE : 0);   // 事务语义: 请求, 若不存在则创建, 需要回执
        nlh->nlmsg_seq = 1;
        nlh->nlmsg_pid = getpid();

        // 填充 ifaddrmsg 结构体
        struct ifaddrmsg* ifa = (struct ifaddrmsg*)NLMSG_DATA(nlh); // 获取 nlmsghdr内的ifaddrmsg 指针
        ifa->ifa_family    = AF_INET;   // IPv4
        ifa->ifa_prefixlen = maskLen;   // 子网掩码长度
        ifa->ifa_scope     = RT_SCOPE_UNIVERSE; // 全局范围
        ifa->ifa_index     = deviceIndex;    // 获取设备索引

        // rtattr
        // 获取 nlmsghdr 内的 ifaddrmsg 之后的 rtattr 指针
        struct rtattr *rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
        uint32_t ipBin = inet_addr(ip.c_str());   // 将字符串 IP 转换为 uint32_t 格式
        rta->rta_type = IFA_LOCAL;                  // 地址类型: 本地地址
        rta->rta_len  = RTA_LENGTH(sizeof(ipBin));     // 地址长度

        memcpy(RTA_DATA(rta), &ipBin, sizeof(ipBin));     // 复制 IP 地址数据到 rtattr 数据部分
        nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len); // 更新 nlmsghdr 的总长度
        // 另一个 rtattr 用于目的地址
        rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
        rta->rta_type = IFA_ADDRESS;                // 地址类型: 目的地址
        rta->rta_len  = RTA_LENGTH(sizeof(ipBin));     // 地址长度

        memcpy(RTA_DATA(rta), &ipBin, sizeof(ipBin));     // 复制 IP 地址数据到 rtattr 数据部分

        nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len); // 更新 nlmsghdr 的总长度

        // 发送 netlink 消息到内核
        struct sockaddr_nl addr{};
        addr.nl_family = AF_NETLINK;
        addr.nl_pid = 0; // to kernel

        if(sendto(netlinkFd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            perror("netlink send fail");
            return false;
        }

        // 检查回执
        ssize_t recvLen = recvfrom(netlinkFd, recvBuf, sizeof(recvBuf), 0, nullptr, nullptr);
        if(recvLen < 0) {
            perror("recvfrom failed");
            return false;
        }

        // 解析回执消息
        struct nlmsghdr* recvNlh = (struct nlmsghdr *)recvBuf;
        if (!NLMSG_OK(recvNlh, recvLen)) {
            std::cerr << "Invalid netlink message" << std::endl;
            return false;
        }

        if (recvNlh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr* err = (struct nlmsgerr*)NLMSG_DATA(recvNlh);
            if (err->error != 0) {
                std::cerr << "Error editing VIP: " << strerror(-err->error) << std::endl;
                return false;
            }
        }

        return true;
    }

/**
 * @brief 删除VIP地址
 * @param ip 要删除的IP地址
 * @param maskLen 子网掩码长度
 * @return true 成功, false 失败
 * 
 * 删除VIP的流程：
 * 1. 通过netlink删除IP地址
 * 2. 停止免费ARP定时器
 */
bool VipManager::delVip(const std::string& ip, uint8_t maskLen) {
        
        if(!editVip(ip, maskLen, false))
        {
            perror("edit Vip fail");
            return false;
        }

        freeArp_->stop();
        return true;
    }

/**
 * @brief 添加VIP地址
 * @param ip 要添加的IP地址
 * @param maskLen 子网掩码长度
 * @return true 成功, false 失败
 * 
 * 添加VIP的完整流程：
 * 1. 将设备索引转换为设备名称
 * 2. 执行ARP冲突检测（RFC 5227）
 * 3. 通过netlink添加IP地址到内核
 * 4. 配置并启动免费ARP定时器
 */
bool VipManager::addVip(const std::string& ip, uint8_t maskLen) {

        char ifname[IFNAMSIZ] = {0};

        // 将设备索引转换为设备名称
        if (if_indextoname(deviceIndex, ifname) == nullptr) {
            perror("if_indextoname");
            return false;
        }
        
        // ARP冲突检测：发送sender_ip=0.0.0.0的ARP请求，监听1秒内是否有回复
        if(!FreeArpPoster::ArpProbe(ifname, ip))
        {
            std::cout << "This ip already exit" << std::endl;
            return false;
        }

        // 通过netlink添加IP地址到内核
        if(!editVip(ip, maskLen, true))
        {
            perror("edit Vip fail");
            return false;
        }

        // 配置免费ARP定时器参数并启动
        freeArp_->setDevice(ifname);
        freeArp_->setIP(ip);
        freeArp_->setPeriod(std::chrono::seconds(5));
        freeArp_->start();
        
        return true;
    }

bool VipManager::hasVip(const std::string& ip) {
        // 准备缓冲区
        char sendBuf[128];
        char recvBuf[8192];
        memset(sendBuf, 0, sizeof(sendBuf));
        memset(recvBuf, 0, sizeof(recvBuf));

        // 构建 netlink 消息头
        struct nlmsghdr* nlh = (struct nlmsghdr*)sendBuf;
        nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
        nlh->nlmsg_type = RTM_GETADDR;  // 获取地址
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;   // 事务语义: 请求, 转储所有地址
        nlh->nlmsg_seq = 1;
        nlh->nlmsg_pid = getpid();

        // 构造ifaddrmsg
        struct ifaddrmsg* ifa = (struct ifaddrmsg*)NLMSG_DATA(nlh); // 获取 nlmsghdr内的ifaddrmsg 指针
        ifa->ifa_family    = AF_INET;   // IPv4
        ifa->ifa_index     = deviceIndex;    // 获取设备索引
        ifa->ifa_prefixlen = 0;              // 不限制前缀长度
        ifa->ifa_scope     = RT_SCOPE_UNIVERSE; // 全局范围

        // 发送 netlink 消息到内核
        struct sockaddr_nl addr{};
        addr.nl_family = AF_NETLINK;
        addr.nl_pid = 0; // to kernel
        if(sendto(netlinkFd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("sendto failed");
            return false;
        }

        uint32_t targetIpBin = inet_addr(ip.c_str());
        bool found = false;
        bool endOfDump = false;

        // 接收内核的响应
        while (!endOfDump) {
            ssize_t recvLen = recv(netlinkFd, recvBuf, sizeof(recvBuf), 0);
            if (recvLen < 0) {
            perror("recv failed");
            return false;
            }
            // 解析内核返回的地址列表
            for (struct nlmsghdr* rnh = (struct nlmsghdr*)recvBuf; NLMSG_OK(rnh, recvLen); rnh = NLMSG_NEXT(rnh, recvLen)) {

                // 1. 检查是否是本次 Dump 的结束标志
                if (rnh->nlmsg_type == NLMSG_DONE) {
                    endOfDump = true;
                    break;
                }
                // 2. 检查是否有错误
                if (rnh->nlmsg_type == NLMSG_ERROR) {
                    return false;
                }
            
                // 3. 只有 RTM_NEWADDR 才是真正的地址数据
                if (rnh->nlmsg_type == RTM_NEWADDR) {
                    struct ifaddrmsg* ifa_res = (struct ifaddrmsg*)NLMSG_DATA(rnh);

                    // 过滤
                    if (ifa_res->ifa_index != deviceIndex) continue;
                
                    // 遍历属性 rtattr 找 IP
                    struct rtattr* rta = IFA_RTA(ifa_res);
                    int rtaLen = IFA_PAYLOAD(rnh);
                
                    for (; RTA_OK(rta, rtaLen); rta = RTA_NEXT(rta, rtaLen)) {
                        if (rta->rta_type == IFA_LOCAL) {
                            uint32_t foundIp = *(uint32_t*)RTA_DATA(rta);
                            if (foundIp == targetIpBin) {
                                found = true;
                            }
                        }
                    }
                }
            }
        }
        return found;
}

}
