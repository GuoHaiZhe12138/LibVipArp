/**
 * @file VipManager.hpp
 * @brief VIP管理器头文件
 * 
 * 本文件定义了VipManager类，用于在Linux系统上管理虚拟IP地址。
 * 支持VIP的添加、删除、查询，并包含ARP冲突检测和免费ARP发送功能。
 * 
 * @author GuoHaiZhe
 * @date 2026-02-11
 * @version 1.0
 */

#ifndef VIPMANAGER_HPP
#define VIPMANAGER_HPP

#include <iostream>
#include <cstring>  
#include <unistd.h> 
#include <net/if.h> 
#include <memory>
#include "Utils.hpp"

namespace tools{

/**
 * @class VipManager
 * @brief VIP管理类
 * 
 * 通过Linux netlink接口与内核通信，实现VIP地址的管理。
 * 支持以下功能：
 * 1. ARP冲突检测 (RFC 5227)
 * 2. 通过netlink添加/删除VIP
 * 3. 周期性发送免费ARP宣告
 * 4. 查询VIP存在状态
 */
class VipManager {
public:
    /**
     * @brief 构造函数
     * @param device 网络接口名称 (如 "eth0")
     */
    VipManager(const std::string& device);

    /**
     * @brief 析构函数
     */
    ~VipManager();

    /**
     * @brief 添加VIP地址
     * @param ip 要添加的IP地址 (如 "192.168.1.100")
     * @param maskLen 子网掩码长度 (如 24)
     * @return true 成功, false 失败
     */
    bool addVip(const std::string& ip, uint8_t maskLen);

    /**
     * @brief 删除VIP地址
     * @param ip 要删除的IP地址
     * @param maskLen 子网掩码长度
     * @return true 成功, false 失败
     */
    bool delVip(const std::string& ip, uint8_t maskLen);

    /**
     * @brief 检查VIP是否存在
     * @param ip 要检查的IP地址
     * @return true 存在, false 不存在
     */
    bool hasVip(const std::string& ip);

private:
    /**
     * @brief 编辑VIP地址 (内部通用方法)
     * @param ip IP地址
     * @param maskLen 子网掩码长度
     * @param isAdd true为添加, false为删除
     * @return true 成功, false 失败
     */
    bool editVip(const std::string& ip, uint8_t maskLen, bool isAdd);

private:
    int netlinkFd{-1};                          ///< Netlink socket文件描述符
    unsigned int deviceIndex{0};               ///< 网络接口索引
    std::unique_ptr<FreeArpScheduler> freeArp_; ///< 免费ARP定时器
};

}

#endif
