/**
 * @file Utils.hpp
 * @brief 网络工具库头文件
 * 
 * 本文件定义了ARP报文结构、免费ARP发送器和定时调度器。
 * 提供以下功能：
 * 1. ARP报文格式定义（RFC 826）
 * 2. 免费ARP发送功能（RFC 5227）
 * 3. ARP冲突检测（RFC 5227）
 * 4. 周期性ARP发送调度器
 * 
 * @author GuoHaiZhe
 * @date 2026-02-11
 * @version 1.0
 */

#ifndef UTILS_HPP
#define UTILS_HPP

#include <mutex>
#include <condition_variable>
#include <iostream>
#include <cstring>  
#include <unistd.h> 
#include <thread>
#include <atomic>
#include <chrono>

namespace tools{

/**
 * @struct ArpPacket
 * @brief ARP报文结构体（RFC 826标准格式）
 * 
 * 包含以太网头部和ARP内容，共42字节。
 * 使用__attribute__((packed))确保内存布局紧凑。
 */
struct ArpPacket {
    // 以太网头 (14字节)
    unsigned char dest_mac[6];   ///< 目标MAC地址（广播时为FF:FF:FF:FF:FF:FF）
    unsigned char src_mac[6];    ///< 源MAC地址（发送方MAC）
    unsigned short eth_type;     ///< 以太网类型（0x0806表示ARP）
    
    // ARP 内容 (28字节)
    unsigned short hw_type;      ///< 硬件类型（1表示以太网）
    unsigned short proto_type;   ///< 协议类型（0x0800表示IPv4）
    unsigned char hw_len;        ///< 硬件地址长度（6字节）
    unsigned char proto_len;     ///< 协议地址长度（4字节）
    unsigned short opcode;       ///< 操作码（1:请求, 2:回复）
    unsigned char sender_mac[6]; ///< 发送方MAC地址
    unsigned char sender_ip[4];  ///< 发送方IP地址
    unsigned char target_mac[6]; ///< 目标MAC地址（请求时为00:00:00:00:00:00）
    unsigned char target_ip[4];  ///< 目标IP地址
} __attribute__((packed));

// ===== ArpPoster =====

/**
 * @class FreeArpPoster
 * @brief 免费ARP发送器类
 * 
 * 提供静态方法用于发送免费ARP报文和进行ARP冲突检测。
 * 所有方法都是静态的，禁止实例化此类。
 */
class FreeArpPoster{
public:
    /**
     * @brief 发送免费ARP报文
     * @param device 网络接口名称
     * @param ip 要宣告的IP地址
     * @param times 发送次数（通常5次）
     * @return true 成功, false 失败
     */
    static bool PostFreeARP(const std::string& device, const std::string& ip, uint8_t times);
    
    /**
     * @brief ARP冲突检测（RFC 5227）
     * @param device 网络接口名称
     * @param ip 要检测的IP地址
     * @return true 无冲突, false 有冲突
     * 
     * 发送sender_ip=0.0.0.0的ARP请求，监听1秒内是否有回复。
     * 如果有回复，说明该IP已被其他主机使用。
     */
    static bool ArpProbe(const std::string& device, const std::string& ip);

private:
    // 禁止构造，所有方法都是静态的
    FreeArpPoster() = delete;
};

// ===== ArpScheduler =====

/**
 * @class FreeArpScheduler
 * @brief 免费ARP定时调度器类
 * 
 * 在后台线程中周期性发送免费ARP报文，用于：
 * 1. 宣告VIP所有权
 * 2. 刷新网络中的ARP缓存
 * 3. 防止ARP缓存过期
 * 
 * 支持运行时动态更新设备名、IP地址和发送周期。
 */
class FreeArpScheduler {
public:
    // 禁止拷贝构造和赋值
    FreeArpScheduler(const FreeArpScheduler&) = delete;
    FreeArpScheduler& operator=(const FreeArpScheduler&) = delete;

    /**
     * @brief 构造函数
     * @param device 网络接口名称
     * @param ip 要发送的IP地址
     * @param period 发送周期（秒）
     */
    FreeArpScheduler(std::string device,
                     std::string ip,
                     std::chrono::seconds period);

    /**
     * @brief 析构函数
     * 
     * 自动停止后台线程并等待线程结束。
     */
    ~FreeArpScheduler();

    // 控制接口
    /**
     * @brief 启动定时器
     * 
     * 如果定时器已经在运行，则不会重复启动。
     */
    void start();
    
    /**
     * @brief 停止定时器
     * 
     * 停止后台线程并等待线程结束。
     */
    void stop();

    // 动态配置接口
    /**
     * @brief 设置网络接口名称
     * @param device 新的网络接口名称
     */
    void setDevice(std::string device);
    
    /**
     * @brief 设置IP地址
     * @param ip 新的IP地址
     */
    void setIP(std::string ip);
    
    /**
     * @brief 设置发送周期
     * @param period 新的发送周期
     */
    void setPeriod(std::chrono::seconds period);

private:
    /**
     * @brief 定时器工作线程函数
     * 
     * 在后台循环发送免费ARP报文，直到被停止。
     * 使用条件变量实现精确的定时等待。
     */
    void run();

private:
    // ===== 业务参数 =====
    std::string device_;           ///< 网络接口名称
    std::string ip_;               ///< 要发送的IP地址
    std::chrono::seconds period_;  ///< 发送周期

    // ===== 线程控制 =====
    std::atomic<bool> running_;    ///< 运行标志
    std::thread worker_;           ///< 工作线程

    // ===== 同步原语 =====
    std::mutex param_mtx_;         ///< 保护device_/ip_/period_参数的互斥锁
    std::mutex wait_mtx_;          ///< 用于条件变量等待的互斥锁
    std::condition_variable cv_;   ///< 条件变量，用于定时等待和即时中断
};

}

#endif
