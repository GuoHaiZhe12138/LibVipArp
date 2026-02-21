/**
 * @file ArpSchedule.cpp
 * @brief 免费ARP定时调度器实现文件
 * 
 * 本文件实现了FreeArpScheduler类的所有功能，包括：
 * 1. 定时器的线程安全启动和停止
 * 2. 运行时动态参数配置（设备名、IP地址、周期）
 * 3. 精确的定时调度机制
 * 4. 线程同步和资源管理
 * 
 * @author GuoHaiZhe
 * @date 2026-02-11
 * @version 1.0
 */

#include "Utils.hpp"

namespace tools{

/**
 * @brief 构造函数
 * @param device 网络接口名称
 * @param ip 要发送的IP地址
 * @param period 发送周期
 * 
 * 初始化所有成员变量，使用std::move优化字符串传递效率。
 * 初始状态为停止状态（running_ = false）。
 */
FreeArpScheduler::FreeArpScheduler(std::string device,
                                   std::string ip,
                                   std::chrono::seconds period)
    : device_(std::move(device)),
      ip_(std::move(ip)),
      period_(period),
      running_(false) {

      }

/**
 * @brief 析构函数
 * 
 * 自动调用stop()函数，确保线程安全地停止后台工作线程。
 * 如果定时器仍在运行，会先停止它再销毁对象。
 */
FreeArpScheduler::~FreeArpScheduler() {
    stop();
}

/**
 * @brief 启动定时器
 * 
 * 使用原子操作确保线程安全，避免重复启动。
 * 如果定时器已经在运行，则直接返回。
 * 创建后台工作线程执行run()函数。
 */
void FreeArpScheduler::start() {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) {
        return; // 已经在运行
    }

    worker_ = std::thread(&FreeArpScheduler::run, this);
}

/**
 * @brief 停止定时器
 * 
 * 设置停止标志，通知条件变量，等待工作线程结束。
 * 使用条件变量确保线程能够及时响应停止请求。
 */
void FreeArpScheduler::stop() {
    if (!running_) return;

    running_ = false;
    cv_.notify_all();

    if (worker_.joinable()) {
        worker_.join();
    }
}

/**
 * @brief 设置网络接口名称
 * @param device 新的网络接口名称
 * 
 * 使用互斥锁保护参数，确保线程安全。
 */
void FreeArpScheduler::setDevice(std::string device) {
    std::lock_guard<std::mutex> lock(param_mtx_);
    device_ = std::move(device);
}

/**
 * @brief 设置IP地址
 * @param ip 新的IP地址
 * 
 * 使用互斥锁保护参数，确保线程安全。
 */
void FreeArpScheduler::setIP(std::string ip) {
    std::lock_guard<std::mutex> lock(param_mtx_);
    ip_ = std::move(ip);
}

/**
 * @brief 设置发送周期
 * @param period 新的发送周期
 * 
 * 更新周期参数并立即通知条件变量，使新的周期立即生效。
 * 使用互斥锁保护参数，确保线程安全。
 */
void FreeArpScheduler::setPeriod(std::chrono::seconds period) {
    {
        std::lock_guard<std::mutex> lock(param_mtx_);
        period_ = period;
    }
    cv_.notify_all(); // 立即生效
}

/**
 * @brief 定时器工作线程函数
 * 
 * 主循环逻辑：
 * 1. 获取最新的参数（设备名、IP地址、周期）
 * 2. 发送一次免费ARP报文
 * 3. 计算下一次发送的时间点
 * 4. 使用条件变量精确等待到指定时间
 * 
 * 支持在等待过程中被中断（周期调整或停止请求）。
 * 使用条件变量的wait_until实现精确的定时调度。
 */
void FreeArpScheduler::run() {
    auto next = std::chrono::steady_clock::now();

    while (running_) {
        std::string device;
        std::string ip;
        std::chrono::seconds period;

        // 每次发送时获取最新的值，支持运行时动态更新
        {
            std::lock_guard<std::mutex> lock(param_mtx_);
            device = device_;
            ip = ip_;
            period = period_;
        }

        // 发送一次免费ARP报文
        FreeArpPoster::PostFreeARP(device, ip, 1);

        // 计算下个周期时间
        next += period;

        // 等待下一次周期到来或停止运行
        std::unique_lock<std::mutex> lock(wait_mtx_);
        cv_.wait_until(lock, next, [&] {
            return !running_;
        });
    }
}

}
