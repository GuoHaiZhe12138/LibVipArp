LibVipArp

LibVipArp 是一个轻量级、高性能的 C++ 工具库，专为嵌入式 Linux 设备（如 NVIDIA Jetson、ARM SBC）设计，用于在高可用性（HA）场景中管理 虚拟 IP（VIP）漂移 并确保网络邻居设备即时感知变化。

🧠 项目简介

在 HA（High Availability）集群与边缘系统中，虚拟 IP 会在主备节点之间漂移。LibVipArp 结合了内核 Netlink API 与 Gratuitous ARP（GARP）机制，实现：

动态添加/删除地址

ARPProbe 冲突检测

周期性发送 Gratuitous ARP 报文（刷新交换机 MAC 表）

最小权限、毫秒级响应

该项目适用于需要精细控制 VIP 行为而避免依赖系统 ip 命令或外部脚本的场景。

🚀 核心特性

✔ 严格遵循 RFC 5227 ARP 规范
在绑定 IP 之前执行 ARP Probe 探测，防止 IP 冲突。

✔ 高性能网络管理
通过 Netlink 直接与内核通信，无需外部命令（如 ip），性能更高。

✔ 可靠性保证
包含异步 ARP Scheduler，可定制周期发送 Arp 报文，避免交换机 MAC 表老化导致失效。

✔ 现代 C++17 API 设计
静态类型安全、RAII 资源管理、可轻松集成现有代码库。

📦 模块结构概览
模块	作用
VipManager	使用 Netlink 与内核管理 IP 地址生命周期
ArpProbe	在设定 VIP 生效前发送 ARP 探测以避免冲突
ArpScheduler	维护后台线程定期发送 Gratuitous ARP 报文
📥 安装与依赖
环境依赖

Linux 内核（RTNETLINK 支持）

支持 C++17 的编译器（如 g++ 7+ 或更高）

推荐用于嵌入式 Linux（如 Jetson L4T 或 Ubuntu）

🛠 编译 & 使用示例

CMake 工程示例

git clone https://github.com/GuoHaiZhe12138/LibVipArp.git
cd LibVipArp
mkdir build && cd build
cmake ..
make -j$(nproc)


⚠️ 注意：该库执行底层网络操作通常需要 root 权限进行测试/运行（或通过 Linux capabilities 赋予单独可执行文件必要权限）。

🧪 示例：使用 VipManager
#include "LibVipArp/VipManager.hpp"

int main() {
    VipManager vip;
    vip.addAddress("eth0", "192.168.1.100/24");  // 动态绑定 VIP
    vip.sendGratuitousArp();                     // 发送即刻的 GARP
    return 0;
}

🛡 安全 & 权限提示

该库涉及底层网络配置和原始套接字操作：

建议在受控环境测试

推荐赋予二进制必要 capabilities（如 CAP_NET_ADMIN）而不是全面 root

生产环境中使用时需谨慎评估安全边界

📚 文档 & 参考

Netlink / RTNETLINK API

ARP RFC 5227

嵌入式网络高可用性场景案例分享

📣 贡献指南

欢迎提出 Issue 或 Pull Request：

修复 Bug 或协议行为

提升测试覆盖

示例和文档增强
