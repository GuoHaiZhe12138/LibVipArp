##LibVipArp 
LibVipArp 是一个轻量级、高性能的 C++ 工具库，专为嵌入式 Linux 设备（如 NVIDIA Jetson）设计。它集成了 IP 地址动态绑定 (Netlink) 和 免费 ARP (Gratuitous ARP) 宣告 功能，确保在 HA（高可用）场景下，VIP (Virtual IP) 的漂移能够被局域网设备即时感知。

✨ 核心特性
协议标准：严格遵循 RFC 5227 规范，在绑定 IP 前执行 ARP Probe 探测，防止 IP 冲突。

高性能：直接使用 Linux Netlink (RTNETLINK) 套接字管理地址，无需调用系统 ip 命令，毫秒级响应。

可靠性：内置 ArpScheduler 异步线程，支持用户自定义周期的周期性 ARP 宣告，防止交换机 MAC 表老化导致 VIP 失效。

现代化 C++：基于 C++17 开发，采用 RAII 模式管理资源与线程生命周期。

🛠 技术架构
该库主要由三个核心模块组成：

VipManager: 负责与内核通信，通过 Netlink 增删 IP 地址。

ArpProbe: 在地址上线前，发送探测报文检测局域网内是否存在冲突。

ArpScheduler: 维护一个后台线程，负责周期性发送 Gratuitous ARP 报文。

🚀 快速开始
环境依赖
Linux 系统（推荐 Jetson L4T 或 Ubuntu）

支持 C++17 的编译器 (GCC 7+)

编译
基本用法
⚠️ 安全说明 (Security)
由于该工具涉及底层网络操作，运行编译后的程序通常需要 root 权限。为了安全起见，建议在生产环境下仅授予可执行文件必要的 Capabilities