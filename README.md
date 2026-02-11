# LibVipArp

LibVipArp 是一个轻量级、高性能的 C++ 库，面向嵌入式 Linux / 边缘计算场景，用于实现 **虚拟 IP（VIP）管理与 ARP 通告**。  
该项目通过 **Netlink + Gratuitous ARP** 的方式，实现不依赖外部命令（如 `ip`、`arping`）的 VIP 漂移与网络邻居刷新，适合高可用（HA）系统使用。

---

## 项目背景

在高可用或主备切换系统中，虚拟 IP 会在不同节点之间漂移。  
如果仅在本机切换 IP，而未及时通知局域网中的交换机和其他主机，可能会导致：

- ARP 缓存未更新
- 流量仍指向旧节点
- 业务短暂不可达

LibVipArp 通过 **ARP Probe + Gratuitous ARP** 的组合机制，解决上述问题。

---

## 核心特性

- **Netlink 直连内核**
  - 使用 RTNETLINK 接口管理 IP 地址
  - 不依赖 shell 命令，性能和可靠性更高

- **ARP Probe（RFC 5227）**
  - 在绑定 VIP 前进行 IP 冲突检测
  - 防止错误占用网络中已存在的地址

- **Gratuitous ARP 定时通告**
  - 主动刷新交换机和主机的 ARP 表
  - 防止 MAC 表老化导致通信异常

- **现代 C++ 设计**
  - C++17
  - RAII 管理资源
  - 清晰的模块边界，易于嵌入现有工程

---

## 模块结构

LibVipArp
├── VipManager
│ └── 通过 Netlink 添加 / 删除 IP
├── ArpProbe
│ └── ARP 冲突探测（RFC 5227）
├── ArpScheduler
│ └── 后台线程，周期性发送 Gratuitous ARP
└── Netlink / ARP 底层封装

---

## 依赖环境

- Linux（需要 RTNETLINK 支持）
- 支持 C++17 的编译器（gcc 7+ / clang）
- 常见嵌入式 Linux 发行版（Ubuntu / L4T / Yocto 等）

---

## 构建方式

git clone https://github.com/GuoHaiZhe12138/LibVipArp.git
cd LibVipArp
mkdir build && cd build
cmake ..
make -j$(nproc)

## ⚠️ 注意：
该库涉及底层网络操作，运行时通常需要 CAP_NET_ADMIN 权限或 root 权限。
