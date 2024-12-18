# PTES技术指南

本节旨在提供PTES技术指南，以帮助定义在渗透测试期间遵循的某些程序。需要注意的是，这些只是行业中使用的基本方法。它们需要由社区以及您自己的标准不断更新和更改。指南仅仅是推动您在特定场景中采取行动的参考，而不是关于如何执行渗透测试的全面说明。鼓励创新思维。

## 1 工具需求

          `1`在渗透测试期间选择所需工具取决于多种因素，例如测试的类型和深度。通常情况下，以下工具是完成渗透测试并获得预期结果所必需的。

### 1.1 操作系统 (*Operating Systems*)

        在渗透测试中选择操作平台对成功利用网络和相关系统至关重要。因此，有必要同时使用三大主要操作系统。这在没有虚拟化的情况下是不可能的。

#### 1.1.1 MacOS X (*MacOS X*)

        MacOS X 是一个来源于BSD的操作系统。它提供了标准的命令行壳（如 sh、csh 和 bash）以及可用于渗透测试的本地网络工具（包括 telnet、ftp、rpcinfo、snmpwalk、host 和 dig），因此是我们的渗透测试工具的首选基础系统。由于这也是一个硬件平台，这使得特定硬件的选择极其简单，并确保所有工具都能按设计工作。

#### 1.1.2 VMware Workstation (*VMware Workstation*)

        VMware Workstation 是实现工作站上多操作系统实例的绝对必要工具。VMware Workstation 是一个完全支持的商业软件包，提供加密功能和快照功能，而这些在VMware的免费版本中是不可用的。如果无法加密VM上收集的数据，机密信息将面临风险，因此不应使用不支持加密的版本。以下列出的操作系统应作为VMware中的客户系统运行。

##### 1.1.2.1 Linux (*Linux*)

        Linux 是大多数安全顾问的首选。Linux平台具有多功能性，系统内核为尖端技术和协议提供了底层支持。所有主流基于IP的攻击和渗透工具都可以在Linux上无障碍地构建和运行。出于这个原因，BackTrack 成为首选平台，因为它拥有执行渗透测试所需的所有工具。

##### 1.1.2.2 Windows XP/7 (*Windows XP/7*)

        Windows XP/7 是某些工具使用的必要平台。许多商业工具或微软特定的网络评估和渗透工具可以在该平台上顺利运行。

### 1.2 射频工具 (*Radio Frequency Tools*)

#### 1.2.1 频率计数器 (*Frequency Counter*)

#### 1.2.2 频率扫描仪 (*Frequency Scanner*)

#### 1.2.3 频谱分析仪 (*Spectrum Analyzer*)

#### 1.2.4 802.11 USB适配器 (*802.11 USB adapter*)

#### 1.2.5 外置天线 (*External Antennas*)

#### 1.2.6 USB GPS (*USB GPS*)

### 1.3 软件 (*Software*)

## 2 情报收集 (*Intelligence Gathering*)

### 2.1 开源情报 (*OSINT*)

#### 2.1.1 企业 (*Corporate*)

#### 2.1.2 物理 (*Physical*)

##### 2.1.2.1 地点 (*Locations*)

##### 2.1.2.2 共享/个人 (*Shared/Individual*)

##### 2.1.2.3 所有者 (*Owner*)

###### 2.1.2.3.1 土地/税务记录 (*Land/tax records*)

#### 2.1.3 数据中心位置 (*Datacenter Locations*)

##### 2.1.3.1 时区 (*Time zones*)

##### 2.1.3.2 外地收集 (*Offsite gathering*)

##### 2.1.3.3 产品/服务 (*Product/Services*)

##### 2.1.3.4 公司日期 (*Company Dates*)

##### 2.1.3.5 职位识别 (*Position identification*)

##### 2.1.3.6 组织结构图 (*Organizational Chart*)

##### 2.1.3.7 企业通讯 (*Corporate Communications*)

###### 2.1.3.7.1 市场营销 (*Marketing*)

###### 2.1.3.7.2 诉讼 (*Lawsuits*)

###### 2.1.3.7.3 交易 (*Transactions*)

##### 2.1.3.8 职位空缺 (*Job openings*)

#### 2.1.4 关系 (*Relationships*)

##### 2.1.4.1 慈善团体联系 (*Charity Affiliations*)

##### 2.1.4.2 网络服务提供商 (*Network Providers*)

##### 2.1.4.3 商业伙伴 (*Business Partners*)

##### 2.1.4.4 竞争对手 (*Competitors*)

### 2.2 个人 (*Individuals*)

#### 2.2.1 社交网络资料 (*Social Networking Profile*)

#### 2.2.2 社交网络网站 (*Social Networking Websites*)

#### 2.2.3 Cree.py (*Cree.py*)

### 2.3 互联网足迹 (*Internet Footprint*)

#### 2.3.1 电子邮件地址 (*Email addresses*)

##### 2.3.1.1 Maltego (*Maltego*)

##### 2.3.1.2 TheHarvester (*TheHarvester*)

##### 2.3.1.3 NetGlub (*NetGlub*)

#### 2.3.2 用户名/手柄 (*Usernames/Handles*)

#### 2.3.3 社交网络 (*Social Networks*)

##### 2.3.3.1 新闻组 (*Newsgroups*)

##### 2.3.3.2 邮件列表 (*Mailing Lists*)

##### 2.3.3.3 聊天室 (*Chat Rooms*)

##### 2.3.3.4 论坛搜索 (*Forums Search*)

#### 2.3.4 个人域名 (*Personal Domain Names*)

#### 2.3.5 个人活动 (*Personal Activities*)

##### 2.3.5.1 音频 (*Audio*)

##### 2.3.5.2 视频 (*Video*)

#### 2.3.6 存档信息 (*Archived Information*)

#### 2.3.7 电子数据 (*Electronic Data*)

##### 2.3.7.1 文档泄漏 (*Document leakage*)

##### 2.3.7.2 元数据泄漏 (*Metadata leakage*)

###### 2.3.7.2.1 FOCA (Windows) (*FOCA (Windows)*)

###### 2.3.7.2.2 Foundstone SiteDigger (Windows) (*Foundstone SiteDigger (Windows)*)

###### 2.3.7.2.3 Metagoofil (Linux/Windows) (*Metagoofil (Linux/Windows)*)

###### 2.3.7.2.4 Exif Reader (Windows) (*Exif Reader (Windows)*)

###### 2.3.7.2.5 ExifTool (Windows/OS X) (*ExifTool (Windows/OS X)*)

###### 2.3.7.2.6 图片搜索 (*Image Search*)

### 2.4 隐蔽收集 (*Covert gathering*)

#### 2.4.1 现场收集 (*On-location gathering*)

##### 2.4.1.1 邻近设施 (*Adjacent Facilities*)

##### 2.4.1.2 物理安全检查 (*Physical security inspections*)

###### 2.4.1.2.1 安保人员 (*Security guards*)

###### 2.4.1.2.2 徽章使用 (*Badge Usage*)

###### 2.4.1.2.3 锁定装置 (*Locking devices*)

###### 2.4.1.2.4 入侵检测系统 (IDS)/警报 (*Intrusion detection systems (IDS)/Alarms*)

###### 2.4.1.2.5 安全照明 (*Security lighting*)

###### 2.4.1.2.6 监控/CCTV系统 (*Surveillance /CCTV systems*)

###### 2.4.1.2.7 访问控制设备 (*Access control devices*)

###### 2.4.1.2.8 环境设计 (*Environmental Design*)

##### 2.4.1.3 员工行为 (*Employee Behavior*)

##### 2.4.1.4 垃圾潜水 (*Dumpster diving*)

##### 2.4.1.5 射频/无线频率扫描 (*RF / Wireless Frequency scanning*)

#### 2.4.2 频率使用 (*Frequency Usage*)

#### 2.4.3 设备识别 (*Equipment Identification*)

##### 2.4.3.1 Airmon-ng (*Airmon-ng*)

##### 2.4.3.2 Airodump-ng (*Airodump-ng*)

##### 2.4.3.3 Kismet-Newcore (*Kismet-Newcore*)

##### 2.4.3.4 inSSIDer (*inSSIDer*)

### 2.5 外部足迹 (*External Footprinting*)

#### 2.5.1 识别IP范围 (*Identifying IP Ranges*)

##### 2.5.1.1 WHOIS查询 (*WHOIS lookup*)

##### 2.5.1.2 BGP观察镜 (*BGP looking glasses*)

#### 2.5.2 主动侦察 (*Active Reconnaissance*)

#### 2.5.3 被动侦察 (*Passive Reconnaissance*)

#### 2.5.4 主动足迹 (*Active Footprinting*)

##### 2.5.4.1 区域传输 (*Zone Transfers*)

###### 2.5.4.1.1 Host (*Host*)

###### 2.5.4.1.2 Dig (*Dig*)

##### 2.5.4.2 反向DNS (*Reverse DNS*)

##### 2.5.4.3 DNS 暴力破解 (*DNS Bruting*)

###### 2.5.4.3.1 Fierce2 (Linux) (*Fierce2 (Linux)*)

###### 2.5.4.3.2 DNSEnum (Linux) (*DNSEnum (Linux)*)

###### 2.5.4.3.3 Dnsdict6 (Linux) (*Dnsdict6 (Linux)*)

##### 2.5.4.4 端口扫描 (*Port Scanning*)

###### 2.5.4.4.1 Nmap (Windows/Linux) (*Nmap (Windows/Linux)*)

##### 2.5.4.5 SNMP 扫描 (*SNMP Sweeps*)

###### 2.5.4.5.1 SNMPEnum (Linux) (*SNMPEnum (Linux)*)

##### 2.5.4.6 SMTP 回传 (*SMTP Bounce Back*)

##### 2.5.4.7 横幅获取 (*Banner Grabbing*)

###### 2.5.4.7.1 HTTP (*HTTP*)

### 2.6 内部足迹 (*Internal Footprinting*)

#### 2.6.1 主动足迹 (*Active Footprinting*)

##### 2.6.1.1 Ping 扫描 (*Ping Sweeps*)

###### 2.6.1.1.1 Nmap (Windows/Linux) (*Nmap (Windows/Linux)*)

###### 2.6.1.1.2 Alive6 (Linux) (*Alive6 (Linux)*)

##### 2.6.1.2 端口扫描 (*Port Scanning*)

###### 2.6.1.2.1 Nmap (Windows/Linux) (*Nmap (Windows/Linux)*)

##### 2.6.1.3 SNMP 扫描 (*SNMP Sweeps*)

###### 2.6.1.3.1 SNMPEnum (Linux) (*SNMPEnum (Linux)*)

##### 2.6.1.4 Metasploit (*Metasploit*)

##### 2.6.1.5 区域传输 (*Zone Transfers*)

###### 2.6.1.5.1 Host (*Host*)

###### 2.6.1.5.2 Dig (*Dig*)

##### 2.6.1.6 SMTP 回传 (*SMTP Bounce Back*)

##### 2.6.1.7 反向DNS (*Reverse DNS*)

##### 2.6.1.8 横幅获取 (*Banner Grabbing*)

###### 2.6.1.8.1 HTTP (*HTTP*)

###### 2.6.1.8.2 httprint (*httprint*)

##### 2.6.1.9 VoIP 映射 (*VoIP mapping*)

###### 2.6.1.9.1 扩展 (*Extensions*)

###### 2.6.1.9.2 Svwar (*Svwar*)

###### 2.6.1.9.3 enumIAX (*enumIAX*)

##### 2.6.1.10 被动侦察 (*Passive Reconnaissance*)

###### 2.6.1.10.1 数据包抓取 (*Packet Sniffing*)

## 3 漏洞分析 (*Vulnerability Analysis*)

### 3.1 漏洞测试 (*Vulnerability Testing*)

#### 3.1.1 主动 (*Active*)

#### 3.1.2 自动化工具 (*Automated Tools*)

##### 3.1.2.1 网络/通用漏洞扫描器 (*Network/General Vulnerability Scanners*)

##### 3.1.2.2 开放漏洞评估系统 (OpenVAS) (*Open Vulnerability Assessment System (OpenVAS) (Linux)*)

##### 3.1.2.3 Nessus (Windows/Linux) (*Nessus (Windows/Linux)*)

##### 3.1.2.4 NeXpose (*NeXpose*)

##### 3.1.2.5 eEYE Retina (*eEYE Retina*)

##### 3.1.2.6 Qualys (*Qualys*)

##### 3.1.2.7 Core IMPACT (*Core IMPACT*)

###### 3.1.2.7.1 Core IMPACT Web (*Core IMPACT Web*)

###### 3.1.2.7.2 Core IMPACT WiFi (*Core IMPACT WiFi*)

###### 3.1.2.7.3 Core IMPACT 客户端 (*Core IMPACT Client Side*)

###### 3.1.2.7.4 Core Web (*Core Web*)

###### 3.1.2.7.5 coreWEBcrawl (*coreWEBcrawl*)

###### 3.1.2.7.6 Core Onestep Web RPTs (*Core Onestep Web RPTs*)

###### 3.1.2.7.7 Core WiFi (*Core WiFi*)

##### 3.1.2.8 SAINT (*SAINT*)

###### 3.1.2.8.1 SAINTscanner (*SAINTscanner*)

###### 3.1.2.8.2 SAINTexploit (*SAINTexploit*)

###### 3.1.2.8.3 SAINTwriter (*SAINTwriter*)

#### 3.1.3 Web应用扫描器 (*Web Application Scanners*)

##### 3.1.3.1 通用Web应用扫描器 (*General Web Application Scanners*)

###### 3.1.3.1.1 WebInspect (Windows) (*WebInspect (Windows)*)

###### 3.1.3.1.2 IBM AppScan (*IBM AppScan*)

###### 3.1.3.1.3 Web目录列表/暴力破解 (*Web Directory Listing/Bruteforcing*)

###### 3.1.3.1.4 Web服务器版本/漏洞识别 (*Webserver Version/Vulnerability Identification*)

##### 3.1.3.2 NetSparker (Windows) (*NetSparker (Windows)*)

##### 3.1.3.3 专用漏洞扫描器 (*Specialized Vulnerability Scanners*)

###### 3.1.3.3.1 虚拟专用网络 (VPN) (*Virtual Private Networking (VPN)*)

###### 3.1.3.3.2 IPv6 (*IPv6*)

###### 3.1.3.3.3 战拨 (*War Dialing*)

#### 3.1.4 被动测试 (*Passive Testing*)

##### 3.1.4.1 自动化工具 (*Automated Tools*)

###### 3.1.4.1.1 流量监控 (*Traffic Monitoring*)

##### 3.1.4.2 Wireshark (*Wireshark*)

##### 3.1.4.3 Tcpdump (*Tcpdump*)

##### 3.1.4.4 Metasploit 扫描器 (*Metasploit Scanners*)

###### 3.1.4.4.1 Metasploit Unleashed (*Metasploit Unleashed*)

### 3.2 漏洞验证 (*Vulnerability Validation*)

#### 3.2.1 公开研究 (*Public Research*)

##### 3.2.1.1 常见/默认密码 (*Common/default passwords*)

#### 3.2.2 建立目标列表 (*Establish target list*)

##### 3.2.2.1 映射版本 (*Mapping Versions*)

##### 3.2.2.2 识别补丁级别 (*Identifying Patch Levels*)

##### 3.2.2.3 寻找弱Web应用 (*Looking for Weak Web Applications*)

##### 3.2.2.4 识别弱端口和服务 (*Identify Weak Ports and Services*)

##### 3.2.2.5 识别锁定阈值 (*Identify Lockout threshold*)

### 3.3 攻击途径 (*Attack Avenues*)

#### 3.3.1 创建攻击树 (*Creation of Attack Trees*)

#### 3.3.2 识别保护机制 (*Identify protection mechanisms*)

##### 3.3.2.1 网络保护 (*Network protections*)

###### 3.3.2.1.1 "简单"数据包过滤器 (*"Simple" Packet Filters*)

###### 3.3.2.1.2 流量整形设备 (*Traffic shaping devices*)

###### 3.3.2.1.3 数据丢失防护 (DLP) 系统 (*Data Loss Prevention (DLP) systems*)

##### 3.3.2.2 主机保护 (*Host based protections*)

###### 3.3.2.2.1 栈/堆保护 (*Stack/heap protections*)

###### 3.3.2.2.2 白名单 (*Whitelisting*)

###### 3.3.2.2.3 AV/过滤/行为分析 (*AV/Filtering/Behavioral Analysis*)

##### 3.3.2.3 应用级保护 (*Application level protections*)

## 4 利用 (*Exploitation*)

### 4.1 精确打击 (*Precision strike*)

#### 4.1.1 对策绕过 (*Countermeasure Bypass*)

##### 4.1.1.1 AV (*AV*)

##### 4.1.1.2 人力 (*Human*)

##### 4.1.1.3 HIPS (*HIPS*)

##### 4.1.1.4 DEP (*DEP*)

##### 4.1.1.5 ASLR (*ASLR*)

##### 4.1.1.6 VA + NX (Linux) (*VA + NX (Linux)*)

##### 4.1.1.7 w^x (OpenBSD) (*w^x (OpenBSD)*)

##### 4.1.1.8 WAF (*WAF*)

##### 4.1.1.9 栈金丝雀 (*Stack Canaries*)

###### 4.1.1.9.1 Microsoft Windows (*Microsoft Windows*)

###### 4.1.1.9.2 Linux (*Linux*)

###### 4.1.1.9.3 MAC OS (*MAC OS*)

### 4.2 定制化利用 (*Customized Exploitation*)

#### 4.2.1 模糊测试 (*Fuzzing*)

#### 4.2.2 哑模糊测试 (*Dumb Fuzzing*)

#### 4.2.3 智能模糊测试 (*Intelligent Fuzzing*)

#### 4.2.4 嗅探 (*Sniffing*)

##### 4.2.4.1 Wireshark (*Wireshark*)

##### 4.2.4.2 Tcpdump (*Tcpdump*)

#### 4.2.5 暴力破解 (*Brute-Force*)

##### 4.2.5.1 Brutus (Windows) (*Brutus (Windows)*)

##### 4.2.5.2 Web Brute (Windows) (*Web Brute (Windows)*)

##### 4.2.5.3 THC-Hydra/XHydra (*THC-Hydra/XHydra*)

##### 4.2.5.4 Medusa (*Medusa*)

##### 4.2.5.5 Ncrack (*Ncrack*)

#### 4.2.6 路由协议 (*Routing protocols*)

#### 4.2.7 Cisco发现协议 (CDP) (*Cisco Discovery Protocol (CDP)*)

#### 4.2.8 热备份路由协议 (HSRP) (*Hot Standby Router Protocol (HSRP)*)

#### 4.2.9 虚拟交换机冗余协议 (VSRP) (*Virtual Switch Redundancy Protocol (VSRP)*)

#### 4.2.10 动态中继协议 (DTP) (*Dynamic Trunking Protocol (DTP)*)

#### 4.2.11 生成树协议 (STP) (*Spanning Tree Protocol (STP)*)

#### 4.2.12 开放最短路径优先 (OSPF) (*Open Shortest Path First (OSPF)*)

#### 4.2.13 RIP (*RIP*)

#### 4.2.14 VLAN跳跃 (*VLAN Hopping*)

#### 4.2.15 VLAN中继协议 (VTP) (*VLAN Trunking Protocol (VTP)*)

### 4.3 射频访问 (*RF Access*)

#### 4.3.1 未加密的无线局域网 (*Unencrypted Wireless LAN*)

##### 4.3.1.1 Iwconfig (Linux) (*Iwconfig (Linux)*)

##### 4.3.1.2 Windows (XP/7) (*Windows (XP/7)*)

#### 4.3.2 攻击接入点 (*Attacking the Access Point*)

##### 4.3.2.1 拒绝服务 (DoS) (*Denial of Service (DoS)*)

#### 4.3.3 破解密码 (*Cracking Passwords*)

##### 4.3.3.1 WPA-PSK/WPA2-PSK (*WPA-PSK/ WPA2-PSK*)

##### 4.3.3.2 WPA/WPA2-Enterprise (*WPA/WPA2-Enterprise*)

#### 4.3.4 攻击 (*Attacks*)

##### 4.3.4.1 LEAP (*LEAP*)

###### 4.3.4.1.1 Asleap (*Asleap*)

##### 4.3.4.2 802.1X (*802.1X*)

###### 4.3.4.2.1 密钥分发攻击 (*Key Distribution Attack*)

###### 4.3.4.2.2 RADIUS伪装攻击 (*RADIUS Impersonation Attack*)

##### 4.3.4.3 PEAP (*PEAP*)

###### 4.3.4.3.1 RADIUS伪装攻击 (*RADIUS Impersonation Attack*)

###### 4.3.4.3.2 认证攻击 (*Authentication Attack*)

##### 4.3.4.4 EAP-Fast (*EAP-Fast*)

##### 4.3.4.5 WEP/WPA/WPA2 (*WEP/WPA/WPA2*)

##### 4.3.4.6 Aircrack-ng (*Aircrack-ng*)

### 4.4 攻击用户 (*Attacking the User*)

#### 4.4.1 Karmetasploit攻击 (*Karmetasploit Attacks*)

#### 4.4.2 DNS请求 (*DNS Requests*)

#### 4.4.3 蓝牙 (*Bluetooth*)

#### 4.4.4 个性化流氓AP (*Personalized Rogue AP*)

#### 4.4.5 Web (*Web*)

##### 4.4.5.1 SQL注入 (SQLi) (*SQL Injection (SQLi)*)

##### 4.4.5.2 跨站脚本 (XSS) (*XSS*)

##### 4.4.5.3 跨站请求伪造 (CSRF) (*CSRF*)

#### 4.4.6 自组网络 (*Ad-Hoc Networks*)

#### 4.4.7 检测绕过 (*Detection bypass*)

#### 4.4.8 控制抵抗攻击 (*Resistance of Controls to attacks*)

#### 4.4.9 攻击类型 (*Type of Attack*)

#### 4.4.10 社会工程工具包 (*The Social-Engineer Toolkit*)

### 4.5 VPN检测 (*VPN detection*)

### 4.6 路由检测，包括静态路由 (*Route detection, including static routes*)

#### 4.6.1 使用的网络协议 (*Network Protocols in use*)

#### 4.6.2 使用的代理 (*Proxies in use*)

#### 4.6.3 网络布局 (*Network layout*)

#### 4.6.4 高价值/高调目标 (*High value/profile targets*)

### 4.7 掠夺 (*Pillaging*)

#### 4.7.1 摄像头 (*Video Cameras*)

#### 4.7.2 数据外传 (*Data Exfiltration*)

#### 4.7.3 共享定位 (*Locating Shares*)

#### 4.7.4 音频捕获 (*Audio Capture*)

#### 4.7.5 高价值文件 (*High Value Files*)

#### 4.7.6 数据库枚举 (*Database Enumeration*)

#### 4.7.7 无线网络 (*Wifi*)

#### 4.7.8 源代码仓库 (*Source Code Repos*)

#### 4.7.9 Git (*Git*)

#### 4.7.10 识别自定义应用程序 (*Identify custom apps*)

#### 4.7.11 备份 (*Backups*)

### 4.8 业务影响攻击 (*Business impact attacks*)

### 4.9 进一步渗透到基础设施 (*Further penetration into infrastructure*)

#### 4.9.1 内部枢纽 (*Pivoting inside*)

##### 4.9.1.1 历史/日志 (*History/Logs*)

#### 4.9.2 清理 (*Cleanup*)

### 4.10 持久性 (*Persistence*)

## 5 后期利用 (*Post Exploitation*)

### 5.1 Windows后期利用 (*Windows Post Exploitation*)

#### 5.1.1 盲文件 (*Blind Files*)

#### 5.1.2 非交互式命令执行 (*Non Interactive Command Execution*)

#### 5.1.3 系统 (*System*)

#### 5.1.4 网络 (ipconfig, netstat, net) (*Networking (ipconfig, netstat, net)*)

#### 5.1.5 配置 (*Configs*)

#### 5.1.6 寻找重要文件 (*Finding Important Files*)

#### 5.1.7 提取文件（如果可能） (*Files To Pull (if possible)*)

#### 5.1.8 远程系统访问 (*Remote System Access*)

#### 5.1.9 自动启动目录 (*Auto-Start Directories*)

#### 5.1.10 二进制植入 (*Binary Planting*)

#### 5.1.11 删除日志 (*Deleting Logs*)

#### 5.1.12 卸载软件“防病毒”（非交互式） (*Uninstalling Software “AntiVirus” (Non interactive)*)

#### 5.1.13 其他 (*Other*)

##### 5.1.13.1 操作特定 (*Operating Specific*)

###### 5.1.13.1.1 Win2k3 (*Win2k3*)

###### 5.1.13.1.2 Vista/7 (*Vista/7*)

###### 5.1.13.1.3 Vista SP1/7/2008/2008R2 (x86 & x64) (*Vista SP1/7/2008/2008R2 (x86 & x64)*)

#### 5.1.14 侵入或更改命令 (*Invasive or Altering Commands*)

#### 5.1.15 支持工具二进制/链接/使用 (*Support Tools Binaries / Links / Usage*)

##### 5.1.15.1 各种工具 (*Various tools*)

### 5.2 获取Windows中的密码哈希 (*Obtaining Password Hashes in Windows*)

#### 5.2.1 LSASS注入 (*LSASS Injection*)

##### 5.2.1.1 Pwdump6和Fgdump (*Pwdump6 and Fgdump*)

##### 5.2.1.2 Hashdump在Meterpreter中 (*Hashdump in Meterpreter*)

#### 5.2.2 从注册表中提取密码 (*Extracting Passwords from Registry*)

##### 5.2.2.1 从注册表中复制 (*Copy from the Registry*)

##### 5.2.2.2 提取哈希 (*Extracting the Hashes*)

#### 5.2.3 使用Meterpreter从注册表中提取密码 (*Extracting Passwords from Registry using Meterpreter*)

## 6 报告 (*Reporting*)

### 6.1 高管级报告 (*Executive-Level Reporting*)

### 6.2 技术报告 (*Technical Reporting*)

### 6.3 风险量化 (*Quantifying the risk*)

### 6.4 可交付成果 (*Deliverable*)

## 7 自制工具开发 (*Custom tools developed*)

## 8 附录A - 创建OpenVAS“仅安全检查”策略 (*Appendix A - Creating OpenVAS "Only Safe Checks" Policy*)

### 8.1 常规 (*General*)

### 8.2 插件 (*Plugins*)

### 8.3 凭证 (*Credentials*)

### 8.4 目标选择 (*Target Selection*)

### 8.5 访问规则 (*Access Rules*)

### 8.6 偏好 (*Preferences*)

### 8.7 知识库 (*Knowledge Base*)

## 9 附录B - 创建“仅安全检查”策略 (*Appendix B - Creating the "Only Safe Checks" Policy*)

### 9.1 常规 (*General*)

### 9.2 凭证 (*Credentials*)

### 9.3 插件 (*Plugins*)

### 9.4 偏好 (*Preferences*)

## 10 附录C - 创建“仅安全检查(Web)”策略 (*Appendix C - Creating the "Only Safe Checks (Web)" Policy*)

### 10.1 常规 (*General*)

### 10.2 凭证 (*Credentials*)

### 10.3 插件 (*Plugins*)

### 10.4 偏好 (*Preferences*)

## 11 附录D - 创建“验证扫描”策略 (*Appendix D - Creating the "Validation Scan" Policy*)

### 11.1 常规 (*General*)

### 11.2 凭证 (*Credentials*)

### 11.3 插件 (*Plugins*)

### 11.4 偏好 (*Preferences*)

## 12 附录E - NeXpose默认模板 (*Appendix E - NeXpose Default Templates*)

### 12.1 拒绝服务 (*Denial of service*)

### 12.2 探索扫描 (*Discovery scan*)

### 12.3 探索扫描（激进） (*Discovery scan (aggressive)*)

### 12.4 详尽 (*Exhaustive*)

### 12.5 全面审计 (*Full audit*)

### 12.6 HIPAA合规 (*HIPAA compliance*)

### 12.7 互联网DMZ审计 (*Internet DMZ audit*)

### 12.8 Linux RPMs (*Linux RPMs*)

### 12.9 Microsoft补丁 (*Microsoft hotfix*)

### 12.10 支付卡行业 (PCI) 审计 (*Payment Card Industry (PCI) audit*)

### 12.11 渗透测试 (*Penetration test*)

### 12.12 渗透测试 (*Penetration test*)

### 12.13 安全网络审计 (*Safe network audit*)

### 12.14 萨班斯-奥克斯利 (SOX) 合规 (*Sarbanes-Oxley (SOX) compliance*)

### 12.15 SCADA审计 (*SCADA audit*)

### 12.16 Web审计 (*Web audit*)
