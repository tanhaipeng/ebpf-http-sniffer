# http-sniff —— 用 eBPF 采集 Linux 上的明文 HTTP 请求

一个**纯 Rust** 的 eBPF 抓包工具：内核态用 TC classifier 把进出指定端口的 TCP
载荷拷进 ring buffer，用户态按连接做 TCP 流重组，再解析出 HTTP/1.x 的**请求和响应**
并打印（文本或 JSON Lines）。

内核态和用户态都是 Rust（aya 0.14 / aya-ebpf 0.2），不需要 clang、libbpf、bpftool，
也不需要 `vmlinux.h`、BTF 或 CO-RE。

---

## 1. 能力与边界

| 能力 | 说明 |
| --- | --- |
| 明文 HTTP/1.x 请求 + 响应 | 两个方向都抓，自动识别请求/响应并推断 client/server |
| 按 TCP 序号重组 | 乱序、重传、重叠、跨包、丢包空洞都能处理（SYN 锚定 + 预热缓冲） |
| HTTP/1.x 语义 | `Content-Length`、`chunked`（含 trailer）、`HEAD`、204/304/1xx、首部折行、LF-only 换行 |
| 输出 | 人类可读多行输出；`--json` 输出 JSON Lines 便于喂给 jq/ELK |
| 统计 | 退出时打印内核侧（包数/命中/丢事件/字节）与用户态（消息/流/重组）计数 |
| 可测试 | 报文解析、HTTP 解析、流重组全部是纯逻辑，**49 个单元测试在任何平台都能跑** |

**边界**：只处理明文 HTTP/1.x。TLS 流量不解密（只做端口过滤），HTTP/2 的二进制帧会被跳过。

---

## 2. 架构

```
                         Linux 内核                                用户态 (Rust)
 ┌────────────────────────────────────────────────┐    ┌───────────────────────────────────┐
 │ TC clsact  Egress + Ingress                    │    │ Ebpf::load → SchedClassifier      │
 │  ├─ parse_packet()  Eth/VLAN → IPv4/IPv6 → TCP │    │  ├─ PORTS map：关注端口（--port）  │
 │  ├─ PORTS map 命中过滤（送入/送出端口）          │    │  ├─ RingBuf + AsyncFd 异步排空     │
 │  ├─ bpf_skb_load_bytes → per-CPU 暂存区        │    │  ├─ FlowTable：按四元组流重组       │
 │  └─ RingBuf::reserve/submit（含 SYN/FIN/RST）  │───▶│  │    └─ Http1Parser：增量解析      │
 └────────────────────────────────────────────────┘    │  └─ 输出：文本 / JSON Lines        │
                                                       └───────────────────────────────────┘
```

### 为什么采集点选 TC，而不是 kprobe/tcp_sendmsg？

- `tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)` 的载荷藏在
  `msg->msg_iter`（`iov_iter`）里，其字段布局随内核版本变化，读它要么依赖 CO-RE/BTF，
  要么写死偏移 —— 前者 aya 支持有限，后者换内核就崩。
- TC classifier 拿到的是**报文本身**。Ethernet / VLAN / IPv4 / IPv6 / TCP 是稳定的
  协议布局，解析它不依赖任何内核内部结构，因此在 5.x～6.x 各版本上都一样工作。
- 代价：拿不到 `pid/comm`（没有进程归属）、需要指定网卡。若需要进程归属，
  可以再加一条 kprobe/uprobe 路径（见第 9 节）。

---

## 3. 环境要求

| 项目 | 要求 |
| --- | --- |
| 内核 | ≥ 5.8（需要 BPF ring buffer）；建议 ≥ 5.10 |
| 权限 | root，或 `CAP_BPF` + `CAP_NET_ADMIN`（挂 TC filter 需要后者） |
| 构建工具链 | **rustup**（apt/yum 装的 rustc 不行）+ nightly + `rust-src`（`rust-toolchain.toml` 已声明，rustup 会自动安装） |
| 链接器 | `bpf-linker`：`cargo install bpf-linker`，或从 [releases](https://github.com/aya-rs/bpf-linker/releases) 下载预编译包解压进 `PATH` |
| 可选 | iproute2 的 `tc`（用于手工删除 clsact qdisc） |

> 已在本机验证：`rustc 1.101.0-nightly` + `bpf-linker 0.11.1`，
> 内核态程序可以完整编译链接成 `EM_BPF` ELF（见第 7 节）。

---

## 4. 构建与运行

```bash
# 1) 工具链（rust-toolchain.toml 会在首次 cargo 调用时自动装 nightly + rust-src）
rustup toolchain install nightly --component rust-src

# 2) BPF 链接器
cargo install bpf-linker            # 或下载预编译包放到 PATH

# 3) 构建：build.rs 会调用 aya-build，在嵌套的 nightly 里把 eBPF 程序编译成
#    bpfel-unknown-none 目标，并把 ELF 内嵌进最终二进制
cargo build --release

# 4) 运行（需要 root；sudo -E 保留环境变量）
sudo -E ./target/release/http-sniff --port 80,8080 --iface all
```

### 命令行参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-p, --port <PORTS>` | `80,8080,8000` | 关注的 TCP 端口，逗号分隔（最多 64 个） |
| `-i, --iface <IFACES>` | `all` | 挂载的网卡，逗号分隔；`all` = `/sys/class/net` 下全部（含 `lo`） |
| `--ebpf-object <PATH>` | 内嵌 | 改用外部 eBPF 目标文件 |
| `--no-headers` | 关 | 不打印首部 |
| `--no-body` | 关 | 不打印 body |
| `--body-limit <BYTES>` | `512` | 每条消息最多打印多少字节 body（超出显示 `… (+N bytes)`） |
| `--json` | 关 | 每行一个 JSON 对象 |
| `--color <auto\|always\|never>` | `auto` | 彩色输出 |
| `-v, --verbose` | 关 | 打印每个抓到的 TCP 段（调试用） |

### 输出示例

```
[15:04:05.123] → GET /api/items?page=2 HTTP/1.1 192.168.1.20:52344 → 10.0.0.5:8080
    Host: 10.0.0.5:8080
    User-Agent: curl/8.5.0
    Accept: */*

[15:04:05.456] ← 200 OK HTTP/1.1 10.0.0.5:8080 → 192.168.1.20:52344
    Content-Type: application/json
    Content-Length: 27
    body: {"items":[],"page":2,"ok":1}
```

`--json` 形态（每行一条）：

```json
{"timestamp":"15:04:05.123","direction":"request","method":"GET","target":"/api/items?page=2",
 "version":"HTTP/1.1","status":null,"reason":null,"client":"192.168.1.20:52344",
 "server":"10.0.0.5:8080","headers":[{"name":"Host","value":"10.0.0.5:8080"}],
 "body":"","body_bytes":0,"body_complete":true,"truncated":false,"skipped_bytes":0}
```

退出时在 **stderr** 打印统计（不污染 `--json` 的 stdout）：

```
── summary ──
  messages   12 requests, 11 responses, 1 without a complete body
  flows      3 tracked, 0 evicted, 0 stream resets
  kernel     2841 packets inspected, 46 segments captured, 0 ring buffer drops, 18342 bytes copied
```

---

## 5. 快速验证（Linux）

```bash
# 终端 1：抓 8000 端口的本机回环流量
sudo -E ./target/release/http-sniff -p 8000 -i lo

# 终端 2：制造明文 HTTP 流量
python3 -m http.server 8000 &
curl -s http://127.0.0.1:8000/ -o /dev/null
curl -s -X POST -d 'hello=world' http://127.0.0.1:8000/api -o /dev/null
curl -s -I http://127.0.0.1:8000/            # HEAD：响应不会等 body
```

应当看到 `GET /`、`POST /api`（body `hello=world`）以及 HEAD 的响应（`body_complete=true`）。

其他有用场景：

```bash
sudo -E ./target/release/http-sniff -p 80,443 -i eth0     # 只抓外网网卡
sudo -E ./target/release/http-sniff --json | jq -c 'select(.direction=="request")'
sudo -E ./target/release/http-sniff -v 2>&1 | head         # 调试：看每个 TCP 段
```

---

## 6. 已知限制

1. **只支持明文 HTTP/1.x**：TLS 不解密；HTTP/2（含 `PRI * HTTP/2.0` 连接前言）会被安全跳过，
   不会破坏连接内后续消息的解析。
2. **IP 分片不重组**（跳过含 MF/offset 的分片）；只处理 TCP，UDP/QUIC 不处理。
3. **单事件载荷上限 1024 字节**（内核 `MAX_PAYLOAD`）。更大的 body 由用户态按序号拼接，
   所以通常仍能拿到完整 body；用户态单条消息 body 上限 4 MiB（`Limits::max_body`）。
4. **没有进程归属**：TC 拿不到 `pid/comm`，只有四元组。需要进程信息请扩展 uprobe/kprobe 路径。
5. **中途接入的流**：抓取从连接中途开始时，第一个消息可能不完整（标记 `[incomplete]`）；
   从 SYN 开始的连接不受影响（SYN 会锚定流起始序号）。
6. **端口上限 64**、ring buffer 1 MiB：高流量下可能丢事件，退出统计里的
   `ring buffer drops` 会显示（丢的是采集事件，不是连接）。

---

## 7. 测试与验证

```bash
# 纯逻辑单元测试（任意平台，包括 macOS/Windows 开发机）
cargo test -p ebpf-http-sniffer-common        # 49 个测试：
                                              #   报文解析 13 个（VLAN/QinQ/IPv6 扩展头/分片/截断）
                                              #   HTTP 解析 17 个（chunked/折行/pipeline/HEAD/上限）
                                              #   流重组   19 个（乱序/重传/重叠/空洞/回绕/SYN/FIN/RST）
# 内核态程序能否编译成 BPF ELF
cargo build --release                          # 在项目内会自动编译 eBPF 并内嵌

# 只想快速做类型检查（没有 bpf-linker 时）
AYA_BUILD_SKIP=1 cargo check                   # 跳过 eBPF 构建（注意：产物不含 eBPF 程序）
```

在 macOS 上开发时，用户态可对 Linux 目标做类型检查：

```bash
rustup target add x86_64-unknown-linux-gnu
cargo check --target x86_64-unknown-linux-gnu
```

**eBPF 程序被 verifier 拒绝时**看内核日志：

```bash
sudo dmesg | tail -30
```

---

## 8. 目录结构

```
ebpf-http-sniffer/
├── Cargo.toml                        # 用户态包 + workspace
├── build.rs                          # 调用 aya-build 编译 eBPF 并内嵌（AYA_BUILD_SKIP 可跳过）
├── rust-toolchain.toml               # nightly + rust-src + rustfmt
├── src/
│   ├── main.rs                       # CLI 入口
│   ├── cli.rs                        # clap 参数
│   ├── capture.rs                    # 加载/挂载 eBPF、排空 ring buffer、统计
│   └── output.rs                     # 文本 / JSON Lines 输出、字节转义、统计打印
├── ebpf-http-sniffer-common/         # 内核态与用户态共享（no_std，可单测）
│   ├── src/lib.rs                    # 事件结构体、方向、TCP 标志、记录解码
│   ├── src/packet.rs                 # Eth/VLAN/IPv4/IPv6/TCP 解析
│   ├── src/http.rs                   # 增量 HTTP/1.x 解析器
│   └── src/flow.rs                   # TCP 流重组 + 连接表
└── ebpf-http-sniffer-ebpf/           # 内核态程序（bpfel-unknown-none）
    ├── .cargo/config.toml            # target = bpfel-unknown-none, -Z build-std=core
    ├── build.rs                      # bpf-linker 存在性检查（缺失时只警告）
    └── src/main.rs                   # TC classifier：解析、过滤、拷贝进 ring buffer
```

### 关键数据结构

- `PacketEvent`（共享）：固定 56 字节头（seq/ack/长度/端口/IPv4v6 地址/方向/TCP 标志）
  + 1024 字节载荷。用户态用一次非对齐读取出头部，载荷按 `captured_len` 切片，避免大对象拷贝。
- 内核 map：`EVENTS`（RingBuf 1 MiB）、`PORTS`（HashMap，端口白名单）、
  `SCRATCH`（PerCpuArray，载荷暂存，绕开 512 字节 BPF 栈限制）、`STATS`（PerCpuArray 计数）。

---

## 9. 扩展点

| 需求 | 做法 |
| --- | --- |
| **HTTPS 明文**（TLS 解密） | 加 `uprobe` 挂 `SSL_write`/`SSL_read`（OpenSSL/BoringSSL）或 GnuTLS，进程过滤用 `--pid`；内核态只拷贝 buf 指针 + len，用户态复用现有 `Http1Parser`/`FlowTable` |
| **进程归属** | 同上路径（uprobe 有 `bpf_get_current_pid_tgid`/`comm`），或在 TC 侧补 cgroup/socket cookie 关联 |
| **HTTP/2** | 在 `Http1Parser` 旁加一个 HTTP/2 帧解析器（9 字节帧头 + HPACK），连接前言可用来识别协议 |
| **落盘 / pcap** | 在 `capture.rs` 的 ring buffer 循环里把 `FlowMessage` 写进 channel，另起任务写 pcap/JSONL 文件 |
| **更多端口/更大载荷** | `ebpf-http-sniffer-ebpf/src/main.rs` 里的 `MAX_PORTS`、`MAX_PAYLOAD`、`RING_SIZE_BYTES` |
| **超时/容量调优** | `FlowConfig`（`ebpf-http-sniffer-common/src/flow.rs`）：`idle_timeout_ms`、`gap_timeout_ms`、`warmup_ms`、`max_flows` |

---

## 10. 故障排查

| 现象 | 原因 / 处理 |
| --- | --- |
| `could not attach to any interface` | 没有 root/CAP_NET_ADMIN；用 `sudo -E` 运行 |
| `the kernel rejected the eBPF program` | verifier 拒绝，`sudo dmesg \| tail` 看具体原因（通常是内核过旧：需要 ≥ 5.8 的 ring buffer） |
| 抓不到 `localhost` 流量 | 加上 `-i lo`（`all` 已包含 `lo`，但若手工指定网卡需显式列出） |
| 抓不到容器间流量 | 把 `veth*`、`docker0`、`br-*` 也加进 `-i`，或直接 `-i all` |
| 什么都抓不到 | 确认端口在 `-p` 里；确认是明文 HTTP（TLS 不可见）；`-v` 看是否有 TCP 段进来 |
| `bpf-linker not found in PATH` | `cargo install bpf-linker` 或下载预编译包（见第 3 节） |
| `build.rs` 报 `AYA_BUILD_SKIP is set` | 之前用 `AYA_BUILD_SKIP=1` 跑过；`unset AYA_BUILD_SKIP` 后重新 `cargo build`（会自动重跑构建脚本） |
| `this binary does not contain the eBPF program` | 二进制是 `AYA_BUILD_SKIP=1` 构建的占位产物，重新完整构建，或用 `--ebpf-object` 指定 ELF |
| 想清理内核里的 TC 规则 | `sudo tc qdisc del dev <iface> clsact`（进程退出时 aya 会摘掉 filter，qdisc 可能保留） |

---

## 11. 设计要点速览

- **内核态只做搬运**：解析、重组、格式化全在用户态，因此核心逻辑可以用普通单测覆盖，
  内核态程序小（约 460 条 BPF 指令）且容易通过 verifier。
- **verifier 友好**：常量大小的拷贝（整块 1 KiB 读进 per-CPU 暂存区再按 `captured_len`
  拷贝）、`min()` 夹取的长度、`u32` 序号回绕安全的距离计算。
- **流重组三件套**：
  1. `SYN` 锚定起始序号（连接从建立就被看到的场景，100% 对齐）；
  2. 无 `SYN` 时"预热"：首个段先缓冲 50 ms 或直到缓冲区里出现可识别的起始行，
     再按序号顺序喂给解析器 —— 这样**首个段乱序**也不会把整条流带偏；
  3. 空洞超时（默认 500 ms）后跳过缺口并把在途消息标记 `[incomplete]`，解析继续。
- **HTTP 解析器可重同步**：抓到流中间也不会卡死，会跳到下一个合法的请求/状态行。
