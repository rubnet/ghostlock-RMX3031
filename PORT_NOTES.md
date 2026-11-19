# GhostLock 移植到 RMX3031（realme GT Neo / MT6893）— stage1

## 来源与方法

参考实现来自同内核世代的姊妹机 RMX1991（realme X2 / SM6150，`4.14.180-perf+`），
其完整技术账证明：pselect fd_set 路线在本机结构性不可用（SHIFT=16 超出窗口上限），
**可行路线是 32 位 `compat_get_timex` + 跨页 `-EFAULT` reclaim → 任意内核读写**。

我在上个会话独立得出的结论与之一致（pselect 是死路、`do_adjtimex` 覆盖假 waiter），
但缺少「跨页 utp 让 `compat_get_timex` 返回 -EFAULT 从而跳过 `do_adjtimex`」这个关键修补。
本目录是把该已验证实现移植到 RMX3031 的结果。

**所有设备相关偏移均由 `vmlinux.elf`（与设备实测内核逐字一致，
即 `boot.bin`）反汇编 + `.rela.dyn` 重定位表实测得出，
没有照抄参考机的数字。**

## 可行性：栈几何逐条反汇编确认（决定性）

| 项 | 参考机 | RMX3031 实测 | 证据 |
|---|---|---|---|
| `compat_SyS_adjtimex` 帧 | 0x100 | **0x100** | `sub sp,sp,#256` |
| `compat_get_timex` 帧 | 0xb0 | **0xb0** | `sub sp,sp,#176` |
| 缓冲 `tx32` @ `sp+8` → 深度 | 0x1a8 | **0x1a8** | `add x0,sp,#8` |
| `compat_get_timex` 故障返回 | -EFAULT | **-14** | `mov w0,#-14` + 故障路径只补零未拷贝尾部 |
| 调用者 `-EFAULT` 跳过 do_adjtimex | `cbnz w0` | **`cbnz w0`** | `0x8157f88: cbnz w0, ...+0x50` |
| `do_futex` 两段帧 | 0x60+0x1a0 | 0x60+0x1c0 | — |
| `&rt_waiter = x29-0xc0` 深度 | 0x190 | **0x190** | `sub x0/x24,x29,#192`，x29=T-0xd0 |
| `waiter_off`（缓冲内） | 0x18 | **0x18** | 0x1a8-0x190 |
| `rt_mutex_waiter` 大小/字段 | 0x50 | **0x50** | task@0x30 lock@0x38 prio@0x40 deadline@0x48 |
| `configfs_buffer` 字段 | 0x20/0x50/0x58 | **一致** | mutex@0x20 bin_buffer@0x50 size@0x58 |
| `file_operations` 槽位 | 0x10/0x18/0x48/0x50/0x58/0x60/0x68/0x70 | **一致** | filp_close: `[filp+0x28]+0x68` |
| `task->files` | 0x840 | **0x800** | `exit_files: ldr x19,[x0,#2048]` |

⇒ **reclaim 几何与全部关键结构布局完全一致**，只有「地址常量」和「task_struct 字段偏移」需要改。

## 前提（真机实测全部满足）

```
内核       4.14.186+ (clang 11.0.1)  —— 与 vmlinux.elf 逐字一致
CONFIG_COMPAT=y / ARM64_PAN=y / VMAP_STACK=y / PERF_EVENTS=y / HAVE_PERF_REGS=y
CONFIG_MODULE_SIG=y / MODULE_SIG_FORCE=y / SYSTEM_TRUSTED_KEYS=""
perf_event_paranoid = -1        —— perf 泄露 KASLR slide + 内核栈 T 可用
/dev/ashmem = crw-rw-rw-        —— fops 劫持 + 共享内存可用
ABI: arm64-v8a, armeabi-v7a, armeabi  —— 32 位 helper 可运行
oplus_root_check / is_unlocked 存在 —— 反 root 防护，用 g_boot_state=1 绕过
VA_BITS=39
```

## 偏移替换表（全部实测）

BASE = `0xffffff8008080000`；下表是写入 stage1.c 的 `off = VA - BASE`。

| define | RMX1991(参考) | **RMX3031(本次)** | 来源 |
|---|---|---|---|
| OFF_EL0_SYNC | 0x3500 | **0x36c0** | symtab el0_sync |
| OFF_RET_TO_USER | 0x3b94 | **0x3e34** | symtab ret_to_user |
| OFF_EL0_SVC | 0x3c80 | **0x3f80** | symtab el0_svc |
| OFF_INET6_PROTOS | 0x239b630 | **0x1e49b80** | inet6_add_protocol: adrp #2944 |
| OFF_INIT_TASK | 0x239cf00 | **0x1e4c000** | start_kernel（OFFSETS_RMX3031.md） |
| OFF_SYSCTL_PERF_PARANOID | 0x238e63c | **0x1e3e17c** | ctl_table procname→data |
| OFF_SYSCTL_NET_BUSY_READ | 0x2390dc8 | **0x1e3fc48** | ctl_table busy_read→data（busy_poll @+4=0） |
| OFF_BUSY_READ_CTL_ENTRY | 0x2677968 | **0x02087660**（⚠️ 曾误写 0x02067660，差 0x20000，导致任意读全 0；2026-11-18 修正） | busy_read ctl_table 条目 @VA 0xffffff800a107660 |
| OFF_ASHEMEM_FOPS | 0x183c0d0 | **0x13c2c38** | .rela.dyn: open/ioctl/mmap/release 簇 |
| OFF_ASHEMEM_LLSEEK | 0xcc7ae0 | **0x1fa6dc** | symtab noop_llseek |
| OFF_G_BOOT_STATE | 0x1d9e278 | **0x17bc458** | is_unlocked: adrp +1112 |
| OFF_SELINUX_STATE | 0x27e09b0 | **0x231d4f8** | selinux_task_alloc |
| OFF_COMPAT_SYS_ADJTIMEX | 0x0dde40 | **0x0d7f5c** | symtab（长 0x7c） |
| OFF_COMPAT_GET_TIMEX | 0x1067b8 | **0x1020f8** | symtab（长 0x1a0） |
| OFF_COMPAT_PUT_TIMEX | 0x106900 | **0x1022a0** | symtab |
| OFF_ASHEMEM_MISC_FOPS | 0x26417c8 | **0x2063ef8** | ashmem_misc+0x10（misc_register 参数） |
| OFF_ASHEMEM_OPEN/IOCTL/COMPAT_IOCTL/MMAP/RELEASE | 0xcc86d0/... | **0xd7e864 / 0xd7ddd4 / 0xd7e6b0 / 0xd7e6fc / 0xd7e8e4** | symtab |
| OFF_CONFIGFS_READ/WRITE_BIN_FILE | 0x2acf80 / 0x2ad100 | **0x2a3630 / 0x2a37b0** | symtab |
| TASK_TASKS_OFF | 0x550 | **0x510** | show_state_filter |
| TASK_REAL_CRED_OFF | 0x7f8 | **0x7d0** | commit_creds |
| TASK_CRED_OFF | 0x800 | **0x7d8** | commit_creds |
| TASK_COMM_OFF | 0x808 | **0x7e0** | __get_task_comm |
| TASK_FILES_OFF | 0x840 | **0x800** | exit_files |
| TASK_PI_LOCK_OFF | 0x8dc | **0x8a4** | rt_mutex_adjust_prio_chain |
| TASK_PI_BLOCKED_ON_OFF | 0x900 | **0x8c8** | 同上 |
| OFF_BUILTIN_TRUSTED_KEYS | 0x270bdc8 | **0x2233890** | system_trusted_keyring_init: str [x8,#2192] |
| OFF_KIMAGE_VOFFSET / OFF_MEMSTART_ADDR | — | **0（仅 alias-probe 用，已禁用）** | 可选路径 |

未改（GEOMETRY / 通用结构偏移，反汇编确认一致）：
`WAITER_OFF=0x18`、`DEPTH_RT_WAITER=0x190`、`ENTRY_DELTA=0x140`、
`FRAME_COMPAT_ADJTIMEX=0x100`、`FRAME_COMPAT_GET_TIMEX=0x1b0`、
`CFG_MUTEX_OFF=0x20`、`CFG_BIN_BUFFER_OFF=0x50`、`CFG_BIN_BUFFER_SIZE_OFF=0x58`、
`CRED_SECURITY_OFF=0x78`、`CRED_CAP_EFF_OFF=0x38`、`PAGE_OFFSET_39`。

> 注意：`TASK_*` 全部相差 +0x48（MTK/WALT 在 task_struct 早期插入字段），
> 这正是照抄参考机数字会失败的地方，已逐项修正。

## 构建

```
$CC = <NDK r25c>/toolchains/llvm/prebuilt/windows-x86_64/bin/armv7a-linux-androideabi30-clang
$CC -O2 -Wall -fPIE -pie -o stage1 stage1.c
```
产物：`stage1`（ELF 32-bit ARM / E_TYPE=DYN/PIE，98,920 B，MD5 `826c81f5...`）。
**必须是 32 位**：reclaim 依赖 compat 路径（`compat_get_timex` 的 `tx32` 是唯一落在
waiter 深度窗口内的逐字节直拷缓冲）。

## 测试进度 / 下一步

- [x] 反汇编核对栈几何与结构布局
- [x] 提取并替换全部偏移
- [x] 32 位编译成功
- [x] **推送设备 + `--leak-only` 零风险验证通过（2026-11-18）**：
  - KASLR slide 用自有 `ghostlock_standalone` 的 perf 泄露得到 `0x30a200000`（连续两次一致），
    base=`ffffff8312280000`。stage1 内置 slide 投票器太弱（cands=0）已放弃，一律显式 `--slide`。
  - `stage1 --leak-only --slide 0x30a200000` 关键输出：
    - `FUTEX_CMP_REQUEUE_PI -> -1 errno=35` ⇒ EDEADLK 死锁路径命中，悬垂 `pi_blocked_on` 造出 ✅
    - 跨页 utp ⇒ `adjtimex -> -1 errno=14` 连续 260 万次 ⇒ `-EFAULT` 跳过 do_adjtimex ✅
    - perf 栈泄露 `T=0xffffff802b5bbec0`、`R=&rt_waiter=0xffffff802b5bbd30`、缓冲基址 `0x...bd18`
    - **函数交叉校验 155/158**（我替换的 `compat_get_timex@0x1020f8`/`el0_svc@0x3f80` 等偏移正确）
    - 样本 `pc_off=0x3f94`（`el0_svc_naked+8`）、`pc_off=0x10214c`（compat_get_timex 体内）与替换值精确吻合
    - `top-sp=0x140` 与 ENTRY_DELTA 一致 ⇒ 栈几何真机确认
  - 全程设备存活（uptime 未重置）⇒ 零风险模式行为符合预期
- [x] `--aw-busy`（erase 原语 oracle，2026-11-18 首次）→ 如参考所述 BUG 重启；
      erase 变体本就会 `BUG_ON`，非移植失败。日志抓取工具已修（`run_live.ps1` 用 `adb shell cat`）。
- [x] **`--aw-fops` 完整链首次实跑（2026-11-18）** —— 大幅推进后崩在链走深处：
  - 重解 slide（重启后）= `0x10dec00000`，base `ffffff90e6c80000`（两次一致）。
  - 双载波线程全部成功：F=`0xffffff8034bc3cb0`、G=`0xffffff8034bcbcb0`，
    perf 泄露交叉校验 122/124 与 163/163（**栈几何与偏移在载波线程上也验证正确**）。
  - 伪 fops 表构造正确（write=configfs_write_bin_file、ioctl/open 指向真 ashmem 函数），
    fd 并集武装 246 个、两载波 `ps_ret=-12345`（真阻塞在 do_select），EDEADLK(35) 命中。
  - **崩溃点从上一会话的 `_raw_spin_trylock+0x1c` 前移到 `rb_erase_cached+0x30/0x3dc`**
    （AEE: `db.fatal.03.KE`）——即链走已越过取锁、进入 rbtree 写阶段。
    反汇编 `rb_erase_cached+0x18` 是 `cbz rb_left`，走到 `+0x30` 说明假节点
    `tree_entry.rb_left`（缓冲 offset 0x28）当时非 0 ⇒ 那一刻栈上缓冲不是预期构造。
    这正是参考台账第 26→35 轮（约 10 次真机崩溃）在同一个 rbtree 状态机上反复打磨的点。
  - 设备自行干净重启、恢复正常；**本机 /data 实为 f2fs（非参考机的 ext4 errors=panic）**，
    强制重启的数据损坏风险比参考描述低。`busy_read` 已复原为 0。
- [x] **第二发 `--aw-fops`（离线深挖崩溃点，2026-11-18）**：
  - AEE：崩溃从 `_raw_spin_trylock+0x1c` 前移到 **`rb_erase_cached+0x30/0x3dc`**（链走越过取锁进入 rbtree 写）。
  - 逐条反汇编复核（全部正确，排除偏移错误）：
    - `pi_blocked_on=0x8c8`（`ldr x25,[x19,#2248]`）、`pi_lock=0x8a4`（`add x26,x19,#2212`）✓
    - `remove_waiter` 用 `current->pi_blocked_on=0`（`mrs x20,SP_EL0`/`str xzr,[x20,#2248]`）✓
    - `rt_mutex_adjust_prio_chain` 首 erase：`x0=x25`(waited waiter)、`x1=x24+8`(lock+8)，前置 `BUG_ON(top_waiter->lock==lock)` 用 `[x24,#16]`→`[x27,#56]`，与 G 布局自洽（P=G+0x28, *(G+0x60)=G）✓
    - 本机 `rb_erase_cached` 两处 store 顺序与参考**相反**（本机先 `*(parent+8)=child` 后 `*(child)=pc`），但结果等价，非根因。
    - `+0x18` 有 `cbz rb_left` → Case-1；我们的 W.tree_entry.rb_left（buf 0x28）=0，本应走 Case-1。
  - **结论**：偏移/几何/构造全部核对无误；崩溃在 `+0x30`（两孩子分支）说明那一刻被 erase 的节点
    `rb_left≠0`，即假对象树形状在链走瞬间不自洽——这正是参考第 26→35 轮（约 10 次真机崩溃）
    在同一个 rtmutex 状态机上反复打磨的点。日志停在 `FUTEX_CMP_REQUEUE_PI` 之后、`waiter_out` 之前，
    提示 requeue 触发 UAF 后内核自发的 PI 维护可能先于我们的假对象铺好而崩。
- [x] **第三发 `--aw-fops` + fsync 阶段标记（2026-11-18，slide=0x1849e00000）**：
  加了 `mark_stage()`（open/write/fsync/close 到 `/data/local/tmp/gl_stage.mark`），0.6s 轮询。
  标记全部到达：`S1-after-requeue → S2b-waiter-first-adjtimex → S2-waiter-out → S3-fops-buf-built → S4-consumer-go`，
  然后崩（AEE 仍 `rb_erase_cached+0x30/0x3dc`）。
  ⇒ **精确定论**：所有前置步骤成功（requeue EDEADLK、waiter 铺缓冲、perf T/R、fops 缓冲构造、消费者放行），
  崩溃就在**消费者触发的链走读假 waiter → rb_erase** 这一步。这既证明 reclaim 完全生效（否则 `r=0` 静默退出），
  也把问题收敛为纯粹的「假对象 rb-tree 形状自洽性」。
  构造日志核对：`F=0xffffff802344bcb0`（载波0栈）、`G=0xffffff80238ebcb0`（载波1栈）、
  `target=0xffffff9853ee3ef8`（= KB+0x2063ef8 = ashmem_misc.fops）、
  `*(F+0x10)=0 ≠ node=0xffffff8023423d30` ✓（Case-1 前置满足）。
- [x] **★★★★★ 第四发（2026-11-18，md5 `6b01bb9c`, slide=0xe2a600000）——【里程碑】任意内核写落地、设备全程存活**：
  加了 fsync 深层标记，全部到达：`S1 requeue → S2b adjtimex → S2 waiter_out → S3 fops buf → S4 consumer-go
  → S4b consumer-loop-done → S5 chainwalk-returned-verify → S6 ARBITRARY-WRITE-LANDED`。
  日志实证：
  - `FUTEX_CMP_REQUEUE_PI EDEADLK` ✓、waiter adjtimex EFAULT ✓、链走完整返回（5 万次 sched_setattr 全 ok）✓
  - ashmem 同-rdev 别名节点打开 `rdev=10:102` fd=6、`SET_NAME` 7 次 ioctl 成功 ✓
  - `还原 ashmem_misc.fops -> 8 errno=0`、`kern_write(busy_read=0x41424344)->4 errno=0`、
    **`busy_read` 读回 = 0x41424344 ⇒ S6 标记触发 ⇒ 任意内核写确凿落地** ✓✓✓
  - 设备存活（uptime 12 分钟未重启）、无新 AEE crash。
  - **唯一未达 root 的原因**：get_root 的 comm 自扫描「遍历 0 个任务未找到自身」——
    任意**读**全返回 0。根因是我把 `OFF_BUSY_READ_CTL_ENTRY` 误写成 `0x02067660`（正确 `0x02087660`，差 0x20000），
    导致读重定向写错内核地址。**已修正并重新审计全部 24 个 OFF_ 偏移，其余全对**。
- [x] **第五发（md5 `e088f92a`，干净重启后 slide=0xbc6200000）**：读偏移修正后重跑，
  标记再次全达 S6（任意写落地），但**任意读仍失败**：`读回 ashmem_misc.fops=0`、
  `[任意读] *(u64*)(fops_slot)=0x4142434441424344`（= busy_read/busy_poll 的 magic 值）。
  **根因查明**：RMX3031 的 `busy_read` ctl_table `.proc_handler` = **`proc_dointvec_minmax`**
  （`ctl_entry+0x20` 重定位到 `0xffffff80080bcacc`），会把读到的内核指针（负 int32）**clamp 成 0**；
  而参考机 RMX1991 用的是**无 clamp 的 `proc_dointvec`**。这是两机的真实内核差异。
  **修复**：`cfg_arm_reads()` 里先用任意写把 `ctl_entry+0x20` 的 handler 改成明文
  `proc_dointvec`（off `0x8bc308`）再做 data 重定向。已编译（md5 `ab70570b`）。
  ⚠️ 注意：任意**写**一直成功，是因为 magic `0x41424344` 是正数、未被 minmax clamp。
- [x] **第六发（md5 `ab70570b`，干净重启 slide=0x1a0e600000）**：崩在链走阶段（仅到 S3），
  AEE 为 `mtk_nanohub_batch_to_hub+0xac`（sensor hub 驱动，非 rb_erase）——
  说明利用**非确定性**：run3/run5 能穿过链走到验证阶段，run2/4/6 在链走或 IRQ 处理崩。
  这与参考机「约 10 轮真机才调出稳定构造」一致。读修复尚未在穿越链走的那一发上验证。
- [ ] **下一步**：继续在干净基线上重跑 `ab70570b`（每次重启后重解 slide），直到再拿到一次
  穿越链走到验证阶段的 run，检验 handler 修复后任意读是否返回真实值 → comm 自扫描 → 改 cred。
  ⚠️ 纪律：每发之间必须干净重启（PARKED 常驻进程的 PI 链不能并发/强杀）；实时抓日志 + uptime 判定。
- [ ] **（历史，已被上条取代）真正的硬骨头**：
  `rb_erase_cached+0x30` 是两孩子分支（`ldr x10,[x10,#16]`），而假节点 `W.tree_entry.rb_left`（buf 0x28）
  我们设为 0、本应走 `+0x18` 的 `cbz` Case-1。二者矛盾的可能解释：
  1. `node == root->rb_leftmost` 走了 `rb_next` 分支（ZH8 前置条件）：root=G+8，`root+8`=G+0x10=P，
     node=W=R；R≠P 应跳过——需再核对第一处 erase 的 root 到底是 G+8 还是别的。
  2. 假 waiter 在链走读到的那一刻，缓冲已被 `do_adjtimex`/信号/IRQ 部分覆盖（rb_left 字段非 0）。
  3. 本机 rtmutex 与参考机存在编译器级结构差异（本机 clang 11 vs 参考 clang 10）。
  参考机在此关耗约 10 轮真机才调出 ZT52 构造。每发先离线排干净、实时抓日志、uptime 判定。

## 设备安全纪律（来自参考台账的教训，必须遵守）

1. 每次 `BUG()`/`brk` 都会干净重启；`/data` 是 `errors=panic` 的 ext4 且 BL 已锁，
   **不要在不确定的构造上反复打真机**；每一发先离线排干净。
2. 日志必须**运行中实时抓取**（`exec-out cat` 轮询），重启后 `/data` 上的日志会丢；
   用 `/proc/uptime` 判定本次实验是否中途重启过。
3. slide 每次重启都要重解；`perf_leak_T` 连续 0 命中第一嫌疑是 slide 解错。
4. 成功后 root 是内存态（重启即失效）；参考交付用 KernelSU LKM + SELinux 模块持久化，
   本机同为 `MODULE_SIG_FORCE=y` / `SYSTEM_TRUSTED_KEYS=""`，可复用其签名交换方案。

## 2026-11-18 下午：Round 5 突破与 copy_from_user panic（二进制 md5 3765c76a → 新增 GR 标记版 0b59bcde）

- [x] **auto_loop 6 轮（--unlock-flag --permissive 满配）**：Round 5（slide 待查，dump 时间 14:13:40）
  **首次穿越链走 + 任意读修复验证成功**：
  - 读回 `ashmem_misc.fops = 0xffffff8202c42c38` 与真值一致 ★任意读命中；
  - 交叉验证 `ashmem_misc.name` 指向 KB 区 "ashmem" 字符串 ✔；
  - 任意写 `busy_read=0x41424344` 回读吻合 ✔ —— **任意内核【读+写】双双到手，系统还原干净**。
- [x] **get_root 阶段新崩溃**：`KE at __arch_copy_from_user+0xfc/0x280`（dump db.fatal.03.KE）。
  glive.log 停在「提权阶段: 改cred」头一行；gl_stage.mark 最后 = S6。
  **定位逻辑**：任意写原语 = pwrite → configfs 路径 → copy_from_user 直写 bin_buffer；
  panic 即某次 kern_write/pwrite 的目标未映射。但 get_root 里所有静态目标（g_boot_state
  0x17bc458 / cred+0x24 slab / ctl_entry）都在映射范围内 → 崩溃点在日志丢失区间内，
  无法静态定位（dump 01/02 仍是老的 rb_erase_cached+0x30，即链走非确定性，非新问题）。
- [x] **参考 natsuu233/GhostLock-MatePad11 (DBY 教程)**：确认同类崩溃纪律——写原语目标必须可写，
  cred/init_cred 引用计数不能因进程退出而清零，每步消费前后要有可持久化判据。
  原文存 `D:/resource/deepseek-harness-workspace/dby_tutorial.md`。
- [x] **对策（当前进行中）**：get_root 全流程埋 fsync 级 GR 标记（gl_stage.mark 已被证明
  能穿越 panic 落盘）：GR1-start / GR2-comm / GR-scan-n512..8192 / GR-scan-end /
  GR3-self-claimed / GR4-cred-read / GR-pre-bootstate / GR5-bootstate /
  GR6-priv-cred / GR-pre-caps-write / GR7-caps-written / GR8-setuid /
  GR9-busyread-restored / GR10-proof-done。auto_loop.ps1 改为**不在 S6 break**，
  继续轮询 GR 标记直到 ROOT/REBOOT，每轮日志存 awfops_round<N>.log。
- [ ] **下一步**：后台循环跑新二进制（0b59bcde），等下一次 S6→GR 崩溃，用标记链精确定位；
  若崩在 GR-pre-caps-write（cred+0x24 44B 写），则换成分段写/先读校验。

## 2026-11-18 傍晚：ROOT 突破（二进制 52012eab → a8405c72）

- [x] **★ROOT 已到手（两次复现）**：uid=0 gid=0 caps=全满，进程以 root 驻留（ps USER=root）。
  日志证据：`读回 cred.uid = 0` → `getuid=0 geteuid=0` → `uid=0(root) gid=0(root) ... context=u:r:shell:s0` → "ROOT 到手"。
- [x] **决定性修复 1：直写 uid/gid 段**（52012eab）。setuid32(0) 被拒 errno=1 (EPERM)，
  反汇编 oplus_root_check：uid==0 直接放行、setuid 家族 syscall 号(143-147/149/203/204/208/210/213/214)白名单；
  拒绝来自内核能力/SELinux 路径而非 oplus 钩子。对策：完全不走 syscall，
  kern_write 直接把私有 cred 的 +0x04..0x23 (uid/gid/suid/sgid/euid/egid/fsuid/fsgid 8×u32) 清零。
  标记 GR-pre-uid-write / GR-uid-written。
- [x] **决定性修复 2：selinux enforcing 真实字节在 +2**（a8405c72）。
  - OFF_SELINUX_STATE=0x231d4f8 地址正确（selinux_task_alloc 的 adrp+add 交叉验证）。
  - avc_denied 反汇编：permissive 判定 = avd.flags bit0（per-domain PERMISSIVE），由
    security_compute_av 在 `!enforcing_enabled(state)` 时设置；该函数 `ldrb w8,[x19,#2]`
    → **enforcing = selinux_state+2**（+0 disabled / +1 checkreqprot 本来就是 0，之前清它们无效）。
  - **OPLUS 伪装**：sel_read_enforce 硬编码 `scnprintf(buf,12,"%d",1)` → selinuxfs 恒报
    "Enforcing"，getenforce 不可信；读 /proc/self/attr/current 等域信息正常。
  - selinux_state 在可写 .data（+0/+1 写未 panic 证实），与 g_boot_state(只读 __ro_after_init) 不同。
  - **时机**：必须在第一次 setuid 尝试【之前】清 +2，否则失败项被 avc 缓存、清了也命中缓存继续拒。
    标记 GR-pre-selinux-flip / GR-selinux-flipped。
- [x] **f2fs 回滚坑**：panic 重启会把 /data/local/tmp 回滚到 checkpoint，push 的新二进制可能被
  回滚成旧版（md5 变回 14:52 版）。auto_loop.ps1 已加：每轮重新 push + chmod 755 + sync×2
  + 设备端 md5 校验（不匹配自动重启重试）。
- [x] auto_loop.ps1 增加参数 -minUptimeSec(默认60)/-bin/-md5；Wait-CleanBaseline 函数。
- [x] probe 结果（root 进程内 --cmd）：读 /proc/1/cmdline ✔；touch /data/local/tmp 被拒 errno=13
  （enforcing 未清时 SELinux 拒）；su.sock bind errno=13 同因。清 +2 后预期恢复（待验证）。
- [ ] 下一步：跑 a8405c72 循环确认 GR-selinux-flipped 后 setuid/文件写/bind 全通，
  验证 `./stage1 --su "id"` 可用性；链走成功率仍 ~1/3（rb_erase_cached / 工作队列踩栈，非确定性）。

## 2026-11-18 晚：★ exploit 完整可用（终态 a8405c72）

- [x] **su 守护验证通过**：`./stage1 --su 'id'` → uid=0(root)；root 下写文件成功
  （HELLO-FROM-ROOT 落盘）；getenforce 仍显示 Enforcing（OPLUS selinuxfs 硬编码伪装），
  但实际 selinux_state.enforcing(+2)=0 permissive，文件写/bind 均已放行。
- [x] **完整成功链**（a8405c72，Round 2 标记链）：
  S6 → GR1..GR10 → GR-pre-selinux-flip → GR-selinux-flipped → caps → uid 直写 →
  setuid(0) 成功(白名单+permissive) → GR10-proof-done → root 守护 bind 成功。
  注：setuid 首试即成功（enforcing 提前清零避免了 avc 缓存问题）。
- [x] **链走成功率再确认**：a8405c72 前 14 连败纯属随机（后 12 轮中第 2 轮即成）。
  链走阶段（S4→S6）本质是 timing race，成功率 ~1/4~1/3，auto_loop 8-12 轮稳出。
- [x] 用法速查：
    adb shell "cd /data/local/tmp && GHOSTLOCK_LEAK_ONLY=1 timeout 50 ./gl_leak"   # 解 slide
    adb shell "cd /data/local/tmp && ./stage1 --aw-fops --slide 0x... --iters 2000000 --unlock-flag --permissive"
    # 成功后进程 PARKED 持 root + su.sock
    adb shell "cd /data/local/tmp && ./stage1 --su 'id'"                            # 任意 root 命令
    su 守护支持 !selinux 0/1 (真实切换 enforcing+2)、!gl <off> <bytes> (任意内核写)
- [ ] root 为内存态，重启即失；持久化(su 安装/模块) 未做——留待后续需求。

## 2026-11-18 17:10：设备端自动循环 auto_loop.sh（替代 auto_loop.ps1）

- [x] auto_loop.ps1 移植为设备端 POSIX sh 脚本 `/data/local/tmp/auto_loop.sh`（不再依赖 adb/PC）。
  保留逻辑：clean-baseline 门槛(uptime>=60 & 无残留)、stage1 md5 校验（防 f2fs 回滚，export GL_MD5=... 启用）、
  gl_leak 解 slide、启动 stage1、轮询 gl_stage.mark/glive.log（S6 不 break，直到 ROOT/REBOOT/超时）、
  每轮存 round<N>.log、ROOT 时存 awfops_SUCCESS.log。
  与 PS 版差异：无 push（只校验）；TIMEOUT 且无残留时**不重启直接下一轮**（提高吞吐）；
  需要重启的场景（panic/脏态）脚本会随设备死亡——重启后重跑 nohup 行即可。
- [x] 用法：
    adb shell "cd /data/local/tmp && GL_MD5=<md5> nohup sh auto_loop.sh 12 60 > loop.log 2>&1 &"
    adb shell "tail -f /data/local/tmp/loop.log"     # 观察
    成功后：adb shell "cd /data/local/tmp && ./stage1 --su 'id'"
- [x] 实战验证：17:11 首发即中，Round 1 全链 19 秒（S1→S6→GR1..GR10→selinux flip→uid 直写→
  root 守护就绪），--su 'id' 输出 uid=0(root)，root 下写文件成功。
