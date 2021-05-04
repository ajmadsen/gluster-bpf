import sys
from bcc import BPF
import ctypes

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/stat.h>

struct data_t {
    s64 ts;
    struct timespec now;
    struct timespec then;
    int stack;
    u32 pid;
};

struct data2_t {
    unsigned long inode;
    int stack;
    u32 pid;
};

BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(calls, 1024);
BPF_HASH(inodes, unsigned long, struct data2_t);
BPF_HASH(in_heal, u32);


int trace_mknod(struct pt_regs *ctx)
{
    bpf_trace_printk("mknod!\\n");
    return 0;
}

int trace_heal(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    in_heal.increment(pid);
    return 0;
}

int ret_heal(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    in_heal.delete(&pid);
    return 0;
}

int trace_gf_tsdiff(struct pt_regs *ctx)
{
    s64 ts;
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid();

    if (!in_heal.lookup(&pid))
        return 0;

    bpf_probe_read_user(&ts, sizeof(ts), (void *)(ctx->bp - 8));
    data.ts = ts;
    bpf_probe_read_user(&data.then, sizeof(data.then), (void *)PT_REGS_PARM1(ctx));
    bpf_probe_read_user(&data.now, sizeof(data.now), (void *)(ctx->bp - 0x20));
    data.stack = calls.get_stackid(ctx, BPF_F_USER_STACK);
    data.pid = bpf_get_current_pid_tgid() >> 32;

    if (data.ts > 1000000000)
        events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int trace_gfid_set(struct pt_regs *ctx)
{
    struct data2_t data = {};
    struct stat stat = {};

    bpf_probe_read_user(&stat, sizeof(stat), (void *)(ctx->bp - 0xc0));
    data.inode = stat.st_ino;
    data.stack = calls.get_stackid(ctx, BPF_F_USER_STACK);
    data.pid = bpf_get_current_pid_tgid() >> 32;

    inodes.insert(&stat.st_ino, &data);

    // events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""


class Timespec(ctypes.Structure):
    _fields_ = [
        ('tv_sec', ctypes.c_long),
        ('tv_nsec', ctypes.c_long),
    ]


class Event(ctypes.Structure):
    _fields_ = [
        ('ts', ctypes.c_int64),
        ('now', Timespec),
        ('then', Timespec),
        ('stack', ctypes.c_int),
        ('pid', ctypes.c_uint32),
    ]


b = BPF(text=bpf_text)
# b.attach_uprobe(name="/usr/lib64/glusterfs/9.1/xlator/storage/posix.so",
#                 sym="posix_mknod", fn_name="trace_mknod")

b.attach_uprobe(name="/usr/lib64/glusterfs/9.1/xlator/storage/posix.so",
                sym="is_fresh_file", fn_name="trace_gf_tsdiff", sym_off=52)

b.attach_uprobe(name="/usr/lib64/glusterfs/9.1/xlator/storage/posix.so",
                sym="posix_gfid_heal", fn_name="trace_heal")
b.attach_uretprobe(name="/usr/lib64/glusterfs/9.1/xlator/storage/posix.so",
                   sym="posix_gfid_heal", fn_name="ret_heal")

# # +3085
# b.attach_uprobe(name="/usr/lib64/glusterfs/9.1/xlator/storage/posix.so",
#                 sym="posix_mknod", fn_name="trace_mknod", sym_off=3085)

# +369
b.attach_uprobe(name="/usr/lib64/glusterfs/9.1/xlator/storage/posix.so",
                sym="posix_gfid_set", fn_name="trace_gfid_set", sym_off=369)

stacks = b.get_table("calls")


def print_evt(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents

    then = event.then.tv_sec + (event.then.tv_nsec / 1e9)
    now = event.now.tv_sec + (event.now.tv_nsec / 1e9)

    print(f"Then: {then}")
    print(f"Now: {now}")
    print(f'Elapsed: {event.ts / 1e9} s')

    for frame in stacks.walk(event.stack):
        print(f'\t{b.sym(frame, event.pid, show_offset=True).decode()}')


def print_evt2(cpu, data, size):
    event = b["events"].event(data)

    print(f"Set GFID on inode {event.inode}")
    for frame in stacks.walk(event.stack):
        print(f"\t{b.sym(frame, event.pid, show_offset=True)}")


b["events"].open_perf_buffer(print_evt)
inodes = b.get_table("inodes")

print("tracing...", file=sys.stderr)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("interrupted")

for k, v in inodes.items():
    print(f"Inode {k.value}")
    for frame in stacks.walk(v.stack):
        print(f"\t{b.sym(frame, v.pid, show_offset=True)}")
