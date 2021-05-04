import json
from collections import namedtuple
import sys
from bcc import BPF
from uuid import UUID


bpf_text = """
# include <linux/vfs.h>
# include <linux/fs.h>
# include <uapi/linux/limits.h>

# define XATTR_VAL_MAX 255

enum DIRECTION {
    DIRECTION_GET,
    DIRECTION_SET
};

struct tmp_t {
    u64 start;
    struct inode *ip;
    const char *name;
    void *value;
    size_t size;
    int ustack;
    int kstack;
};

struct data_t {
    u64 start;
    u64 end;
    enum DIRECTION dir;
    unsigned long inode;
    char name[XATTR_NAME_MAX];
    u8 value[XATTR_VAL_MAX];
    int size;
    char comm[TASK_COMM_LEN];
    u32 pid;
    u32 tgid;
    int ustack;
    int kstack;
};

BPF_HASH(entry, u32, struct tmp_t);
BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(tmpdata, struct data_t, 1);
BPF_STACK_TRACE(traces, 1024);

int kprobe__zpl_xattr_get(struct pt_regs *ctx, struct inode *ip, const char *name, void *value, size_t size)
{
    u32 pid = bpf_get_current_pid_tgid();

    struct tmp_t tmp = {
        .ip = ip,
        .name = name,
        .value = value,
        .size = size,
    };
    tmp.start = bpf_ktime_get_ns();
    tmp.kstack = traces.get_stackid(ctx, 0);
    tmp.ustack = traces.get_stackid(ctx, BPF_F_USER_STACK);

    entry.insert(&pid, &tmp);

    return 0;
}

int kretprobe__zpl_xattr_get(struct pt_regs *ctx)
{
    u32 idx = 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    u32 tgid = pid_tgid >> 32;
    struct tmp_t *tmp;
    struct data_t *data = tmpdata.lookup(&idx);
    int sz;

    tmp = entry.lookup(&pid);
    if (!tmp || !data)
        return 0;

    bpf_probe_read_kernel_str(&data->name, sizeof(data->name), tmp->name);
    data->size = min_t(size_t, sizeof(data->value), tmp->size);
    bpf_probe_read_kernel(data->value, data->size, tmp->value);

    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->pid = pid;
    data->tgid = tgid;
    data->dir = DIRECTION_GET;
    bpf_probe_read_kernel(&data->inode, sizeof(data->inode), &tmp->ip->i_ino);
    data->end = bpf_ktime_get_ns();
    data->start = tmp->start;
    data->kstack = tmp->kstack;
    data->ustack = tmp->ustack;

    entry.delete(&pid);
    events.perf_submit(ctx, data, sizeof(*data));

    return 0;
}

typedef struct {} cred_t;

int kprobe__zpl_xattr_set(struct pt_regs *ctx, struct inode *ip, const char *name, const void *value,
    size_t size, int flags, cred_t *cr)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    u32 tgid = pid_tgid >> 32;
    u32 idx = 0;
    struct data_t *data = tmpdata.lookup(&idx);

    if (!data)
        return 0;

    data->dir = DIRECTION_SET;
    data->pid = pid;
    data->tgid = tgid;
    data->start = bpf_ktime_get_ns();
    data->kstack = traces.get_stackid(ctx, 0);
    data->ustack = traces.get_stackid(ctx, BPF_F_USER_STACK);

    bpf_probe_read_kernel_str(&data->name, sizeof(data->name), name);
    data->size = min_t(size_t, sizeof(data->value), size);
    bpf_probe_read_kernel(data->value, data->size, value);

    events.perf_submit(ctx, data, sizeof(*data));

    return 0;
}

"""


b = BPF(text=bpf_text)

events = []
Event = namedtuple('Event', ['data', 'ts', 'pid', 'tgid',
                   'comm', 'function', 'inode', 'name', 'ustack', 'kstack'])


def dump_event(event):
    try:
        kstack = [] if event.kstack < 0 else \
            list(traces.walk(event.kstack))
        ustack = [] if event.ustack < 0 else \
            list(traces.walk(event.ustack))
    except KeyError:
        print(
            f'Unkown stack: u {event.ustack}, k {event.kstack}', file=sys.stderr)
        kstack = []
        ustack = []

    ktrace = [b.ksym(addr).decode('utf-8', 'replace')
              for addr in (kstack)]
    utrace = [b.sym(addr, event.tgid).decode('utf-8', 'replace')
              for addr in (ustack)]

    print(f'{event.ts} {event.pid} {event.comm} - {event.function}({event.inode}, {event.name}) = {event.data}')
    print('\n'.join([*ktrace, '-', *utrace]))


def print_event(cpu, data, size):
    event = b["events"].event(data)

    comm = event.comm.decode()
    name = event.name.decode()
    data = bytes(event.value[:event.size])

    if name == 'trusted.gfid':
        data = UUID(bytes=data)
    else:
        return

    function = "getfattr"
    if event.dir == 1:
        function = "setfattr"

    events.append(Event(
        data=data,
        ts=event.start,
        pid=event.pid,
        tgid=event.tgid,
        comm=comm,
        function=function,
        inode=event.inode,
        name=name,
        ustack=event.ustack,
        kstack=event.kstack,
    ))


b["events"].open_perf_buffer(print_event)
traces = b.get_table('traces')
print('tracing', file=sys.stderr)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print(f'Got {len(events)} events. Dumping...', file=sys.stderr)


class E(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, UUID):
            return str(o)
        return super().default(o)


def export_event(event):
    try:
        kstack = [] if event.kstack < 0 else \
            list(traces.walk(event.kstack))
        ustack = [] if event.ustack < 0 else \
            list(traces.walk(event.ustack))
    except KeyError:
        print(
            f'Unkown stack: u {event.ustack}, k {event.kstack}', file=sys.stderr)
        kstack = []
        ustack = []

    ktrace = [b.ksym(addr).decode('utf-8', 'replace')
              for addr in (kstack)]
    utrace = [b.sym(addr, event.tgid).decode('utf-8', 'replace')
              for addr in (ustack)]

    event = event._asdict()
    event["kstack"] = ktrace
    event["ustack"] = utrace

    return event


for e in sorted(events, key=lambda e: e.ts):
    print(json.dumps(export_event(e), cls=E))
