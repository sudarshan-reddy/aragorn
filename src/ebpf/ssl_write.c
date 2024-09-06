#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>

#define MAX_BUF_SIZE 256

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_BUF_SIZE);
    __uint(max_entries, 1);
} data_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("uprobe/SSL_write")
int ssl_write_entry(struct pt_regs *ctx)
{
    __u64 ssl = PT_REGS_PARM1(ctx);
    __u64 buf = PT_REGS_PARM2(ctx);
    __u64 num = PT_REGS_PARM3(ctx);

    __u32 key = 0;
    void *data = bpf_map_lookup_elem(&data_buffer, &key);
    if (!data)
        return 0;

    __u32 size = num < MAX_BUF_SIZE ? num : MAX_BUF_SIZE;

    bpf_probe_read_user(data, size, (void *)buf);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, size);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
