#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/bpf.h>

BPF_PERF_OUTPUT(events);  // Output buffer for user-space events

struct ssl_write_event_t {
    u32 pid;
    u32 len;
    char data[256];
};

// Uprobe attached to the OpenSSL 'SSL_write' function
SEC("uprobe/SSL_write")
int uprobe__SSL_write(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Extract arguments: SSL_write(SSL *ssl, const void *buf, int num)
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    int num = PT_REGS_PARM3(ctx);

    // TODO: This temporarily limtis the buffer size to 256 bytes
    // Should/Could revisit this to handle larger buffers in the future.
    if (num > 256) {
        num = 256;
    }

    struct ssl_write_event_t event = {};
    event.pid = pid;
    event.len = num;

    // Read user-space buffer
    bpf_probe_read_user(&event.data, sizeof(event.data), buf);

    // Send the captured data to user space
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}
