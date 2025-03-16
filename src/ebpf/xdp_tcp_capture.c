// xdp_tcp_capture.c with added debug messages
// A simplified XDP program to capture TCP payloads for packets to/from a specific port

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// Structure to store packet metadata
struct packet_metadata {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 payload_size;
    __u8 payload[64]; // Reduced buffer size
};

// Define a perf event array to send data to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} events SEC(".maps");

// Define our target port map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
    __uint(pinning, 1); // LIBBPF_PIN_BY_NAME
} target_port SEC(".maps");

// Simple message format for trace_printk
#define bpf_printk(fmt, ...)                                    \
({                                                              \
    char ____fmt[] = fmt;                                       \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
})

SEC("xdp")
int xdp_tcp_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Bounds check: Ensure we have a complete Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IP packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Bounds check: Ensure we have a complete IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Only process TCP packets
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Bounds check: Ensure we have a complete TCP header
    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Get port numbers and convert from network to host byte order
    __u16 dst_port = bpf_ntohs(tcp->dest);
    __u16 src_port = bpf_ntohs(tcp->source);

    // Check if packet is going to/from our target port
    __u32 key = 0;
    __u32 *port = bpf_map_lookup_elem(&target_port, &key);
    if (!port) {
        return XDP_PASS;  // No port configured, pass all packets
    }

    // Sudarsan-Test to exclude 22 since Im sshing and it prints all those packets.
    if (dst_port != 22) {
        bpf_printk("DEBUG: TCP packet src_port=%u, dst_port=%u", src_port, dst_port);
    }

    // Check if the packet involves our target port
    if (dst_port != *port && src_port != *port) {
        return XDP_PASS;
    }

    bpf_printk("DEBUG: MATCH! Port matches target port");

    // Calculate TCP header length and find payload
    __u32 tcp_header_length = tcp->doff * 4;
    void *tcp_payload = (void *)tcp + tcp_header_length;

    // Bounds check: Ensure we have some payload
    if (tcp_payload > data_end) {
        bpf_printk("DEBUG: No payload available");
        return XDP_PASS;
    }

    __u32 payload_size = data_end - tcp_payload;

    // Skip empty payloads
    if (payload_size == 0) {
        bpf_printk("DEBUG: Empty payload");
        return XDP_PASS;
    }

    bpf_printk("DEBUG: Found payload of size %u", payload_size);

    // Prepare data for perf event
    struct packet_metadata pkt_data = {0};  // Zero initialization

    // Set metadata fields
    pkt_data.src_ip = ip->saddr;
    pkt_data.dst_ip = ip->daddr;
    pkt_data.src_port = src_port;
    pkt_data.dst_port = dst_port;

    // Set payload size (capped to buffer size)
    __u16 bytes_to_copy = payload_size;
    if (bytes_to_copy > sizeof(pkt_data.payload))
        bytes_to_copy = sizeof(pkt_data.payload);

    pkt_data.payload_size = bytes_to_copy;

    bpf_printk("DEBUG: About to copy %u bytes of payload", bytes_to_copy);

    // Copy payload data with explicit bounds checking
    for (int i = 0; i < sizeof(pkt_data.payload); i++) {
        if (i >= bytes_to_copy)
            break;

        if (tcp_payload + i >= data_end)
            break;

        pkt_data.payload[i] = *(__u8 *)(tcp_payload + i);
    }

    // Send data to user space via perf event
    bpf_printk("DEBUG: Sending event to userspace via perf_event_output");
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                         &pkt_data,
                         sizeof(struct packet_metadata));

    // Don't drop the packet, just pass it through
    return XDP_PASS;
}
