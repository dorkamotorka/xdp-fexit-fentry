//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("fentry/xdp")
int BPF_PROG(fentry_xdp, struct xdp_buff *xdp) {
    bpf_printk("Fentry triggered.");
    return 0;
}

SEC("fexit/xdp")
int BPF_PROG(fexit_xdp, struct xdp_buff *xdp, int ret) {
    bpf_printk("Fexit triggered.");
    return 0;
}

SEC("xdp")
int dummy(struct xdp_md *ctx) {
    return XDP_PASS;
}
