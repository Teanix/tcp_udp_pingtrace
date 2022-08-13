#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tcpping.h"
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, 10);
// 	__type(key, u64);
// 	__type(value, struct netInfoSend);
// 	__uint(map_flags, BPF_F_NO_PREALLOC);
// } netInfo SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__type(key, u64);
	__type(value, struct net_test);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} net_test_map SEC(".maps");

SEC("tp/net/netif_receive_skb")
int tracepoint__netif_receive_skb(struct trace_event_raw_net_dev_xmit *args)
{
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	u64 ts = bpf_ktime_get_ns();
	struct net_test net={};
	int ip_off = sizeof(struct iphdr);

	struct sk_buff *skb = (struct sk_buff *)(args->skbaddr);
    struct iphdr *ip_data = (struct iphdr *)(BPF_CORE_READ(skb,data));
	struct tcphdr *tcp_data =(struct tcphdr *)(BPF_CORE_READ(skb,data) + ip_off);

	net.pid = pid;
	net.srcIP = BPF_CORE_READ(ip_data,saddr);
	net.dstIP = BPF_CORE_READ(ip_data,daddr);
	net.srcPort = bpf_ntohs(BPF_CORE_READ(tcp_data,source));
	net.dstPort = bpf_ntohs(BPF_CORE_READ(tcp_data,dest));	
	bpf_map_update_elem(&net_test_map,&pid,&net,BPF_ANY);

	return 0;
}

SEC("kprobe/ip_rcv")
int BPF_KPROBE(tcp_v4_rcv_hook,struct sk_buff *skb)
{
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	u64 ts = bpf_ktime_get_ns();
	
	int ip_off = sizeof(struct iphdr);

	struct iphdr *ip_data =(struct iphdr *)(BPF_CORE_READ(skb,data));
	struct tcphdr *tcp_data =(struct tcphdr *)(BPF_CORE_READ(skb,data)+ip_off);

	struct net_test net={};
	net.pid = pid;
	net.srcIP = BPF_CORE_READ(ip_data,saddr);
	net.dstIP = BPF_CORE_READ(ip_data,daddr);
	net.srcPort = bpf_ntohs(BPF_CORE_READ(tcp_data,source));
	net.dstPort = bpf_ntohs(BPF_CORE_READ(tcp_data,dest));
	
	bpf_map_update_elem(&net_test_map,&pid,&net,BPF_ANY);

	return 0;
}

SEC("kprobe/ip_local_deliver")
int BPF_KPROBE(ip_local_deliver_finish,struct sk_buff *skb)
{
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	u64 ts = bpf_ktime_get_ns();

	struct sock_common skcommon = BPF_CORE_READ(skb,sk,__sk_common);

	struct net_test net={};
	net.pid = pid;
	net.srcIP = skcommon.skc_rcv_saddr;
	net.dstIP = skcommon.skc_daddr;
	net.srcPort = skcommon.skc_num;
	net.dstPort = bpf_ntohs(skcommon.skc_dport);
	

	if(net.srcPort==1234 || net.dstPort==1234)
	bpf_map_update_elem(&net_test_map,&pid,&net,BPF_ANY);


	return 0;
}


SEC("kprobe/tcp_v4_rcv")
int BPF_KPROBE(tcp_v4_rcv_hook,struct sk_buff *skb)
{
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	u64 ts = bpf_ktime_get_ns();

	struct sock_common skcommon = BPF_CORE_READ(skb,sk,__sk_common);

	struct net_test net={};
	net.pid = pid;
	net.srcIP = skcommon.skc_rcv_saddr;
	net.dstIP = skcommon.skc_daddr;
	net.srcPort = skcommon.skc_num;
	net.dstPort = bpf_ntohs(skcommon.skc_dport);
	

	if(net.srcPort==1234 || net.dstPort==1234)
	bpf_map_update_elem(&net_test_map,&pid,&net,BPF_ANY);


	return 0;
}
