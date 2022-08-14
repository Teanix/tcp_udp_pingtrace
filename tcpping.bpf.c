#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tcpping.h"
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__type(key, struct tuple);
	__type(value, struct net_time_Info);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} net_info_map SEC(".maps");

// tx ----------------------------------------------------------------
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg_hook, struct sock *sock)
{
	u64 pid, ts;

	pid = bpf_get_current_pid_tgid() >> 32;
	ts = bpf_ktime_get_ns();

	struct sock_common skcommon;
	skcommon = BPF_CORE_READ(sock, __sk_common);

	struct tuple tuple = {};
	struct net_time_Info net_time_Info = {};

	tuple.srcIP = skcommon.skc_rcv_saddr;
	tuple.dstIP = skcommon.skc_daddr;
	tuple.srcPort = skcommon.skc_num;
	tuple.dstPort = bpf_htons(skcommon.skc_dport);

	net_time_Info.pid = pid;
	net_time_Info.time = ts;
	net_time_Info.tuple.srcIP = tuple.srcIP;
	net_time_Info.tuple.dstIP = tuple.dstIP;
	net_time_Info.tuple.srcPort = tuple.srcPort;
	net_time_Info.tuple.dstPort = tuple.dstPort;

	net_time_Info.isdel = 0;
	net_time_Info.durationTime.dt1 = 0;
	net_time_Info.durationTime.dt2 = 0;
	net_time_Info.durationTime.dt3 = 0;

	if (tuple.dstPort == 1234 || tuple.srcPort == 1234)
	{
		bpf_printk("1-sip:%ld sp:%d dip:%ld \n",tuple.dstIP,tuple.dstPort,tuple.srcIP);
		bpf_printk("1-dp:%d \n",tuple.srcPort);
		bpf_map_update_elem(&net_info_map, &tuple, &net_time_Info, BPF_ANY);
	}	
		
	return 0;
}

SEC("kprobe/ip_queue_xmit")
int BPF_KPROBE(ip_queue_xmit_hook, struct sock *sk)
{
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	u64 ts = bpf_ktime_get_ns();
	struct sock_common skcommon = BPF_CORE_READ(sk, __sk_common);

	struct tuple tuple = {};

	tuple.srcIP = skcommon.skc_rcv_saddr;
	tuple.dstIP = skcommon.skc_daddr;
	tuple.srcPort = skcommon.skc_num;
	tuple.dstPort = bpf_htons(skcommon.skc_dport);

	struct net_time_Info *net_time_Info = bpf_map_lookup_elem(&net_info_map, &tuple);

	if (net_time_Info != NULL)
	{
		bpf_printk("2-sip:%ld sp:%d dip:%ld \n",tuple.dstIP,tuple.dstPort,tuple.srcIP);
		bpf_printk("2-dp:%d \n",tuple.srcPort);
		net_time_Info->durationTime.dt1 = ts - net_time_Info->time;
		net_time_Info->time = ts;
		net_time_Info->isdel = 0;
	}

	return 0;
}

SEC("kprobe/ip_finish_output")
int BPF_KPROBE(ip_finish_output_hook, struct net *net, struct sock *sk)
{

	u64 pid = bpf_get_current_pid_tgid() >> 32;
	u64 ts = bpf_ktime_get_ns();

	struct sock_common skcommon = BPF_CORE_READ(sk, __sk_common);

	struct tuple tuple = {};

	tuple.srcIP = skcommon.skc_rcv_saddr;
	tuple.dstIP = skcommon.skc_daddr;
	tuple.srcPort = skcommon.skc_num;
	tuple.dstPort = bpf_htons(skcommon.skc_dport);

	struct net_time_Info *net_time_Info = bpf_map_lookup_elem(&net_info_map, &tuple);

	if (net_time_Info != NULL)
	{
		bpf_printk("3-sip:%ld sp:%d dip:%ld \n",tuple.dstIP,tuple.dstPort,tuple.srcIP);
		bpf_printk("3-dp:%d \n",tuple.srcPort);
		net_time_Info->durationTime.dt2 = ts - net_time_Info->time;
		net_time_Info->time = ts;
		net_time_Info->isdel = 0;
	}

	return 0;
}

SEC("kprobe/__dev_queue_xmit")
int BPF_KPROBE(__dev_queue_xmit_hook, struct sk_buff *skb)
{
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	u64 ts = bpf_ktime_get_ns();

	struct sock_common skcommon = BPF_CORE_READ(skb, sk, __sk_common);

	struct tuple tuple = {};

	tuple.srcIP = skcommon.skc_rcv_saddr;
	tuple.dstIP = skcommon.skc_daddr;
	tuple.srcPort = skcommon.skc_num;
	tuple.dstPort = bpf_htons(skcommon.skc_dport);

	struct net_time_Info *net_time_Info = bpf_map_lookup_elem(&net_info_map, &tuple);

	if (net_time_Info != NULL)
	{
		bpf_printk("4-sip:%ld sp:%d dip:%ld \n",tuple.dstIP,tuple.dstPort,tuple.srcIP);
		bpf_printk("4-dp:%d \n",tuple.srcPort);
		net_time_Info->durationTime.dt3 = ts - net_time_Info->time;
		net_time_Info->time = ts;
		net_time_Info->isdel = 0;
	}

	return 0;
}

// rx----------------------------------------------------------------
SEC("tp/net/netif_receive_skb")
int tracepoint__netif_receive_skb(struct trace_event_raw_net_dev_xmit *args)
{
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	u64 ts = bpf_ktime_get_ns();

	int ip_off = sizeof(struct iphdr);
	struct sk_buff *skb = (struct sk_buff *)(args->skbaddr);
	struct iphdr *ip_data = (struct iphdr *)(BPF_CORE_READ(skb, data));
	struct tcphdr *tcp_data = (struct tcphdr *)(BPF_CORE_READ(skb, data) + ip_off);

	struct tuple tuple = {};
	//因为是收包，为了保证键一致，所以需要交换data域中的源和目的的IP+port
	tuple.srcIP = BPF_CORE_READ(ip_data, daddr);
	tuple.dstIP = BPF_CORE_READ(ip_data, saddr);
	tuple.srcPort = bpf_ntohs(BPF_CORE_READ(tcp_data, dest));
	tuple.dstPort = bpf_ntohs(BPF_CORE_READ(tcp_data, source));

	struct net_time_Info *net_time_Info = bpf_map_lookup_elem(&net_info_map, &tuple);
	if (net_time_Info != NULL)
	{
		bpf_printk("5-sip:%ld sp:%d dip:%ld \n",tuple.dstIP,tuple.dstPort,tuple.srcIP);
		bpf_printk("5-dp:%d \n",tuple.srcPort);
		net_time_Info->durationTime.dt4 = ts - net_time_Info->time;
		net_time_Info->time = ts;
		net_time_Info->isdel = 0;
	}

	return 0;
}

SEC("kprobe/ip_rcv")
int BPF_KPROBE(ip_rcv_hook, struct sk_buff *skb)
{
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	u64 ts = bpf_ktime_get_ns();

	int ip_off = sizeof(struct iphdr);

	struct iphdr *ip_data = (struct iphdr *)(BPF_CORE_READ(skb, data));
	struct tcphdr *tcp_data = (struct tcphdr *)(BPF_CORE_READ(skb, data) + ip_off);

	struct tuple tuple = {};
	//因为是收包，为了保证键一致，所以需要交换data域中的源和目的的IP+port
	tuple.srcIP = BPF_CORE_READ(ip_data, daddr);
	tuple.dstIP = BPF_CORE_READ(ip_data, saddr);
	tuple.srcPort = bpf_ntohs(BPF_CORE_READ(tcp_data, dest));
	tuple.dstPort = bpf_ntohs(BPF_CORE_READ(tcp_data, source));
	struct net_time_Info *net_time_Info = bpf_map_lookup_elem(&net_info_map, &tuple);
	if (net_time_Info != NULL)
	{
		bpf_printk("6-sip:%ld sp:%d dip:%ld \n",tuple.dstIP,tuple.dstPort,tuple.srcIP);
		bpf_printk("6-dp:%d \n",tuple.srcPort);
		net_time_Info->durationTime.dt5 = ts - net_time_Info->time;
		net_time_Info->time = ts;
		net_time_Info->isdel = 0;
	}

	return 0;
}


SEC("kprobe/ip_local_deliver")
int BPF_KPROBE(ip_local_deliver_hook, struct sk_buff *skb)
{
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	u64 ts = bpf_ktime_get_ns();
	int ip_off = sizeof(struct iphdr);

	struct tuple tuple = {};
	struct iphdr *ip_data = (struct iphdr *)(BPF_CORE_READ(skb, data));
	struct tcphdr *tcp_data = (struct tcphdr *)(BPF_CORE_READ(skb, data) + ip_off);

	tuple.srcIP = BPF_CORE_READ(ip_data, daddr);
	tuple.dstIP = BPF_CORE_READ(ip_data, saddr);
	tuple.srcPort = bpf_ntohs(BPF_CORE_READ(tcp_data, dest));
	tuple.dstPort = bpf_ntohs(BPF_CORE_READ(tcp_data, source));

	struct net_time_Info *net_time_Info = bpf_map_lookup_elem(&net_info_map, &tuple);
	if (net_time_Info != NULL)
	{
		bpf_printk("7-sip:%ld sp:%d dip:%ld \n",tuple.dstIP,tuple.dstPort,tuple.srcIP);
		bpf_printk("7-dp:%d \n",tuple.srcPort);
		net_time_Info->durationTime.dt6 = ts - net_time_Info->time;
		net_time_Info->time = ts;
		net_time_Info->isdel = 0;
	}

		
	return 0;
}

SEC("kprobe/tcp_v4_rcv")
int BPF_KPROBE(tcp_v4_rcv_hook,struct sk_buff *skb)
{
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	u64 ts = bpf_ktime_get_ns();

	struct sock_common skcommon = BPF_CORE_READ(skb,sk,__sk_common);

	struct tuple tuple={};
	tuple.srcIP = skcommon.skc_rcv_saddr;
	tuple.dstIP = skcommon.skc_daddr;
	tuple.srcPort = skcommon.skc_num;
	tuple.dstPort = bpf_ntohs(skcommon.skc_dport);

	struct net_time_Info *net_time_Info = bpf_map_lookup_elem(&net_info_map, &tuple);

	if (net_time_Info != NULL)
	{
		bpf_printk("8-sip:%ld sp:%d dip:%ld \n",tuple.dstIP,tuple.dstPort,tuple.srcIP);
		bpf_printk("8-dp:%d \n",tuple.srcPort);
		net_time_Info->durationTime.dt7 = ts - net_time_Info->time;
		net_time_Info->time = ts;
		net_time_Info->isdel = 1;
	}

	return 0;
}