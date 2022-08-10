#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tcpping.h"
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
struct netInfo *sc;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__type(key, u64);
	__type(value, struct netInfoData);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} netInfo SEC(".maps");


//tx
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg,struct sock *sock)
{
	u64 pid,ts;

	pid = bpf_get_current_pid_tgid() >> 32;
	ts = bpf_ktime_get_ns();

	struct sock_common skcommon;
	skcommon = BPF_CORE_READ(sock,__sk_common);
	u16 srcPort=skcommon.skc_num;

	struct netInfoData net;
	net.pid = pid;
	net.time =ts;
	net.srcIP = skcommon.skc_rcv_saddr;
	net.dstIP =skcommon.skc_daddr;
	net.srcPort = skcommon.skc_num; 
	net.dstPort = bpf_htons(skcommon.skc_dport);
	net.durationTime.dt1 = 0;
	net.durationTime.dt2 = 0;
	net.durationTime.dt3 = 0;
	net.isdel=0;
	if(net.dstPort==1234)
		bpf_map_update_elem(&netInfo,&pid,&net,BPF_ANY);
	return 0;
}

SEC("kprobe/ip_local_out")
int BPF_KPROBE(ip_local_out,struct sock *sk)
{
	u64 pid;
	pid = bpf_get_current_pid_tgid() >> 32;
	struct netInfoData *net = bpf_map_lookup_elem(&netInfo, &pid);
	if(net!=NULL)
	{
		net->durationTime.dt1 = bpf_ktime_get_ns()- net->time;
		net->isdel=0;
	}
	return 0;
}

SEC("kprobe/ip_finish_output")
int BPF_KPROBE(ip_finish_output,struct sk_buff *skb)
{
	u64 pid;
	pid = bpf_get_current_pid_tgid() >> 32;
	struct netInfoData *net = bpf_map_lookup_elem(&netInfo, &pid);
	if(net!=NULL)
	{
		net->durationTime.dt2 = bpf_ktime_get_ns()- net->time;
		net->isdel=0;
	}
	return 0;
}

SEC("kprobe/__dev_queue_xmit")
int BPF_KPROBE(__dev_queue_xmit,struct sk_buff *skb)
{
	u64 pid;
	pid = bpf_get_current_pid_tgid() >> 32;
	struct netInfoData *net = bpf_map_lookup_elem(&netInfo, &pid);
	if(net!=NULL)
	{
		net->durationTime.dt3 = bpf_ktime_get_ns()- net->time;
		net->isdel=1;
	}
	return 0;
}


//rx
