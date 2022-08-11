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
	__type(value, struct netInfoRcv);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} netInfo2 SEC(".maps");

//tx
// SEC("kprobe/tcp_sendmsg")
// int BPF_KPROBE(tcp_sendmsg,struct sock *sock)
// {
// 	u64 pid,ts;

// 	pid = bpf_get_current_pid_tgid() >> 32;
// 	ts = bpf_ktime_get_ns();

// 	struct sock_common skcommon;
// 	skcommon = BPF_CORE_READ(sock,__sk_common);

// 	struct netInfoSend net;
// 	net.pid = pid;
// 	net.time =ts;
// 	net.srcIP = skcommon.skc_rcv_saddr;
// 	net.dstIP =skcommon.skc_daddr;
// 	net.srcPort = skcommon.skc_num; 
// 	net.dstPort = bpf_htons(skcommon.skc_dport);
// 	net.durationTime.dt1 = 0;
// 	net.durationTime.dt2 = 0;
// 	net.durationTime.dt3 = 0;
// 	net.isdel=0;
// 	if(net.dstPort==1234)
// 		bpf_map_update_elem(&netInfo,&pid,&net,BPF_ANY);
// 	return 0;
// }

// SEC("kprobe/ip_local_out")
// int BPF_KPROBE(ip_local_out,struct sock *sk)
// {
// 	u64 pid;
// 	pid = bpf_get_current_pid_tgid() >> 32;
// 	struct netInfoSend *net = bpf_map_lookup_elem(&netInfo, &pid);
// 	if(net!=NULL)
// 	{
// 		net->durationTime.dt1 = bpf_ktime_get_ns()- net->time;
// 		net->isdel=0;
// 	}
// 	return 0;
// }

// SEC("kprobe/ip_finish_output")
// int BPF_KPROBE(ip_finish_output,struct sk_buff *skb)
// {
// 	u64 pid;
// 	pid = bpf_get_current_pid_tgid() >> 32;
// 	struct netInfoSend *net = bpf_map_lookup_elem(&netInfo, &pid);
// 	if(net!=NULL)
// 	{
// 		net->durationTime.dt2 = bpf_ktime_get_ns()- net->time;
// 		net->isdel=0;
// 	}
// 	return 0;
// }

// SEC("kprobe/__dev_queue_xmit")
// int BPF_KPROBE(__dev_queue_xmit,struct sk_buff *skb)
// {
// 	u64 pid;
// 	pid = bpf_get_current_pid_tgid() >> 32;
// 	struct netInfoSend *net = bpf_map_lookup_elem(&netInfo, &pid);
// 	if(net!=NULL)
// 	{
// 		net->durationTime.dt3 = bpf_ktime_get_ns()- net->time;
// 		net->isdel=1;
// 	}
// 	return 0;
// }


// struct netif_rx_args
// {
// 	uint64_t pad;
// 	struct sk_buff *skb;
// };
// SEC("tp/net/netif_receive_skb")
// int netif_receive_skb_hook(struct netif_rx_args *args)
// {
// 	u64 pid = bpf_get_current_pid_tgid() >> 32;
// 	// u64 ts = bpf_ktime_get_ns();
// 	// struct sock *sk = BPF_CORE_READ(skb,sk);
// 	// struct sock_common skcommon = BPF_CORE_READ(sk,__sk_common);
	
// 	struct sk_buff *myskb = args->skb;
// 	// struct sock_common skcommon = BPF_CORE_READ(myskb,sk,__sk_common);
// 	if(myskb)
// 	bpf_printk("pid:%ld saddr:%px  %ld\n",pid//daddr:%ld sport:%d dport:%d
// 														,myskb
// 														,myskb->data_len
// 														// ,skcommon.skc_daddr
// 														// ,skcommon.skc_num
// 														// ,bpf_htons(skcommon.skc_dport);
// 														);
// 	return 0;
// }

//rx
SEC("kretprobe/__netif_receive_skb")
int BPF_KRETPROBE(__netif_receive_skb,struct sk_buff *skb)
{
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	u64 ts = bpf_ktime_get_ns();
	struct sock_common skcommon = BPF_CORE_READ(skb,sk,__sk_common);

		struct netInfoRcv net;
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
		bpf_map_update_elem(&netInfo2,&pid,&net,BPF_ANY);
	// bpf_printk("pid:%ld saddr:%ld daddr:%ld sport:%d dport:%d\n",pid
	// 													,skcommon.skc_rcv_saddr
	// 													,skcommon.skc_daddr
	// 													,skcommon.skc_num
	// 													,bpf_htons(skcommon.skc_dport)
	// 													);
	return 0;
}

// SEC("kprobe/ip_rcv_finish")
// int BPF_KPROBE(ip_rcv_finish,struct sk_buff *skb)
// {
// 	int pid = bpf_get_current_pid_tgid() >> 32;
// 	u64 time = bpf_ktime_get_ns();
// 	bpf_printk("[-3]ip_rcv_finish - PID:%d time:%ld\n",pid,time);
// 	return 0;
// }

// SEC("kprobe/ip_local_deliver_finish")
// int BPF_KPROBE(ip_local_deliver_finish,struct sk_buff *skb)
// {
// 	int pid = bpf_get_current_pid_tgid() >> 32;
// 	u64 time = bpf_ktime_get_ns();
// 	bpf_printk("[-2]ip_local_deliver_finish - PID:%d time:%ld\n",pid,time);
// 	return 0;
// }

// SEC("kprobe/tcp_v4_rcv")
// int BPF_KPROBE(tcp_v4_rcv,struct sk_buff *skb)
// {
// 	int pid = bpf_get_current_pid_tgid() >> 32;
// 	u64 time = bpf_ktime_get_ns();
// 	bpf_printk("[-1]tcp_v4_rcv - PID:%d time:%ld\n",pid,time);
// 	return 0;
// }






