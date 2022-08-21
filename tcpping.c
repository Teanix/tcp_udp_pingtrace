#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcpping.skel.h"
#include "tcpping.h"
#include <linux/tcp.h>
#include <arpa/inet.h>
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}


int main(int argc, char **argv)
{
	struct tcpping_bpf *skel_tcp;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Open BPF application */
	skel_tcp = tcpping_bpf__open();
	if (!skel_tcp) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* ensure BPF program only handles write() syscalls from our process */
	// skel->bss->my_pid = 0;//getpid();

	/* Load & verify BPF programs */
	err = tcpping_bpf__load(skel_tcp);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */ 
	err = tcpping_bpf__attach(skel_tcp);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("===== now is begin =====\n");

	// struct tuple tuple_init;
	// struct net_time_Info net_time_Info_init={};
	// tuple_init.srcIP=16777343;
	// tuple_init.dstIP=16777343;
	// tuple_init.srcPort=12345;
	// tuple_init.dstPort=1234;
	// int res =bpf_map_update_elem(bpf_map__fd(skel_tcp->maps.net_info_map), &tuple_init, &net_time_Info_init, BPF_ANY);
	// printf("res:%d\n",res);


	struct tuple lookup_key,next_key;
	char str[100];
	char str1[100];
	struct net_time_Info net_time_Info;

        while(!exiting && -1 != bpf_map_get_next_key(bpf_map__fd(skel_tcp->maps.net_info_map), &lookup_key, &next_key))
		{
			err = bpf_map_lookup_elem(bpf_map__fd(skel_tcp->maps.net_info_map), &next_key, &net_time_Info);
            if(0 == err &&net_time_Info.durationTime.dt7!=0 )// &&net_time_Info.durationTime.dt7!=0 && net_time_Info.time!=0 
			{
				struct in_addr saddr,daddr;
				saddr.s_addr = net_time_Info.tuple.srcIP;
				daddr.s_addr = net_time_Info.tuple.dstIP;
				printf("pid:%ld s:%s sp:%d d:%s dp:%d time1:%ld time2:%ld time3:%ld time4:%ld time5:%ld time6:%ld time7:%ld\n"
												,net_time_Info.pid
												,inet_ntop(AF_INET,&saddr.s_addr,str,sizeof(str))
												,net_time_Info.tuple.srcPort
												,inet_ntop(AF_INET,&daddr.s_addr,str1,sizeof(str1))
												,net_time_Info.tuple.dstPort
												,net_time_Info.durationTime.dt1
												,net_time_Info.durationTime.dt2
												,net_time_Info.durationTime.dt3
												,net_time_Info.durationTime.dt4
												,net_time_Info.durationTime.dt5
												,net_time_Info.durationTime.dt6
												,net_time_Info.durationTime.dt7
												);
			}
			if(net_time_Info.isdel)
				bpf_map_delete_elem(bpf_map__fd(skel_tcp->maps.net_info_map), &next_key);
            lookup_key = next_key;
        }

cleanup:
	tcpping_bpf__destroy(skel_tcp);
	return -err;
}
