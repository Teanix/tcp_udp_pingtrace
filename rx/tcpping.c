#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcpping.skel.h"
#include "tcpping.h"
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

	/*map cat*/
	u64 lookup_key,next_key;
	// struct netInfoSend net;
	struct netInfoSend net2;
	// while(1)
    // {
        while(!exiting && -1 != bpf_map_get_next_key(bpf_map__fd(skel_tcp->maps.netInfo2), &lookup_key, &next_key))
		{
			err = bpf_map_lookup_elem(bpf_map__fd(skel_tcp->maps.netInfo2), &next_key, &net2);
            if(0 == err )
			{
					struct in_addr src_addr,dst_addr;
					src_addr.s_addr = net2.srcIP;
					dst_addr.s_addr = net2.dstIP;
					printf("pid:%ld sip:%s sport:%d dip:%s dport:%d time1:%ld time2:%ld time3:%ld\n",net2.pid
																									,inet_ntoa(src_addr)
																									,net2.srcPort
																									,inet_ntoa(dst_addr)
																									,net2.dstPort
																									,net2.durationTime.dt1
																									,net2.durationTime.dt2
																									,net2.durationTime.dt3
																									);
				
				if(net2.isdel)
					bpf_map_delete_elem(bpf_map__fd(skel_tcp->maps.netInfo2), &next_key);
			}
            lookup_key = next_key;
        }

cleanup:
	tcpping_bpf__destroy(skel_tcp);
	return -err;
}
