#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libnet.h>

int main(int argc, char *argv[])

{

    char send_msg[1000] = "";
    char err_buf[100] = "";
    int lens = 0;

    libnet_t *lib_net = NULL;
    libnet_ptag_t lib_t = 0;

    unsigned char src_mac[6] = {0xd8, 0xbb, 0xc1, 0xde, 0xc0, 0x5e}; //发送者网卡地址 d8:bb:c1:de:c0:5e
    unsigned char dst_mac[6] = {0xd8, 0xbb, 0xc1, 0xde, 0xc0, 0x5e}; //接收者网卡地址 d8:bb:c1:de:c0:5e

    char *src_ip_str = "127.0.0.1"; //源主机IP
    char *dst_ip_str = "127.0.0.1";//目的主机IP

    unsigned long src_ip, dst_ip = 0;


    lib_net = libnet_init(LIBNET_LINK_ADV, NULL, err_buf); //初始化 

    if (NULL == lib_net)
    {
        perror("libnet_init error!");
        exit(-1);
    }

    src_ip = libnet_name2addr4(lib_net, src_ip_str, LIBNET_RESOLVE); //将字符串类型的ip转换为顺序网络字节流 
    dst_ip = libnet_name2addr4(lib_net, dst_ip_str, LIBNET_RESOLVE);



    /*构造TCP数据包*/
    u_char payload[64] = {0}; /* 承载数据的数组，初值为空 */
	u_long payload_len = 0; /* 承载数据的长度，初值为0 */

    strncpy((char *)payload, "a", sizeof(payload)-1); /* 构造负载的内容 */
    u_short proto = IPPROTO_TCP; /* 传输层协议 */
    payload_len = strlen((char *)payload);
    int seq = 0;
    int ack = 0;
    
    int len = LIBNET_TCP_H+ payload_len;
    
    lib_t = libnet_build_tcp(12345,1234,seq,ack,TH_SYN,0,0,0,len,payload,payload_len,lib_net,0);

    lib_t =libnet_build_ipv4(
				LIBNET_IPV4_H + LIBNET_TCP_H + payload_len, /* IP协议块的总长,*/
				0, /* tos */
				(u_short) libnet_get_prand(LIBNET_PRu32), /* id,随机产生0~65535 */
				0, /* frag 片偏移 */
				(u_int8_t)libnet_get_prand(LIBNET_PR8), /* ttl,随机产生0~255 */
				proto, /* 上层协议 */
				0, /* 校验和，此时为0，表示由Libnet自动计算 */
				src_ip, /* 源IP地址,网络序 */
				dst_ip, /* 目标IP地址,网络序 */
				NULL, /* 负载内容或为NULL */
				0, /* 负载内容的大小*/
				lib_net, /* Libnet句柄 */
				0 /* 协议块标记可修改或创建,0表示构造一个新的*/
				);
    lib_t = libnet_build_ethernet((u_int8_t *)dst_mac, (u_int8_t *)src_mac, 0x800, NULL, 0, lib_net, 0); //构造以太网数据包 

    int res = 0;
    res = libnet_write(lib_net); //发送数据包 
    if (-1 == res)
    {
        perror("libnet tx error");
        exit(-1);
    }

    libnet_destroy(lib_net); //销毁资源 
    printf("----ok-----\n");
    return 0;
}