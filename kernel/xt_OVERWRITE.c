/*
   Module to overwrite arbitrary sections of packets
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include "../ipt_OVERWRITE.h"

MODULE_AUTHOR("Nick Huber <nhuber@securityinnovation.com>");
MODULE_DESCRIPTION("Xtables: Overwrite arbitary section of packet target");
MODULE_LICENSE("GPL");

//Generalized checksum algorithm
unsigned short csum (unsigned short *buf, int nwords)
{
	unsigned long sum;
	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

//replaces TCP/UDP checksum offload
static void update_csum(struct sk_buff *skb)
{

	struct iphdr *ip_header;

	ip_header = ip_hdr(skb);
	skb->ip_summed = CHECKSUM_NONE; //stop offloading
	skb->csum_valid = 0;
	ip_header->check = 0;
	ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);


	if(skb_is_nonlinear(skb))
		skb_linearize(skb);

	//TCP checksum
	if (ip_header->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph;
		unsigned int tcplen;

		tcph = tcp_hdr(skb);
		skb->csum =0;
		tcplen = ntohs(ip_header->tot_len) - ip_header->ihl*4;
		tcph->check = 0;
		tcph->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char *)tcph, tcplen, 0));
		//UDP checksum
	} else if (ip_header->protocol == IPPROTO_UDP) {
		struct udphdr *udph;
		unsigned int udplen;

		udph = udp_hdr(skb);
		skb->csum =0;
		udplen = ntohs(ip_header->tot_len) - ip_header->ihl*4;
		udph->check = 0;
		udph->check = udp_v4_check(udplen,ip_header->saddr, ip_header->daddr,csum_partial((char *)udph, udplen, 0));
	}
}

static unsigned int overwrite_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct ipt_OVERWRITE_info *info = par->targinfo;
	struct iphdr *iph;
	char *buf;
	char *tail;
	char* layer4;
	int i;
	char offload;

	//Ensure the socket buffer is writable
	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;

	//Lay out some useful pointers
	iph = ip_hdr(skb);
	buf = (char *)skb->data;
	tail = skb_tail_pointer(skb);
	layer4 = buf + sizeof(struct iphdr);
	offload = info->offload;

	//Overwrite the packet with the pattern here
	for (i = 0; i < info->patlen; i++){
		if (buf + info->offset + i > tail){
			//printk("OVERWRITE: attempted to write past end of user defined data, aborted");
			break;
		}
		buf[info->offset + i] = info->pattern[i]; //dangerous, actually writes the pattern
	}

	//Dealing with layer 4 checksums
	if (iph->protocol == 1){
		//most NICs dont offer ICMP hardware checksumming so I do it here
		skb->ip_summed = CHECKSUM_NONE; //disables offloading
		iph->check = 0;
		iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
		*((unsigned short *)(layer4 + 2)) = 0;
		*((unsigned short *)(layer4 + 2)) = csum((unsigned short *)layer4, (tail-layer4)/2);	
	} else if (!offload){
		update_csum(skb);
	}
	return XT_CONTINUE;
}

static int overwrite_tg_check(const struct xt_tgchk_param *par)
{
	return 0;
}

//Defines object to be registered against x_tables
static struct xt_target overwrite_tg_reg __read_mostly = {
	.name       = "OVERWRITE",
	.revision   = 0,
	.family     = NFPROTO_IPV4,
	.target     = overwrite_tg,
	.targetsize = sizeof(struct ipt_OVERWRITE_info),
	.table      = "mangle",
	.checkentry = overwrite_tg_check,
	.me         = THIS_MODULE,
};

static int __init overwrite_tg_init(void)
{
	return xt_register_target(&overwrite_tg_reg);
}

static void __exit overwrite_tg_exit(void)
{
	xt_unregister_target(&overwrite_tg_reg);
}

module_init(overwrite_tg_init);
module_exit(overwrite_tg_exit);
MODULE_ALIAS("ipt_OVERWRITE");
