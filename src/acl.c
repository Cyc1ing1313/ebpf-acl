//go:build ignore
#include <stdio.h>
#include <string.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <linux/icmp.h>
#include <linux/pkt_cls.h>
#include "./match.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("tc/acl")
int acl_match(struct __sk_buff *skb) {
	// bpf_printk("recv packet");
	void *data = (void*)(long)skb->data;
	void *data_end = (void*)(long)skb->data_end;
	struct match_addr_params addr_param;
	struct match_integer_params int_param;
	struct ethhdr *ethhdr;
	struct iphdr *iph;
	struct match_res res;
	struct match_val *mv;
	// struct ipv6hdr *ipv6h;
	
	ethhdr = data;
	if (data+sizeof(struct ethhdr) > data_end) {
		return TC_ACT_OK;
	}

	memset(&addr_param,0,sizeof(addr_param));
	addr_param.is_ipv6 = (ethhdr->h_proto == ETH_P_IPV6);

	if (addr_param.is_ipv6) {
		// ipv6h = data +  sizeof(struct ethhdr);
		// if (data+sizeof(struct ethhdr)+sizeof(struct ipv6hdr) > data_end) {
		// 	return TC_ACT_OK;
		// }
		// memcpy(addr_param.addr.ipv6,ipv6h->addrs.daddr.__in6_u.__u6_addr32,sizeof(__u32)*4);
		return TC_ACT_OK;
	} else {
		iph = data + sizeof(struct ethhdr);
		if (data+sizeof(struct ethhdr)+sizeof(struct iphdr) > data_end) {
			return TC_ACT_OK;
		}
		struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
		if (data + sizeof(struct ethhdr) + sizeof(struct iphdr)+sizeof(struct icmphdr) > data_end) {
			return TC_ACT_OK;
		}
		bpf_printk("icmp type %d",icmp->type);
		if (icmp->type == ICMP_ECHO) {
			bpf_printk("icmp packet %d -> %d",ntohl(iph->addrs.saddr),ntohl(iph->addrs.daddr));
		}
		addr_param.addr.ip = ntohl(iph->addrs.daddr);
	}
	addr_param.hash_map = &match_addr_dst_hash_map;


	mv = addr_match(&addr_param);
	if (mv == NULL) {
		return TC_ACT_OK;
	}
	res.dst = mv;


	addr_param.addr.ip = ntohl(iph->addrs.saddr);
	addr_param.hash_map = &match_addr_src_hash_map;

	mv = addr_match(&addr_param);
	if (mv == NULL) {
		return TC_ACT_OK;
	}
	res.src = mv;


	memset(&int_param, 0, sizeof(int_param));



	struct data_t log = {
		.rule_id = {0}
	};


	struct action_key a_k;
	memset(&a_k, 0, sizeof(a_k));
	for(int i=0;i<8;i++) {
		log.rule_id[i] =  ((res.dst->bits[i]) & (res.src->bits[i]));
		if (log.rule_id[i]) {
			a_k.offset = i;
			a_k.bits = log.rule_id[i];
			res.act_key = a_k;
			bpf_printk("offset %d bit %llu", i,log.rule_id[i]);
		}
	}

	struct action_params action_param = {
		.key = &a_k,
		.hash_map = &match_action_hash_map
	};

	bpf_perf_event_output(skb,&log_perf,0,&log,sizeof(struct data_t));
	return do_action(&action_param);
}


