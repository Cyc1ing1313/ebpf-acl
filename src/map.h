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
#include "headers/bpf_endian.h"
#include "headers/bpf_helpers.h"
#define MAX_SIZE 1000000

struct action_key {
	__u64 offset;
	__u64 bits;
};

struct action_val {
	__u32 action;
};

struct match_port {
	__u32 port;
};

struct match_proto {
	__u32 proto;
};

struct match_cgroup {
	__u64 cgroup;
};

struct match_mark {
	__u32 mark;
};

struct match_integer_params {
	union {
		struct match_port port;
		struct match_proto proto;
		struct match_cgroup cgroup;
		struct match_mark mark;
	};
	void *map;
	struct match_val *val;
};

struct action_params {
	struct action_key *key;
	void *hash_map;
};

struct match_res {
	struct action_key act_key;
	struct match_val *src;
	struct match_val *dst;
	struct match_val *sport;
	struct match_val *dport;
	// struct match_val *proto;
	// struct match_val *cgroup;
	// struct match_val *mark;
};



struct match_val {
	__u64 bits[8];
};

struct match_addr_hash {
	__u32 ip;
};

struct match_addr_lpm {
	__u32 addr;
	struct bpf_lpm_trie_key key;
};

struct ipv6_addr {
	__u32 ip[4];
};

struct match_addr_params {
	__u32 is_ipv6;
	union {
		__u32 ip;
		__u32 ipv6[4];
	} addr;
	void *hash_map;
	void *lpm_map;
};

struct data_t {
	__u64 rule_id[8];
};

struct bpf_map_def SEC("maps") log_perf = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = 0,
	.max_entries = MAX_SIZE
};

struct bpf_map_def SEC("maps") match_addr_src_hash_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct match_addr_hash),
	.value_size = sizeof(struct match_val),
	.max_entries = MAX_SIZE
};

struct bpf_map_def SEC("maps") match_addr_dst_hash_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct match_addr_hash),
	.value_size = sizeof(struct match_val),
	.max_entries = MAX_SIZE
};

struct bpf_map_def SEC("maps") match_dport_hash_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct match_port),
	.value_size = sizeof(struct match_val),
	.max_entries = MAX_SIZE
};

struct bpf_map_def SEC("maps") match_sport_hash_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct match_port),
	.value_size = sizeof(struct match_val),
	.max_entries = MAX_SIZE
};

struct bpf_map_def SEC("maps") match_action_hash_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct action_key),
	.value_size = sizeof(struct action_val),
	.max_entries = MAX_SIZE
};


struct bpf_map_def SEC("maps") match_proto_hash_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct match_proto),
	.value_size = sizeof(struct match_val),
	.max_entries = MAX_SIZE
};
