#include "headers/bpf_helpers.h"
#include "map.h"
#include <linux/pkt_cls.h>

static inline struct match_val *addr_match(struct match_addr_params *param) {
	struct match_val *val;
	if (!param->hash_map) {
		return NULL;
	}
	if (!(val=(struct match_val *)bpf_map_lookup_elem(param->hash_map,&param->addr.ip))) {
		// struct match_addr_lpm key;
		// key.addr =param->addr.ip;
		// key.key.prefixlen = 32;
		// val = (struct match_val*)bpf_map_lookup_elem(param->lpm_map,&key);
		return NULL;
	}
	return val;
}


static inline struct match_val *integer_match(struct match_integer_params *param) {
	struct match_val *val;
	if (!param->map) {
		return NULL;
	}
	if (!(val=(struct match_val *)bpf_map_lookup_elem(param->map,&param->port))) {
		return NULL;
	}
	return val;
}

static inline __u32 do_action(struct action_params *param) {
	struct action_val *val;
	if (!param->hash_map) {
		return TC_ACT_OK;
	}
	if (!(val=(struct action_val *)bpf_map_lookup_elem(param->hash_map,param->key))) {
		return TC_ACT_OK;
	}
	bpf_printk("action %lu", val->action);
	return val->action;
}