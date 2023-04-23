#include "map.h"

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