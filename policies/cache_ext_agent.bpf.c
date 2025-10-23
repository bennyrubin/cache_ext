#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

// EVOLVE-BLOCK-START

static u64 cold_list;   /* first-touch pages */
static u64 hot_list;    /* re-used pages */

static inline bool is_folio_relevant(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;

	return inode_in_watchlist(folio->mapping->host->i_ino);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(agent_init, struct mem_cgroup *memcg)
{
	/* create two separate lists: cold and hot */
	cold_list = bpf_cache_ext_ds_registry_new_list(memcg);
	hot_list  = bpf_cache_ext_ds_registry_new_list(memcg);
	if (cold_list == 0 || hot_list == 0) {
		bpf_printk("cache_ext: init: Failed to create lists\n");
		return -1;
	}
	bpf_printk("cache_ext: Created lists: cold=%llu hot=%llu\n",
		   cold_list, hot_list);

	return 0;
}

static int bpf_agent_evict_cb(int idx, struct cache_ext_list_node *a)
{
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(agent_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	/* evict only from the cold list, preserving hot pages */
	if (bpf_cache_ext_list_iterate(memcg, cold_list, bpf_agent_evict_cb, eviction_ctx) < 0) {
		bpf_printk("cache_ext: evict: Failed to iterate cold_list\n");
		return;
	}
}

void BPF_STRUCT_OPS(agent_folio_evicted, struct folio *folio) {
	// if (bpf_cache_ext_list_del(folio)) {
	// 	bpf_printk("cache_ext: Failed to delete folio from list\n");
	// 	return;
	// }
}

void BPF_STRUCT_OPS(agent_folio_added, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;

	/* If the folio was already tracked, remove it from whichever list.   */
	bool already_tracked = (bpf_cache_ext_list_del(folio) == 0);

	if (already_tracked) {
		/* Second (or later) touch – keep in the hot list. */
		if (bpf_cache_ext_list_add_tail(hot_list, folio))
			bpf_printk("cache_ext: added: Failed to re-add to hot_list\n");
		return;
	}

	/* First time we see the folio – insert into the cold list. */
	if (bpf_cache_ext_list_add_tail(cold_list, folio))
		bpf_printk("cache_ext: added: Failed to add folio to cold_list\n");
}

SEC(".struct_ops.link")
struct cache_ext_ops agent_ops = {
	.init = (void *)agent_init,
	.evict_folios = (void *)agent_evict_folios,
	.folio_evicted = (void *)agent_folio_evicted,
	.folio_added = (void *)agent_folio_added,
};
// EVOLVE-BLOCK-END
