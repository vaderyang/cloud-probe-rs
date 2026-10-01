/*
 * cprs_dpdk_shim: the C side of the feature-gated DPDK pdump capturer.
 *
 * Several helpers the Rust declarative bindings call are `static
 * __rte_always_inline` in the DPDK headers and are therefore *not* exported by
 * the DPDK shared libraries, so a direct link fails with an undefined symbol.
 * The most important one is `rte_ring_sc_dequeue_burst_elem` (rte_ring_elem.h),
 * the single missing symbol on DPDK 23.11 — verified with `nm -D`: zero hits in
 * librte_ring. `rte_pktmbuf_free_bulk` and `rte_pcapng_mbuf_size` are inline on
 * older DPDK (21.11/22.11) and exported on 23.11, so they are wrapped too and
 * the compiler keeps only what the link actually needs.
 *
 * This translation unit renames each inline on include and re-exports it under
 * the exact name the Rust `extern "C"` block declares, so `--features dpdk`
 * links without patching DPDK. `build.rs` compiles it when the feature is on.
 */

#define rte_ring_sc_dequeue_burst_elem rte_ring_sc_dequeue_burst_elem_inline
#include <rte_ring_elem.h>
#undef rte_ring_sc_dequeue_burst_elem

unsigned int
rte_ring_sc_dequeue_burst_elem(struct rte_ring *r, void **obj_table,
                               unsigned int esize, unsigned int n,
                               unsigned int *available)
{
    return rte_ring_sc_dequeue_burst_elem_inline(r, obj_table, esize, n, available);
}
