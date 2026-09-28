#!/usr/bin/env bash
# Run every differential / fuzz harness. Exits non-zero on the first failure.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================================="
echo " 1/10 packet_split  (parse + fragment + checksums)"
echo "=========================================================="
"$HERE/run.sh" "${PACKET_N:-5000}" "${PACKET_SEED:-42}"

echo "=========================================================="
echo " 2/10 config        (JSON schema + bpf host exclusion)"
echo "=========================================================="
"$HERE/verify_config.sh" "${CONFIG_N:-2000}" "${CONFIG_SEED:-17}"

echo "=========================================================="
echo " 3/10 req_pattern   (custom matcher)"
echo "=========================================================="
"$HERE/verify_req.sh" "${REQ_N:-3000}" "${REQ_SEED:-555}"

echo "=========================================================="
echo " 4/10 protocol      (GRE / VXLAN / ZMQ batch wire bytes)"
echo "=========================================================="
"$HERE/fuzz_proto.sh" "${PROTO_CASES:-60}" "${PROTO_SEEDS:-5}"

echo "=========================================================="
echo " 5/10 unix RPC      (JSON-RPC framing + dispatch)"
echo "=========================================================="
"$HERE/fuzz_rpc.sh"

echo "=========================================================="
echo " 6/10 ZMTP interop  (pure-Rust PUSH -> real libzmq PULL)"
echo "=========================================================="
"$HERE/verify_zmtp.sh"

echo "=========================================================="
echo " 7/10 BPF filter    (pure-Rust compiler vs libpcap)"
echo "=========================================================="
# No seed here on purpose: verify_bpf.sh uses a fixed default corpus (AUDIT4
# P5-27), and BPF_SEED / BPF_PKTS / BPF_EXPRS override it. The sizes are set in
# the environment so a local run and the CI `parity` job exercise the same corpus
# without the default seed being written down twice.
BPF_PKTS="${BPF_PKTS:-800}" BPF_EXPRS="${BPF_EXPRS:-96}" \
    "$HERE/verify_bpf.sh"

echo "=========================================================="
echo " 8/10 API liveness  (implemented-but-never-called guard)"
echo "=========================================================="
bash "$HERE/verify_liveness.sh"

echo "=========================================================="
echo " 9/10 WP4 hygiene   (truncating casts, panic surface, fuzz registration)"
echo "=========================================================="
bash "$HERE/verify_hygiene.sh"

echo "=========================================================="
echo " 10/10 hygiene reverse check (each gate must still catch a rewritten violation)"
echo "=========================================================="
# A gate that can be passed by rewording the violation is worse than no gate,
# because it is quoted as evidence. AUDIT4 P2-3: all four hygiene gates were
# green against an injected copy. This re-inserts each violation in its rewritten
# form and requires the gate to go red.
bash "$HERE/verify_hygiene_reverse.sh"

echo
echo "✅ ALL DIFFERENTIAL HARNESSES PASSED"
