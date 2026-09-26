#!/usr/bin/env bash
# Run every differential / fuzz harness. Exits non-zero on the first failure.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================================="
echo " 1/7 packet_split  (parse + fragment + checksums)"
echo "=========================================================="
"$HERE/run.sh" "${PACKET_N:-5000}" "${PACKET_SEED:-42}"

echo "=========================================================="
echo " 2/7 config        (JSON schema + bpf host exclusion)"
echo "=========================================================="
"$HERE/verify_config.sh" "${CONFIG_N:-2000}" "${CONFIG_SEED:-17}"

echo "=========================================================="
echo " 3/7 req_pattern   (custom matcher)"
echo "=========================================================="
"$HERE/verify_req.sh" "${REQ_N:-3000}" "${REQ_SEED:-555}"

echo "=========================================================="
echo " 4/7 protocol      (GRE / VXLAN / ZMQ batch wire bytes)"
echo "=========================================================="
"$HERE/fuzz_proto.sh" "${PROTO_CASES:-60}" "${PROTO_SEEDS:-5}"

echo "=========================================================="
echo " 5/7 unix RPC      (JSON-RPC framing + dispatch)"
echo "=========================================================="
"$HERE/fuzz_rpc.sh"

echo "=========================================================="
echo " 6/7 ZMTP interop  (pure-Rust PUSH -> real libzmq PULL)"
echo "=========================================================="
"$HERE/verify_zmtp.sh"

echo "=========================================================="
echo " 7/7 BPF filter    (pure-Rust compiler vs libpcap)"
echo "=========================================================="
"$HERE/verify_bpf.sh" "${BPF_SEED:-$RANDOM}" "${BPF_PKTS:-800}" "${BPF_EXPRS:-96}"

echo
echo "✅ ALL DIFFERENTIAL HARNESSES PASSED"
