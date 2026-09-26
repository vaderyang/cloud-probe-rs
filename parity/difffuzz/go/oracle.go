// Command difforacle is the Go side of the differential fingerprint fuzzer.
//
// It speaks the same line protocol as the C oracles (parity/c_harness.c etc.):
// one request per line on stdin, output lines followed by a `@@END@@` sentinel.
//
// A request is prefixed to select the mode:
//
//	L<0x1F-delimited key/value tokens>   -> common.LabelsToFingerprint(map)
//	J<json TaskConfig>                   -> worker.TaskConfig fingerprint
//
// Both print `Fingerprint.String()` and `Fingerprint.UUID().String()`.
//
// It is compiled by parity/difffuzz.sh against the reference cloud-probe
// sources (the `--sentinel` argument, if present, is ignored).
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/common"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/worker"
)

const sentinel = "@@END@@"

func emit(w *bufio.Writer, f common.Fingerprint) {
	fmt.Fprintln(w, f.String())
	fmt.Fprintln(w, f.UUID().String())
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	for in.Scan() {
		line := in.Text()
		switch {
		case strings.HasPrefix(line, "J"):
			var t worker.TaskConfig
			if err := json.Unmarshal([]byte(line[1:]), &t); err != nil {
				fmt.Fprintln(w, "PARSE_FAIL")
			} else {
				emit(w, common.LabelsToFingerprint(t.FingerPrintLables()))
			}
		case strings.HasPrefix(line, "L"):
			toks := strings.Split(line[1:], "\x1f")
			labels := make(map[string]string)
			// Pair tokens as k,v,k,v…; a trailing key maps to "".
			for i := 0; i < len(toks); i += 2 {
				v := ""
				if i+1 < len(toks) {
					v = toks[i+1]
				}
				labels[toks[i]] = v
			}
			emit(w, common.LabelsToFingerprint(labels))
		}
		fmt.Fprintln(w, sentinel)
		w.Flush()
	}
}
