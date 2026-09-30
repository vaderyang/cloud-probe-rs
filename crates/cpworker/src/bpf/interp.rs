//! Safe classic-BPF interpreter.
//!
//! Out-of-bounds loads and unsupported opcodes terminate the program with a
//! drop verdict (return value 0), matching libpcap/kernel `bpf_filter` semantics
//! for truncated frames. Every load is bounds-checked; no `unsafe` is used.

use super::codes::*;
use super::Program;

fn load_be(pkt: &[u8], off: usize, size: usize) -> Option<u32> {
    let end = off.checked_add(size)?;
    let s = pkt.get(off..end)?;
    let mut v = 0u32;
    for &b in s {
        v = (v << 8) | u32::from(b);
    }
    Some(v)
}

/// Execute `prog` against `pkt`, returning the filter verdict (0 = drop).
pub fn run(prog: &Program, pkt: &[u8]) -> u32 {
    let insns = &prog.insns;
    let mut a: u32 = 0;
    let mut x: u32 = 0;
    let mut pc: usize = 0;

    loop {
        let Some(ins) = insns.get(pc) else {
            return 0;
        };
        match ins.code {
            LD_W_ABS => match load_be(pkt, ins.k as usize, 4) {
                Some(v) => a = v,
                None => return 0,
            },
            LD_H_ABS => match load_be(pkt, ins.k as usize, 2) {
                Some(v) => a = v,
                None => return 0,
            },
            LD_B_ABS => match load_be(pkt, ins.k as usize, 1) {
                Some(v) => a = v,
                None => return 0,
            },
            LD_H_IND => {
                let off = x as usize + ins.k as usize;
                match load_be(pkt, off, 2) {
                    Some(v) => a = v,
                    None => return 0,
                }
            }
            LDX_MSH => match load_be(pkt, ins.k as usize, 1) {
                Some(v) => x = (v & 0xf) * 4,
                None => return 0,
            },
            ALU_AND_K => a &= ins.k,
            JMP_JA => {
                pc = pc.wrapping_add(1).wrapping_add(ins.k as usize);
                continue;
            }
            JMP_JEQ_K => {
                pc += 1 + if a == ins.k { ins.jt } else { ins.jf } as usize;
                continue;
            }
            JMP_JGE_K => {
                pc += 1 + if a >= ins.k { ins.jt } else { ins.jf } as usize;
                continue;
            }
            JMP_JGT_K => {
                pc += 1 + if a > ins.k { ins.jt } else { ins.jf } as usize;
                continue;
            }
            JMP_JSET_K => {
                pc += 1 + if a & ins.k != 0 { ins.jt } else { ins.jf } as usize;
                continue;
            }
            RET_K => return ins.k,
            _ => return 0,
        }
        pc += 1;
    }
}

#[cfg(test)]
mod tests {
    //! Hand-built programs, one per opcode.
    //!
    //! The compiler emits only a subset of the instruction shapes (and reuses
    //! the same jump offsets), so a filter compiled from text does not pin down
    //! every interpreter arm. These tests drive [`run`] directly with programs
    //! chosen so each arm is *observable*: each conditional branch sits at index
    //! 1 with fall-through offsets 1 and 2, and the three landing slots return
    //! distinct verdicts, so a wrong jump distance cannot coincidentally land on
    //! the right answer.

    use super::super::{Insn, Program};
    use super::*;

    fn prog(list: &[(u16, u8, u8, u32)]) -> Program {
        Program {
            insns: list
                .iter()
                .map(|&(code, jt, jf, k)| Insn { code, jt, jf, k })
                .collect(),
        }
    }

    /// `prefix` then observe A: verdict 1 when `A == expected`, else 2.
    fn observe_a(prefix: &[(u16, u8, u8, u32)], expected: u32, pkt: &[u8]) -> u32 {
        let mut v = prefix.to_vec();
        v.push((JMP_JEQ_K, 0, 1, expected));
        v.push((RET_K, 0, 0, 1));
        v.push((RET_K, 0, 0, 2));
        prog(&v).evaluate(pkt)
    }

    #[test]
    fn loads_have_the_right_width_and_byte_order() {
        let pkt = [0x11, 0x22, 0x33, 0x44, 0x55];
        assert_eq!(observe_a(&[(LD_W_ABS, 0, 0, 0)], 0x1122_3344, &pkt), 1);
        assert_eq!(observe_a(&[(LD_H_ABS, 0, 0, 1)], 0x2233, &pkt), 1);
        assert_eq!(observe_a(&[(LD_B_ABS, 0, 0, 2)], 0x33, &pkt), 1);
        // A little-endian interpretation must not slip through.
        assert_eq!(observe_a(&[(LD_W_ABS, 0, 0, 0)], 0x4433_2211, &pkt), 2);
    }

    #[test]
    fn out_of_bounds_load_terminates_with_drop() {
        let pkt = [0u8; 3];
        // One byte past the end, and one full width short, for each load.
        assert_eq!(
            prog(&[(LD_B_ABS, 0, 0, 3), (RET_K, 0, 0, 7)]).evaluate(&pkt),
            0
        );
        assert_eq!(
            prog(&[(LD_H_ABS, 0, 0, 2), (RET_K, 0, 0, 7)]).evaluate(&pkt),
            0
        );
        assert_eq!(
            prog(&[(LD_W_ABS, 0, 0, 0), (RET_K, 0, 0, 7)]).evaluate(&pkt),
            0
        );
        // A 1-byte load at the last valid offset still works.
        assert_eq!(
            prog(&[(LD_B_ABS, 0, 0, 2), (RET_K, 0, 0, 7)]).evaluate(&pkt),
            7
        );
    }

    #[test]
    fn alu_and_masks_a() {
        let pkt = [0xab];
        // 0xab & 0x0f == 0x0b; both dropping the arm (A stays 0xab) and `|=`
        // (A becomes 0xaf) are distinguishable.
        assert_eq!(
            observe_a(&[(LD_B_ABS, 0, 0, 0), (ALU_AND_K, 0, 0, 0x0f)], 0x0b, &pkt),
            1
        );
    }

    /// Conditional branch at index 1 with offsets 1 and 2. Normal verdicts:
    /// taken -> 0x222 (index 3), not taken -> 0x333 (index 4). Index 2
    /// (0x111) is where a mutated jump distance lands, which makes an
    /// off-by-one visible instead of harmless.
    fn branch(jcc: u16, k: u32, a: u8) -> u32 {
        prog(&[
            (LD_B_ABS, 0, 0, 0),
            (jcc, 1, 2, k),
            (RET_K, 0, 0, 0x111),
            (RET_K, 0, 0, 0x222),
            (RET_K, 0, 0, 0x333),
        ])
        .evaluate(&[a])
    }

    #[test]
    fn ja_jumps_unconditionally() {
        // `ja 1` skips one instruction; `ja 0` falls through.
        assert_eq!(
            prog(&[
                (LD_B_ABS, 0, 0, 0),
                (JMP_JA, 0, 0, 1),
                (RET_K, 0, 0, 10),
                (RET_K, 0, 0, 20),
            ])
            .evaluate(&[0]),
            20
        );
        assert_eq!(
            prog(&[
                (LD_B_ABS, 0, 0, 0),
                (JMP_JA, 0, 0, 0),
                (RET_K, 0, 0, 10),
                (RET_K, 0, 0, 20),
            ])
            .evaluate(&[0]),
            10
        );
    }

    #[test]
    fn jeq_takes_only_on_equal() {
        assert_eq!(branch(JMP_JEQ_K, 5, 5), 0x222);
        assert_eq!(branch(JMP_JEQ_K, 5, 4), 0x333);
        assert_eq!(branch(JMP_JEQ_K, 5, 6), 0x333);
    }

    #[test]
    fn jge_takes_on_equal_or_greater() {
        assert_eq!(branch(JMP_JGE_K, 5, 5), 0x222);
        assert_eq!(branch(JMP_JGE_K, 5, 6), 0x222);
        assert_eq!(branch(JMP_JGE_K, 5, 4), 0x333);
    }

    #[test]
    fn jgt_takes_only_on_greater() {
        assert_eq!(branch(JMP_JGT_K, 5, 5), 0x333);
        assert_eq!(branch(JMP_JGT_K, 5, 6), 0x222);
        assert_eq!(branch(JMP_JGT_K, 5, 4), 0x333);
    }

    #[test]
    fn jset_takes_on_any_shared_bit() {
        assert_eq!(branch(JMP_JSET_K, 0b0100, 0b0100), 0x222);
        assert_eq!(branch(JMP_JSET_K, 0b0100, 0b0011), 0x333);
        assert_eq!(branch(JMP_JSET_K, 0b0100, 0b1100), 0x222);
    }

    #[test]
    fn x_is_set_from_the_ip_header_length() {
        // pkt[0] = 0x45 -> IHL 5 -> X = 20. Bytes at the offsets a mutated
        // `(v & 0xf) * 4` would read are deliberately different.
        let mut pkt = vec![0u8; 32];
        pkt[0] = 0x45;
        pkt[1] = 0x22;
        pkt[2] = 0x22;
        pkt[9] = 0x11;
        pkt[10] = 0x11;
        pkt[20] = 0xab;
        pkt[21] = 0xcd;
        let p = prog(&[
            (LD_B_ABS, 0, 0, 0),
            (LDX_MSH, 0, 0, 0),
            (LD_H_IND, 0, 0, 0),
            (JMP_JEQ_K, 0, 1, 0xabcd),
            (RET_K, 0, 0, 1),
            (RET_K, 0, 0, 2),
        ]);
        assert_eq!(p.evaluate(&pkt), 1);
    }

    #[test]
    fn indexed_load_adds_k_to_x() {
        let mut pkt = vec![0u8; 32];
        pkt[0] = 0x45; // X = 20
        pkt[18] = 0x99; // where `x - 2` would read
        pkt[19] = 0x99;
        pkt[22] = 0x55;
        pkt[23] = 0x66;
        let p = prog(&[
            (LD_B_ABS, 0, 0, 0),
            (LDX_MSH, 0, 0, 0),
            (LD_H_IND, 0, 0, 2),
            (JMP_JEQ_K, 0, 1, 0x5566),
            (RET_K, 0, 0, 1),
            (RET_K, 0, 0, 2),
        ]);
        assert_eq!(p.evaluate(&pkt), 1);
    }

    #[test]
    fn unknown_opcode_and_falling_off_the_end_drop() {
        // Unsupported opcode.
        assert_eq!(
            prog(&[(0xffff, 0, 0, 0), (RET_K, 0, 0, 7)]).evaluate(&[0]),
            0
        );
        // No RET: running past the last instruction is a drop, not a panic.
        assert_eq!(prog(&[(LD_B_ABS, 0, 0, 0)]).evaluate(&[1]), 0);
    }
}
