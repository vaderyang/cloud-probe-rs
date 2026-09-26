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
