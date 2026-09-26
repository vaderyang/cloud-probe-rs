//! Classic BPF (cBPF) opcode constants, matching `linux/filter.h`.
//!
//! Only the opcodes actually emitted by [`super::compiler`] (and handled by
//! [`super::interp`]) are defined here.

pub const BPF_LD: u16 = 0x00;
pub const BPF_LDX: u16 = 0x01;
pub const BPF_ALU: u16 = 0x04;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;

pub const BPF_W: u16 = 0x00;
pub const BPF_H: u16 = 0x08;
pub const BPF_B: u16 = 0x10;

pub const BPF_ABS: u16 = 0x20;
pub const BPF_IND: u16 = 0x40;
pub const BPF_MSH: u16 = 0xa0;

pub const BPF_AND: u16 = 0x50;

pub const BPF_JA: u16 = 0x00;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;

pub const BPF_K: u16 = 0x00;

/// `ldh [k]` (absolute, 16-bit).
pub const LD_H_ABS: u16 = BPF_LD | BPF_H | BPF_ABS;
/// `ld [k]` (absolute, 32-bit).
pub const LD_W_ABS: u16 = BPF_LD | BPF_W | BPF_ABS;
/// `ldb [k]` (absolute, 8-bit).
pub const LD_B_ABS: u16 = BPF_LD | BPF_B | BPF_ABS;
/// `ldh [x + k]` (indexed, 16-bit).
pub const LD_H_IND: u16 = BPF_LD | BPF_H | BPF_IND;
/// `ldxb 4*([k]&0xf)` (load IP header length into X).
pub const LDX_MSH: u16 = BPF_LDX | BPF_B | BPF_MSH;
/// `and #k`.
pub const ALU_AND_K: u16 = BPF_ALU | BPF_AND | BPF_K;
/// `jeq #k`.
pub const JMP_JEQ_K: u16 = BPF_JMP | BPF_JEQ | BPF_K;
/// `jge #k`.
pub const JMP_JGE_K: u16 = BPF_JMP | BPF_JGE | BPF_K;
/// `jgt #k`.
pub const JMP_JGT_K: u16 = BPF_JMP | BPF_JGT | BPF_K;
/// `jset #k`.
pub const JMP_JSET_K: u16 = BPF_JMP | BPF_JSET | BPF_K;
/// `ja k`.
pub const JMP_JA: u16 = BPF_JMP | BPF_JA;
/// `ret #k`.
pub const RET_K: u16 = BPF_RET | BPF_K;
