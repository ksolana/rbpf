//! Semantic analyzer of ebpf binary with btf information.
//! the first function_range.start is the start of function. this will have entry in btf.

// the argumenet types will also have entry in btf.
// at the end r0 will have the return value.
// Other than this we have to reconstruct the type of everything else.
// let btf_type = btf.get_btftype(&insn).unwrap();

// use the `BtfTypes::resolve_type` to get type from a type_id.
// you can assume that you'll get the type id of the function prototype of the function you're verifying
// Look at FuncProto and BTF_KIND_FUNC_PROTO, add a function that returns type_id based on a FuncProto.
// if you want to get it now while testing, you need to iterate over all the btf types, and look for a func proto that matches the name of the function you're verifying
// https://github.com/aya-rs/aya/blob/373fb7bf06ba80ee4c120d8c112f5e810204c472/aya-obj/src/btf/btf.rs#L279
// hash<fn, type_id>
//! let program_range = 0..prog.len() / ebpf::INSN_SIZE;

// Fucntion registry has list of function start and end.
// key (int) -> name of the function. in BTF we can retried type from the name of the function.
// TODO: Build a table (function name -> btf type) as line-info may not be present.

use crate::{
    ebpf,
    btf::{btf::*, types::BtfType},
    program::{FunctionRegistry, SBPFVersion},
    verifier::VerifierError,
    vm::Config,
};

use alloc::{
    borrow::{Cow, ToOwned as _},
    format,
    string::String,
    vec,
    vec::Vec,
};

use std::collections::HashMap;

/// Semantic analysis of eBPF programs with attached BTF.
#[derive(PartialEq, Eq, Clone, Default)]
pub struct Sema {
    /// Function Name -> BtfType
    pub fn_symbol_table : HashMap<String, BtfType>,
    /// Insn Address -> BtfType
    pub insn_symbol_table : HashMap<String, BtfType>,
}

impl Sema {
    ///
    pub fn new(fn_symbol_table : HashMap<String, BtfType>,
        insn_symbol_table : HashMap<String, BtfType>) -> Self {
        Sema {
            fn_symbol_table,
            insn_symbol_table
        }
    }
    /// Build symbol table of prog.
    pub fn build_symtab(prog: &[u8], sbpf_version: &SBPFVersion, function_registry: &FunctionRegistry<usize>) -> Result<(), VerifierError>{
        let program_range = 0..prog.len() / ebpf::INSN_SIZE;
        let mut function_iter = function_registry.keys().map(|insn_ptr| insn_ptr as usize).peekable();
        let mut function_range = program_range.start..program_range.end;
        let mut insn_ptr: usize = 0;
        while (insn_ptr + 1) * ebpf::INSN_SIZE <= prog.len() {
            let insn = ebpf::get_insn(prog, insn_ptr);
            let mut store = false;

            if sbpf_version.static_syscalls() && function_iter.peek() == Some(&insn_ptr) {
                function_range.start = function_iter.next().unwrap_or(0);
                function_range.end = *function_iter.peek().unwrap_or(&program_range.end);
                let end_insn = ebpf::get_insn(prog, function_range.end.saturating_sub(1));
                match end_insn.opc {
                    ebpf::JA | ebpf::EXIT => {},
                    _ =>  return Err(VerifierError::InvalidFunction(
                        function_range.end.saturating_sub(1),
                    )),
                }
            }
        }
        Ok(())
    }
}