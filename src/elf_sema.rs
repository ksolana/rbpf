//! Semantic analyzer of ebpf binary with btf information.

// BTF provides minimal type information.
// - The function_range.start (start of function) has entry in btf.
// - The argument types has entry in btf.
// - At the end r0 will have the return value.
//
// Other than this we have to reconstruct the type of everything else.
// use the `BtfTypes::resolve_type` to get type from a type_id.
// We can assume that we'll get the type id of the function prototype
// of the function you're verifying. Look at FuncProto and BTF_KIND_FUNC_PROTO.
// Add a function that returns type_id based on a FuncProto.
//
// Btf::types() returns an  impl Iterator<Item = &BtfType>.
// This can also be used but maybe inefficient because we'll have to iterate
// over all types and find the matching function.
// https://github.com/aya-rs/aya/blob/373fb7bf06ba80ee4c120d8c112f5e810204c472/aya-obj/src/btf/btf.rs#L279
//
// key (int) -> name of the function. in BTF we can retried type from the name of the function.
// TODO: Build a table (function name -> btf type) as line-info may not be present.
// TODO: Build a cfg. Look at static_analysis.rs::split_into_basic_blocks
// TODO: Build a def-use chain to track types.

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
    /// * `prog` - The SBPF program.
    /// * `sbpf_version` - Version.
    /// * `function_registry` - List of function start and end.
    pub fn build_symtab(&mut self, prog: &[u8], btf: Btf, sbpf_version: &SBPFVersion, function_registry: &FunctionRegistry<usize>) -> Result<(), VerifierError> {
        let program_range = 0..prog.len() / ebpf::INSN_SIZE;
        // TODO: Why iterate over keys, we should just query function_registry for the insn_ptr.
        // function_iter gets a list of all the function addresses in sorted order.
        let mut function_iter = function_registry.keys().map(|insn_ptr| insn_ptr as usize).peekable();
        let mut function_range = program_range.start..program_range.end;
        let insn_ptr: usize = 0;
        while (insn_ptr + 1) * ebpf::INSN_SIZE <= prog.len() {
            let insn = ebpf::get_insn(prog, insn_ptr);

            // An insn_ptr points to the end of a function when it has value in function_iter.
            if sbpf_version.static_syscalls() && function_iter.peek() == Some(&insn_ptr) {
                // function_range contains the current function start and end pointers.
                function_range.start = function_iter.next().unwrap_or(0);
                // FIXME: Does it work when function_range.end == program_range.end?
                function_range.end = *function_iter.peek().unwrap_or(&program_range.end);
                let exit_insn_ptr_val = function_range.end.saturating_sub(1);
                let end_insn = ebpf::get_insn(prog, exit_insn_ptr_val);
                match end_insn.opc { // function_end must have a `ja` or `exit`.
                    ebpf::JA | ebpf::EXIT => {},
                    _ =>  return Err(VerifierError::InvalidFunction(
                        exit_insn_ptr_val,
                    )),
                }
                // Entry of the function will have a BtfType in BTF section.
                // e.g., [1] FUNC_PROTO '(anon)' ret_type_id=2 vlen=1 '(anon)' type_id=2
                let fentry_btf_type = btf.get_btftype(&insn).unwrap();
                // Last instruction in the function has the return type.
                let fexit_btf_type = btf.get_btftype(&end_insn).unwrap();
                let entry_insn_ptr_val = insn_ptr as u32;
                let exit_insn_ptr_val_u32 = exit_insn_ptr_val as u32;
                self.fn_symbol_table.insert(function_registry.map.get(&entry_insn_ptr_val).unwrap().1.to_string(), fentry_btf_type.clone());
                self.fn_symbol_table.insert(function_registry.map.get(&exit_insn_ptr_val_u32).unwrap().1.to_string(), fexit_btf_type.clone());
            }
        }
        Ok(())
    }
}