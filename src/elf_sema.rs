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
    static_analysis::Analysis,
};

use alloc::{
    borrow::{Cow, ToOwned as _},
    format,
    string::String,
    vec,
    vec::Vec,
};

use std::collections::{HashMap, BTreeMap};

/// Semantic analysis of eBPF programs with attached BTF.
#[derive(PartialEq, Eq, Clone, Default)]
pub struct Sema {
    /// Functions in the executable
    pub functions: BTreeMap<usize, (u32, String)>,
    /// Function Name -> BtfType
    pub fn_symbol_table : HashMap<String, BtfType>,
    /// Insn Address -> BtfType
    pub insn_symbol_table : HashMap<String, BtfType>,
}

impl Sema {
    ///
    pub fn clone(functions: BTreeMap<usize, (u32, String)>,
        fn_symbol_table : HashMap<String, BtfType>,
        insn_symbol_table : HashMap<String, BtfType>) -> Self {
        Sema {
            functions,
            fn_symbol_table,
            insn_symbol_table
        }
    }

    pub fn build_cfg(bpf_function : (u32, (&[u8], usize))) {

    }

    pub fn build_prog_cfg(function_registry: &FunctionRegistry<usize>) {
        for bpf_function in function_registry.iter() {
            Self::build_cfg(bpf_function);
        }
    }
    /// Get all the functions in a binary
    pub fn get_functions(&mut self, function_registry: &FunctionRegistry<usize>, prog_len : usize) {
        let mut functions = BTreeMap::new();
        for (key, (function_name, pc)) in function_registry.iter() {
            functions.insert(
                pc,
                (key, String::from_utf8_lossy(function_name).to_string()),
            );
        }
        debug_assert!(
            prog_len % ebpf::INSN_SIZE == 0,
            "eBPF program length must be a multiple of {:?} octets is {:?}",
            ebpf::INSN_SIZE,
            prog_len
        );
    }
    /// Infer type of an instruction based on its operand and available context.
    pub fn infer_type(&mut self, insn : &ebpf::Insn, insn_ptr : usize) -> Result<BtfType, VerifierError> {
        match insn.opc {
            ebpf::LD_DW_IMM  => {},

            // BPF_LDX class
            ebpf::LD_B_REG   => {},
            ebpf::LD_H_REG   => {},
            ebpf::LD_W_REG   => {},
            ebpf::LD_DW_REG  => {},

            // BPF_ST class
            ebpf::ST_B_IMM   => {},
            ebpf::ST_H_IMM   => {},
            ebpf::ST_W_IMM   => {},
            ebpf::ST_DW_IMM  => {},

            // BPF_STX class
            ebpf::ST_B_REG   => {},
            ebpf::ST_H_REG   => {},
            ebpf::ST_W_REG   => {},
            ebpf::ST_DW_REG  => {},

            // BPF_ALU class
            ebpf::ADD32_IMM  => {},
            ebpf::ADD32_REG  => {},
            ebpf::SUB32_IMM  => {},
            ebpf::SUB32_REG  => {},
            ebpf::MUL32_IMM  => {},
            ebpf::MUL32_REG  => {},
            ebpf::DIV32_IMM  => {},
            ebpf::DIV32_REG  => {},
            ebpf::OR32_IMM   => {},
            ebpf::OR32_REG   => {},
            ebpf::AND32_IMM  => {},
            ebpf::AND32_REG  => {},
            ebpf::LSH32_IMM  => {},
            ebpf::LSH32_REG  => {},
            ebpf::RSH32_IMM  => {},
            ebpf::RSH32_REG  => {},
            ebpf::NEG32      => {},
            ebpf::MOD32_IMM  => {},
            ebpf::MOD32_REG  => {},
            ebpf::XOR32_IMM  => {},
            ebpf::XOR32_REG  => {},
            ebpf::MOV32_IMM  => {},
            ebpf::MOV32_REG  => {},
            ebpf::ARSH32_IMM => {},
            ebpf::ARSH32_REG => {},
            ebpf::LE         => {},
            ebpf::BE         => {},

            // BPF_ALU64 class
            ebpf::ADD64_IMM  => {},
            ebpf::ADD64_REG  => {},
            ebpf::SUB64_IMM  => {},
            ebpf::SUB64_REG  => {},
            ebpf::MUL64_IMM  => {},
            ebpf::MUL64_REG  => {},
            ebpf::DIV64_IMM  => {},
            ebpf::DIV64_REG  => {},
            ebpf::OR64_IMM   => {},
            ebpf::OR64_REG   => {},
            ebpf::AND64_IMM  => {},
            ebpf::AND64_REG  => {},
            ebpf::LSH64_IMM  => {},
            ebpf::LSH64_REG  => {},
            ebpf::RSH64_IMM  => {},
            ebpf::RSH64_REG  => {},
            ebpf::NEG64      => {},
            ebpf::MOD64_IMM  => {},
            ebpf::MOD64_REG  => {},
            ebpf::XOR64_IMM  => {},
            ebpf::XOR64_REG  => {},
            ebpf::MOV64_IMM  => {},
            ebpf::MOV64_REG  => {},
            ebpf::ARSH64_IMM => {},
            ebpf::ARSH64_REG => {},
            ebpf::HOR64_IMM  => {},

            // BPF_PQR class
            ebpf::LMUL32_IMM => {},
            ebpf::LMUL32_REG => {},
            ebpf::LMUL64_IMM => {},
            ebpf::LMUL64_REG => {},
            ebpf::UHMUL64_IMM => {},
            ebpf::UHMUL64_REG => {},
            ebpf::SHMUL64_IMM => {},
            ebpf::SHMUL64_REG => {},
            ebpf::UDIV32_IMM => {},
            ebpf::UDIV32_REG => {},
            ebpf::UDIV64_IMM => {},
            ebpf::UDIV64_REG => {},
            ebpf::UREM32_IMM => {},
            ebpf::UREM32_REG => {},
            ebpf::UREM64_IMM => {},
            ebpf::UREM64_REG => {},
            ebpf::SDIV32_IMM => {},
            ebpf::SDIV32_REG => {},
            ebpf::SDIV64_IMM => {},
            ebpf::SDIV64_REG => {},
            ebpf::SREM32_IMM => {},
            ebpf::SREM32_REG => {},
            ebpf::SREM64_IMM => {},
            ebpf::SREM64_REG => {},

            // BPF_JMP class
            ebpf::JA         => {},
            ebpf::JEQ_IMM    => {},
            ebpf::JEQ_REG    => {},
            ebpf::JGT_IMM    => {},
            ebpf::JGT_REG    => {},
            ebpf::JGE_IMM    => {},
            ebpf::JGE_REG    => {},
            ebpf::JLT_IMM    => {},
            ebpf::JLT_REG    => {},
            ebpf::JLE_IMM    => {},
            ebpf::JLE_REG    => {},
            ebpf::JSET_IMM   => {},
            ebpf::JSET_REG   => {},
            ebpf::JNE_IMM    => {},
            ebpf::JNE_REG    => {},
            ebpf::JSGT_IMM   => {},
            ebpf::JSGT_REG   => {},
            ebpf::JSGE_IMM   => {},
            ebpf::JSGE_REG   => {},
            ebpf::JSLT_IMM   => {},
            ebpf::JSLT_REG   => {},
            ebpf::JSLE_IMM   => {},
            ebpf::JSLE_REG   => {},
            ebpf::CALL_IMM   => {},
            ebpf::CALL_REG   => {},
            ebpf::EXIT       => {},
            _                => {
                return Err(VerifierError::UnknownOpCode(insn.opc, insn_ptr));
            }
        }
        Ok(BtfType::Unknown)
    }
    /// Build symbol table of prog.
    /// * `prog` - The SBPF program.
    /// * `sbpf_version` - Version.
    /// * `function_registry` - List of function start and end.
    pub fn build_symtab(&mut self, prog: &[u8], btf: Btf, sbpf_version: &SBPFVersion, function_registry: &FunctionRegistry<usize>, analysis: &Analysis) -> Result<(), VerifierError> {
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
            match self.infer_type(&insn, insn_ptr) {
                Ok(ty) => {
                    if ty == BtfType::Unknown {
                        return Err(VerifierError::UnknownOpCode(insn.opc, insn_ptr));
                    } else {
                        self.insn_symbol_table.insert(insn_ptr.to_string(), ty.clone());
                    }
                }
                Err(_) => return Err(VerifierError::UnknownBtfType(insn_ptr)),
            };
        }
        Ok(())
    }
}