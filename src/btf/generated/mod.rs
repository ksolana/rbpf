//! eBPF bindings generated by rust-bindgen

#![allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    clippy::all,
    missing_docs
)]

mod btf_internal_bindings;
#[cfg(target_arch = "aarch64")]
mod linux_bindings_aarch64;
#[cfg(target_arch = "x86_64")]
mod linux_bindings_x86_64;

pub use btf_internal_bindings::{bpf_core_relo, bpf_core_relo_kind, btf_ext_header};
#[cfg(target_arch = "aarch64")]
pub use linux_bindings_aarch64::*;
#[cfg(target_arch = "x86_64")]
pub use linux_bindings_x86_64::*;
