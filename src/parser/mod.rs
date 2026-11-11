//! Shell parsing utilities for claude-guardrails
//!
//! Provides shell tokenization, wrapper command detection, and AST-based analysis.

pub mod ast;
pub mod command_words;
mod command_words_legacy;
pub mod rm_home;
pub mod shell;
pub mod wrapper;
