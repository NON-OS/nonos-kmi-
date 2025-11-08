#![deny(clippy::all)]
#![deny(rust_2018_idioms)]
#![allow(deprecated)]

pub mod app;
pub mod crypto;
pub mod crypto_provider;
pub mod crypto_harness;
pub mod gdb;
pub mod kernel;
pub mod monitor;
pub mod nonos;
pub mod streaming;
pub mod system;
pub mod ui;
pub mod visualization;

pub use crate::app::App;
