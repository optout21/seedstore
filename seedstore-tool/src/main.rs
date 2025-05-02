//! `seedstore-tool` is a command-line utility to create or check secret files.

use seedstore::SeedStoreTool;
use std::env;

/// Top-level executable implementation for seedstore-tool.
fn main() {
    let args: Vec<String> = env::args().collect();
    SeedStoreTool::run(&args);
}
