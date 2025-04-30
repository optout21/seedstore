//! Executable shell for seedstore-tool

use seedstore::SeedStoreTool;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    SeedStoreTool::run(&args);
}
