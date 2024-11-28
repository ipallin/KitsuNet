mod network;
mod client;
mod client5g;
mod server;

use client::run_client;
use client5g::run_5gclient;
use server::run_server;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} --client | --5gclient | --server", args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "--client" => run_client(),
        "--server" => run_server(),
        "--5gclient" => run_5gclient(),
        _ => {
            eprintln!("Invalid argument: {}. Use --client or --server.", args[1]);
            std::process::exit(1);
        }
    }
}