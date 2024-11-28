use crate::network::{create_socket, find_interface, get_source_ip};
use crate::pcap::process_pcap;
use serde::Deserialize;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::thread;
use toml;

#[derive(Debug, Deserialize)]
struct Config {
    client: ClientConfig,
    server: ServerConfig,
}

#[derive(Debug, Deserialize)]
struct ClientConfig {
    pcap_file: String,
    remote_ip: Ipv4Addr,
    remote_port: u16,
    local_iface: String,
}

#[derive(Debug, Deserialize)]
struct ServerConfig {
    pcap_file: String,
    local_iface: String,
}

pub fn run_server() {
    println!("Running in server mode");
    let config_content = fs::read_to_string("config.toml").expect("Failed to read config.toml");
    let config: Config = toml::from_str(&config_content).expect("Failed to parse config.toml");

    let server_config = config.server;

    let pcap_file = Arc::new(server_config.pcap_file);
    let local_iface = server_config.local_iface;
    let interface = find_interface(&local_iface).expect("Network interface not found");
    let source_ip = get_source_ip(&interface).expect("Failed to get source IP");

    let source_ip = match source_ip {
        IpAddr::V4(ipv4) => ipv4,
        _ => panic!("Expected an IPv4 address"),
    };

    let listener = create_socket();
    println!("Server listening on port 2404");

    let interface = Arc::new(interface);
    let source_ip = Arc::new(source_ip);

    for stream in listener.incoming() {
        match stream {
            Ok(socket) => {
                let pcap_file = Arc::clone(&pcap_file);
                let interface = Arc::clone(&interface);
                let source_ip = Arc::clone(&source_ip);

                thread::spawn(move || {
                    let client_addr = match socket.peer_addr() {
                        Ok(addr) => addr,
                        Err(e) => {
                            println!("Failed to get client address: {}", e);
                            return;
                        }
                    };

                    let client_ip = match client_addr.ip() {
                        IpAddr::V4(ipv4) => ipv4,
                        _ => panic!("Expected an IPv4 address from the client"),
                    };

                    let client_port = client_addr.port();

                    println!(
                        "New connection from client IP: {}, Port: {}",
                        client_ip, client_port
                    );

                    process_pcap(&pcap_file, *source_ip, client_ip, &interface, socket);
                });
            }
            Err(e) => {
                println!("Connection failed: {}", e);
            }
        }
    }
}