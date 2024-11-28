use crate::network::{create_bound_socket, find_interface, get_source_ip};
use crate::pcap::process_pcap;
use serde::Deserialize;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use std::process::Command;
use std::time::Duration;
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

pub fn run_5gclient() {
    println!("Running in client mode");
    let config_content = fs::read_to_string("config.toml").expect("Failed to read config.toml");
    let config: Config = toml::from_str(&config_content).expect("Failed to parse config.toml");

    let client_config = config.client;

    let pcap_file = client_config.pcap_file;
    let remote_ip = client_config.remote_ip;
    let remote_port = client_config.remote_port;
    let local_iface = client_config.local_iface;

    let ueransim_thread = thread::spawn(|| loop {
        println!("Interface 'uesimtun0' not found. Re-executing 'build/nr-ue'...");
        execute_command();
        thread::sleep(Duration::from_secs(5));
    });

    thread::sleep(Duration::from_secs(15));

    let interface_name = "uesimtun0";
    let interface = loop {
        match find_interface(interface_name) {
            Some(iface) => break iface,
            None => {
                eprintln!("Network interface not found. Retrying...");
                thread::sleep(Duration::from_secs(5));
            }
        }
    };

    let source_ip = loop {
        match get_source_ip(&interface) {
            Some(ip) => break ip,
            None => {
                eprintln!("Failed to get source IP. Retrying...");
                thread::sleep(Duration::from_secs(5));
            }
        }
    };

    let source_ip = match source_ip {
        IpAddr::V4(ipv4) => ipv4,
        _ => panic!("Expected an IPv4 address"),
    };

    let socket = loop {
        match create_bound_socket(&remote_ip.to_string(), remote_port, &local_iface) {
            Ok(socket) => break socket,
            Err(e) => {
                eprintln!("Failed to connect to remote socket: {}. Retrying...", e);
                thread::sleep(Duration::from_secs(5));
            }
        }
    };
    let local_addr = socket.local_addr().expect("Failed to get local address");
    println!(
        "Socket created and connected to {}:{} from {}:{}",
        remote_ip,
        remote_port,
        local_addr.ip(),
        local_addr.port()
    );

    process_pcap(&pcap_file, source_ip, remote_ip, &interface, socket);

    ueransim_thread.join().unwrap();
}

fn execute_command() {
    println!("Executing 'build/nr-ue' command...");
    Command::new("sudo")
        .arg("ueransim/build/nr-ue")
        .arg("-c")
        .arg("ueransim/config/open5gs-ue.yaml")
        .status()
        .expect("Failed to execute 'build/nr-ue'");
}