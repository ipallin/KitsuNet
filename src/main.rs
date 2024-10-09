use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};
use std::net::{IpAddr, Ipv4Addr, TcpStream, SocketAddr, UdpSocket};
use std::io::{Read, Write};
use std::env;
use pcap::Capture;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::datalink::NetworkInterface;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::util::checksum;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::TcpListener;
use std::fs;
use serde::Deserialize;
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

fn set_ipv4_checksum(packet: &mut MutableIpv4Packet) {
    packet.set_checksum(0);
}

fn set_tcp_checksum(ipv4_packet: &Ipv4Packet, tcp_packet: &mut MutableTcpPacket) {
    tcp_packet.set_checksum(0);
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

fn find_interface(name: &str) -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();
    for iface in interfaces {
        if iface.name == name {
            return Some(iface);
        }
    }
    None
}

fn get_source_ip(interface: &NetworkInterface) -> Option<IpAddr> {
    for ip in &interface.ips {
        if let IpAddr::V4(ipv4) = ip.ip() {
            return Some(IpAddr::V4(ipv4));
        }
    }
    None
}
fn create_socket() -> TcpListener {
    let listener = TcpListener::bind(("0.0.0.0", 2404)).expect("Failed to bind to port 2404");
    listener
}

/* // Antigua función de crear socket (Deprecated)
fn create_socket(remote_ip: Ipv4Addr, remote_port: u16) -> TcpStream {
    loop {
        match TcpStream::connect((remote_ip, remote_port)) {
            Ok(socket) => return socket,
            Err(e) => {
                eprintln!("Failed to connect to remote socket: {}. Retrying...", e);
                thread::sleep(Duration::from_secs(5));
            }
        }
    }
}
*/

fn create_bound_socket(remote_ip: &str, remote_port: u16, local_iface: &str) -> std::io::Result<TcpStream> {
    let remote_addr = format!("{}:{}", remote_ip, remote_port);
    let remote_socket_addr: SocketAddr = remote_addr.parse().unwrap();

    // Crea socket
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.bind_device(Some(local_iface.as_bytes()))?;
    socket.connect(&remote_socket_addr.into())?;

    // Convierte el socket en un TcpStream
    let stream: TcpStream = socket.into();
    Ok(stream)
}

fn process_pcap(file_path: &str, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, interface: &NetworkInterface, mut socket: TcpStream) {
    loop {
        let mut cap = match Capture::from_file(file_path) {
            Ok(cap) => cap,
            Err(e) => {
                eprintln!("Failed to open PCAP file: {}. Retrying...", e);
                thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        let (mut tx, _rx) = match datalink::channel(interface, Default::default()) {
            Ok(Ethernet(tx, _rx)) => (tx, _rx),
            Ok(_) => {
                eprintln!("Unhandled channel type. Retrying...");
                thread::sleep(Duration::from_secs(5));
                continue;
            }
            Err(e) => {
                eprintln!("Failed to create datalink channel: {}. Retrying...", e);
                thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        while let Ok(packet) = cap.next_packet() {
            let payload = packet.data;

            if payload.len() < EthernetPacket::minimum_packet_size() {
                println!("Packet too small, skipping.");
                continue;
            }

            if let Some(ethernet_packet) = EthernetPacket::new(payload) {
                if ethernet_packet.get_ethertype() == pnet::packet::ethernet::EtherTypes::Ipv4 {
                    if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                        if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                            if tcp_packet.get_destination() == 2404 {
                                let mut ipv4_buffer = vec![0u8; Ipv4Packet::minimum_packet_size() + ipv4_packet.payload().len()];
                                let mut new_ipv4_packet = match MutableIpv4Packet::new(&mut ipv4_buffer) {
                                    Some(packet) => packet,
                                    None => {
                                        eprintln!("Failed to create mutable IPv4 packet. Retrying...");
                                        thread::sleep(Duration::from_secs(5));
                                        continue;
                                    }
                                };

                                new_ipv4_packet.set_version(4); 
                                new_ipv4_packet.set_header_length(5);
                                new_ipv4_packet.set_total_length((Ipv4Packet::minimum_packet_size() + ipv4_packet.payload().len()) as u16);
                                new_ipv4_packet.set_ttl(64); 
                                new_ipv4_packet.set_next_level_protocol(ipv4_packet.get_next_level_protocol());

                                new_ipv4_packet.clone_from(&ipv4_packet);

                                new_ipv4_packet.set_source(src_ip);
                                new_ipv4_packet.set_destination(dst_ip);
                                set_ipv4_checksum(&mut new_ipv4_packet); // Calculate and set IPv4 checksum

                                println!("--- IPv4 Layer ---");
                                println!("Source IP: {:?}", new_ipv4_packet.get_source());
                                println!("Destination IP: {:?}", new_ipv4_packet.get_destination());
                                println!("Protocol: {:?}", new_ipv4_packet.get_next_level_protocol());
                                println!("Checksum: {:?}", new_ipv4_packet.get_checksum());

                                if let Some(mut tcp_packet) = MutableTcpPacket::new(new_ipv4_packet.payload_mut()) {
                                    set_tcp_checksum(&ipv4_packet, &mut tcp_packet); // Calculate and set TCP checksum
                                    println!("--- TCP Layer ---");
                                    println!("Source Port: {:?}", tcp_packet.get_source());
                                    println!("Destination Port: {:?}", tcp_packet.get_destination());
                                    println!("Sequence Number: {:?}", tcp_packet.get_sequence());
                                    println!("Acknowledgment Number: {:?}", tcp_packet.get_acknowledgement());
                                    println!("Flags: {:?}", tcp_packet.get_flags());
                                } else if let Some(udp_packet) = UdpPacket::new(new_ipv4_packet.payload()) {
                                    println!("--- UDP Layer ---");
                                    println!("Source Port: {:?}", udp_packet.get_source());
                                    println!("Destination Port: {:?}", udp_packet.get_destination());
                                    println!("Length: {:?}", udp_packet.get_length());
                                    println!("Checksum: {:?}", udp_packet.get_checksum());
                                }

                                println!("IPv4 Packet: {:?}", ipv4_packet);
                                println!("Ethernet Packet: {:?}", ethernet_packet);
                                println!("TCP Packet: {:?}", TcpPacket::new(ipv4_packet.payload()).unwrap());

                                println!("New IPv4 Packet: {:?}", new_ipv4_packet);

                                // Send 
                                if let Some(Err(e)) = tx.send_to(new_ipv4_packet.packet(), None) {
                                    eprintln!("Failed to send packet: {}. Retrying...", e);
                                    thread::sleep(Duration::from_secs(5));
                                    continue;
                                }

                                // Send the packet through the TCP socket
                                if let Err(e) = socket.write_all(new_ipv4_packet.packet()) {
                                    eprintln!("Failed to send packet through TCP socket: {}. Retrying...", e);
                                    thread::sleep(Duration::from_secs(5));
                                    continue;
                                }

                                // Print the entire sent packet data in hexadecimal format
                                let sent_packet_hex: String = new_ipv4_packet.packet().iter().map(|byte| format!("{:02x}", byte)).collect();
                                println!("Sent Packet Data: {}", sent_packet_hex);
                            } else {
                                // Listen on the socket and skip one PCAP row for each packet received
                                let mut buffer = [0; 1024];
                                socket.set_read_timeout(Some(Duration::from_secs(10))).expect("Failed to set read timeout");
                                match socket.read(&mut buffer) {
                                    Ok(_) => {
                                        println!("Received packet on socket, skipping one PCAP row.");
                                        continue;
                                    }
                                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                        println!("Timeout reached, skipping to the next packet.");
                                        continue;
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to read from socket: {}. Retrying...", e);
                                        thread::sleep(Duration::from_secs(5));
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}


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

fn run_client() {
    println!("Running in client mode");
    /* // Variables hardcodeadas (solo para debbuging)
    let pcap_file = "industroyer2.pcap";
    let remote_ip = Ipv4Addr::new(192, 168, 10, 3);
    let remote_port = 2404;
    let local_iface = "uesimtun0";
    */
    let config_content = fs::read_to_string("config.toml").expect("Failed to read config.toml");
    let config: Config = toml::from_str(&config_content).expect("Failed to parse config.toml");

    let client_config = config.client;

    let pcap_file = client_config.pcap_file;
    let remote_ip = client_config.remote_ip;
    let remote_port = client_config.remote_port;
    let local_iface = client_config.local_iface;

    //let interface_name = "uesimtun0";
    let interface = loop {
        match find_interface(&local_iface) {
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

    // Crea el socket TCP
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
    println!("Socket created and connected to {}:{} from {}:{}", remote_ip, remote_port, local_addr.ip(), local_addr.port());

    // Empieza a mandar tráfico (quitar para debbuging)
    process_pcap(&pcap_file, source_ip, remote_ip, &interface, socket);
}


fn run_5gclient() {
    println!("Running in client mode");
    /* // Variables hardcodeadas (solo para debbuging)
    let pcap_file = "industroyer2.pcap";
    let remote_ip = Ipv4Addr::new(192, 168, 10, 3);
    let remote_port = 2404;
    let local_iface = "uesimtun0";
    */
    let config_content = fs::read_to_string("config.toml").expect("Failed to read config.toml");
    let config: Config = toml::from_str(&config_content).expect("Failed to parse config.toml");

    let client_config = config.client;

    let pcap_file = client_config.pcap_file;
    let remote_ip = client_config.remote_ip;
    let remote_port = client_config.remote_port;
    let local_iface = client_config.local_iface;

    let ueransim_thread = thread::spawn(|| {
        loop {
            println!("Interface 'uesimtun0' not found. Re-executing 'build/nr-ue'...");
            execute_command();
            thread::sleep(Duration::from_secs(5));
        }
    });
    
    // Empezar antes de ejecutar el otro hilo
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

    // Crea el socket TCP
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
    println!("Socket created and connected to {}:{} from {}:{}", remote_ip, remote_port, local_addr.ip(), local_addr.port());

    // Empieza a mandar tráfico (quitar para debbuging)
    process_pcap(&pcap_file, source_ip, remote_ip, &interface, socket);

    // Esto hay que mejorarlo
    ueransim_thread.join().unwrap();
}





fn run_server() {
    println!("Running in server mode");
    let config_content = fs::read_to_string("config.toml").expect("Failed to read config.toml");
    let config: Config = toml::from_str(&config_content).expect("Failed to parse config.toml");

    let server_config = config.server;

    let pcap_file = server_config.pcap_file;
    let local_iface = server_config.local_iface;
    //let pcap_file = "industroyer2.pcap";
    //let interface_name = "ens4";
    let interface = find_interface(&local_iface).expect("Network interface not found");
    let source_ip = get_source_ip(&interface).expect("Failed to get source IP");

    let source_ip = match source_ip {
        IpAddr::V4(ipv4) => ipv4,
        _ => panic!("Expected an IPv4 address"),
    };

    // Create the socket
    let listener = create_socket();
    println!("Server listening on port 2404");

    for stream in listener.incoming() {
        match stream {
            Ok(socket) => {
                // Extract the client's IP address and port from the socket
                let client_addr = match socket.peer_addr() {
                    Ok(addr) => addr,
                    Err(e) => {
                        println!("Failed to get client address: {}", e);
                        continue;
                    }
                };
                
                let client_ip = match client_addr.ip() {
                    IpAddr::V4(ipv4) => ipv4,
                    _ => panic!("Expected an IPv4 address from the client"),
                };

                let client_port = client_addr.port();

                println!("New connection from client IP: {}, Port: {}", client_ip, client_port);
                // Handle the connection and use client's IP and port as the destination
                process_pcap(&pcap_file, source_ip, client_ip, &interface, socket);
            }
            Err(e) => {
                println!("Connection failed: {}", e);
            }
        }
    }
}