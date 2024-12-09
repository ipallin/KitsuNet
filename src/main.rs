use libc::sleep;
use pcap::Capture;
use pnet::datalink::NetworkInterface;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::{MutablePacket, Packet};
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::process::Command;
use std::thread;
use std::time::Duration;
use toml;
use std::sync::Arc;
use std::sync::Mutex;
use std::error::Error;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::util::MacAddr;

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
    port: u16,
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

fn create_socket(port: u16) -> TcpListener {
    let listener = TcpListener::bind(("0.0.0.0", port)).expect("Failed to bind to port");
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

fn create_bound_socket(
    remote_ip: &str,
    remote_port: u16,
    local_iface: &str,
) -> std::io::Result<TcpStream> {
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

fn process_pcap(
    file_path: &str,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    interface: &NetworkInterface,
    mut socket: TcpStream,
) -> Result<(), Box<dyn Error>> {
    loop {
        let mut cap: Capture<pcap::Offline> = Capture::from_file(file_path)?;

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
            // Parse the original packet
            let ethernet_packet = EthernetPacket::new(packet.data).unwrap();
            let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload()).unwrap();
            let tcp_packet = TcpPacket::new(ipv4_packet.payload()).unwrap();

            // Extract the application layer
            let application_layer = tcp_packet.payload();

            // Create new link layer
            let mut new_ethernet_packet = MutableEthernetPacket::owned(vec![0u8; ethernet_packet.packet().len()]).unwrap();
            new_ethernet_packet.set_destination(MacAddr::new(0, 0, 0, 0, 0, 1));
            new_ethernet_packet.set_source(MacAddr::new(0, 0, 0, 0, 0, 2));
            new_ethernet_packet.set_ethertype(ethernet_packet.get_ethertype());

            // Create new internet layer
            let mut new_ipv4_packet = MutableIpv4Packet::owned(vec![0u8; ipv4_packet.packet().len()]).unwrap();
            new_ipv4_packet.set_version(4);
            new_ipv4_packet.set_header_length(5);
            new_ipv4_packet.set_total_length(ipv4_packet.get_total_length());
            new_ipv4_packet.set_ttl(64);
            new_ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            new_ipv4_packet.set_source(src_ip);
            new_ipv4_packet.set_destination(dst_ip);

            // Create new transport layer
            let mut new_tcp_packet = MutableTcpPacket::owned(vec![0u8; tcp_packet.packet().len()]).unwrap();
            new_tcp_packet.set_source(tcp_packet.get_source());
            new_tcp_packet.set_destination(tcp_packet.get_destination());
            new_tcp_packet.set_sequence(tcp_packet.get_sequence());
            new_tcp_packet.set_acknowledgement(tcp_packet.get_acknowledgement());
            new_tcp_packet.set_data_offset(tcp_packet.get_data_offset());
            new_tcp_packet.set_flags(tcp_packet.get_flags());
            new_tcp_packet.set_window(tcp_packet.get_window());
            new_tcp_packet.set_checksum(tcp_packet.get_checksum());
            new_tcp_packet.set_urgent_ptr(tcp_packet.get_urgent_ptr());

            // Set the application layer
            new_tcp_packet.set_payload(application_layer);

            // Combine all layers into a new packet
            new_ipv4_packet.set_payload(new_tcp_packet.packet());
            new_ethernet_packet.set_payload(new_ipv4_packet.packet());

            // Send the new packet
            tx.send_to(new_ethernet_packet.packet(), None)
                .ok_or("Failed to send packet")?;

            // Send the payload through the TCP socket
            socket.write_all(application_layer)?;
            thread::sleep(Duration::from_secs(1));

            // Print the entire sent packet data in hexadecimal format
            let sent_packet_hex: String = new_ethernet_packet
                .packet()
                .iter()
                .map(|byte| format!("{:02x}", byte))
                .collect::<Vec<String>>()
                .join(" ");
            println!("Sent Packet: {}", sent_packet_hex);
        }

        println!("Reached end of PCAP file, restarting...");
    }
}

/* Antigua función de procesar PCAP (Deprecated)
fn process_pcap(
    file_path: &str,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    interface: &NetworkInterface,
    mut socket: TcpStream,
) -> Result<(), Box<dyn Error>> {
    loop {
        let mut cap: Capture<pcap::Offline> = Capture::from_file(file_path)?;

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
                                let mut ipv4_buffer = vec![
                                    0u8;
                                    Ipv4Packet::minimum_packet_size()
                                        + ipv4_packet.payload().len()
                                ];
                                let mut new_ipv4_packet =
                                    MutableIpv4Packet::new(&mut ipv4_buffer)
                                        .ok_or("Failed to create mutable IPv4 packet")?;

                                new_ipv4_packet.set_version(4);
                                new_ipv4_packet.set_header_length(5);
                                new_ipv4_packet.set_total_length(
                                    (Ipv4Packet::minimum_packet_size()
                                        + ipv4_packet.payload().len())
                                        as u16,
                                );
                                new_ipv4_packet.set_ttl(64);
                                new_ipv4_packet
                                    .set_next_level_protocol(ipv4_packet.get_next_level_protocol());

                                new_ipv4_packet.clone_from(&ipv4_packet);

                                new_ipv4_packet.set_source(src_ip);
                                new_ipv4_packet.set_destination(dst_ip);
                                set_ipv4_checksum(&mut new_ipv4_packet); // Calculate and set IPv4 checksum

                                println!("--- IPv4 Layer ---");
                                println!("Source IP: {:?}", new_ipv4_packet.get_source());
                                println!("Destination IP: {:?}", new_ipv4_packet.get_destination());
                                println!(
                                    "Protocol: {:?}",
                                    new_ipv4_packet.get_next_level_protocol()
                                );
                                println!("Checksum: {:?}", new_ipv4_packet.get_checksum());

                                if let Some(mut tcp_packet) =
                                    MutableTcpPacket::new(new_ipv4_packet.payload_mut())
                                {
                                    set_tcp_checksum(&ipv4_packet, &mut tcp_packet); // Calculate and set TCP checksum
                                    println!("--- TCP Layer ---");
                                    println!("Source Port: {:?}", tcp_packet.get_source());
                                    println!(
                                        "Destination Port: {:?}",
                                        tcp_packet.get_destination()
                                    );
                                    println!("Sequence Number: {:?}", tcp_packet.get_sequence());
                                    println!(
                                        "Acknowledgment Number: {:?}",
                                        tcp_packet.get_acknowledgement()
                                    );
                                    println!("Flags: {:?}", tcp_packet.get_flags());
                                } else if let Some(udp_packet) =
                                    UdpPacket::new(new_ipv4_packet.payload())
                                {
                                    println!("--- UDP Layer ---");
                                    println!("Source Port: {:?}", udp_packet.get_source());
                                    println!(
                                        "Destination Port: {:?}",
                                        udp_packet.get_destination()
                                    );
                                    println!("Length: {:?}", udp_packet.get_length());
                                    println!("Checksum: {:?}", udp_packet.get_checksum());
                                }

                                println!("IPv4 Packet: {:?}", ipv4_packet);
                                println!("Ethernet Packet: {:?}", ethernet_packet);
                                println!(
                                    "TCP Packet: {:?}",
                                    TcpPacket::new(ipv4_packet.payload()).unwrap()
                                );

                                println!("New IPv4 Packet: {:?}", new_ipv4_packet);

                                // Send
                                tx.send_to(new_ipv4_packet.packet(), None)
                                    .ok_or("Failed to send packet")?;

                                // Send the packet through the TCP socket
                                socket.write_all(new_ipv4_packet.packet())?;

                                // Print the entire sent packet data in hexadecimal format
                                let sent_packet_hex: String = new_ipv4_packet
                                    .packet()
                                    .iter()
                                    .map(|byte| format!("{:02x}", byte))
                                    .collect();
                                println!("Sent Packet Data: {}", sent_packet_hex);
                            } else {
                                // Listen on the socket and skip one PCAP row for each packet received
                                let mut buffer = [0; 1024];
                                socket.set_read_timeout(Some(Duration::from_secs(10)))?;
                                match socket.read(&mut buffer) {
                                    Ok(_) => {
                                        println!(
                                            "Received packet on socket, skipping one PCAP row."
                                        );
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
}*/

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} --client | --5gclient | --server [--config <FILE>]", args[0]);
        std::process::exit(1);
    }

    let mut config_file = "config/config.toml";
    let mut mode = "";

    for i in 1..args.len() {
        match args[i].as_str() {
            "--client" => mode = "client",
            "--server" => mode = "server",
            "--5gclient" => mode = "5gclient",
            "--config" => {
                if i + 1 < args.len() {
                    config_file = &args[i + 1];
                } else {
                    eprintln!("Usage: {} --client | --5gclient | --server [--config <FILE>]", args[0]);
                    std::process::exit(1);
                }
            }
            _ => {}
        }
    }

    if mode.is_empty() {
        eprintln!("Invalid argument. Use --client, --server, or --5gclient.");
        std::process::exit(1);
    }

    println!("Using config file: {}", config_file);

    // Load the config file
    let config_content = fs::read_to_string(config_file)
        .expect("Failed to read config file");

    match mode {
        "client" => run_client(config_file),
        "server" => run_server(config_file),
        "5gclient" => run_5gclient(config_file),
        _ => unreachable!(),
    }
}

fn run_client(config_file: &str) {
    println!("Running in client mode");
    /* // Variables hardcodeadas (solo para debbuging)
    let pcap_file = "industroyer2.pcap";
    let remote_ip = Ipv4Addr::new(192, 168, 10, 3);
    let remote_port = 2404;
    let local_iface = "uesimtun0";
    */
    let config_content = fs::read_to_string(config_file).expect("Failed to read config file");
    let config: Config = toml::from_str(&config_content).expect("Failed to parse config file");

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
    println!(
        "Socket created and connected to {}:{} from {}:{}",
        remote_ip,
        remote_port,
        local_addr.ip(),
        local_addr.port()
    );

    // Empieza a mandar tráfico (quitar para debbuging)
    process_pcap(&pcap_file, source_ip, remote_ip, &interface, socket);
}

fn run_5gclient(config_file: &str) {
    println!("Running in client mode");
    /* // Variables hardcodeadas (solo para debbuging)
    let pcap_file = "industroyer2.pcap";
    let remote_ip = Ipv4Addr::new(192, 168, 10, 3);
    let remote_port = 2404;
    let local_iface = "uesimtun0";
    */
    let config_content = fs::read_to_string(config_file).expect("Failed to read config file");
    let config: Config = toml::from_str(&config_content).expect("Failed to parse config file");

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
    println!(
        "Socket created and connected to {}:{} from {}:{}",
        remote_ip,
        remote_port,
        local_addr.ip(),
        local_addr.port()
    );

    // Empieza a mandar tráfico (quitar para debbuging)
    process_pcap(&pcap_file, source_ip, remote_ip, &interface, socket);

    // Esto hay que mejorarlo
    ueransim_thread.join().unwrap();
}

fn run_server(config_file: &str) {
    println!("Running in server mode");
    let config_content = fs::read_to_string(config_file).expect("Failed to read config file");
    let config: Config = toml::from_str(&config_content).expect("Failed to parse config file");

    let server_config = config.server;

    let pcap_file = Arc::new(server_config.pcap_file);
    let local_iface = server_config.local_iface;
    let port = server_config.port;
    let interface = find_interface(&local_iface).expect("Network interface not found");
    let source_ip = get_source_ip(&interface).expect("Failed to get source IP");

    let source_ip = match source_ip {
        IpAddr::V4(ipv4) => ipv4,
        _ => panic!("Expected an IPv4 address"),
    };

    let listener = create_socket(port);
    println!("Server listening on port {}", port);

    let interface = Arc::new(interface);
    let source_ip = Arc::new(source_ip);

    for stream in listener.incoming() {
        match stream {
            Ok(socket) => {
                let pcap_file = Arc::clone(&pcap_file);
                let interface = Arc::clone(&interface);
                let source_ip = Arc::clone(&source_ip);

                thread::spawn(move || {
                    if let Err(e) = handle_client(socket, pcap_file, interface, source_ip) {
                        println!("Error handling client: {}", e);
                    }
                });
            }
            Err(e) => {
                println!("Connection failed: {}", e);
            }
        }
    }
}

fn handle_client(
    mut socket: TcpStream,
    pcap_file: Arc<String>,
    interface: Arc<NetworkInterface>,
    source_ip: Arc<Ipv4Addr>,
) -> Result<(), Box<dyn std::error::Error>> {
    let client_addr = socket.peer_addr()?;
    let client_ip = match client_addr.ip() {
        IpAddr::V4(ipv4) => ipv4,
        _ => panic!("Expected an IPv4 address from the client"),
    };

    let client_port = client_addr.port();

    println!(
        "New connection from client IP: {}, Port: {}",
        client_ip, client_port
    );

    // Ensure the socket is active before processing the PCAP file
    socket.set_nonblocking(true)?;

    process_pcap(&pcap_file, *source_ip, client_ip, &interface, socket)?;

    Ok(())
}
