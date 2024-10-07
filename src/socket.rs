use std::net::TcpStream;
use std::io::{self, Write};
use std::thread;
use std::time::Duration;

fn create_and_connect_socket(server_addr: &str, pcap_data: &[u8]) {
    loop {
        match TcpStream::connect(server_addr) {
            Ok(mut stream) => {
                println!("Successfully connected to server at {}", server_addr);

                match stream.write_all(pcap_data) {
                    Ok(_) => {
                        println!("Successfully sent pcap data");
                        break;
                    }
                    Err(e) => {
                        eprintln!("Failed to send pcap data: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to connect to server: {}", e);
                println!("Retrying in 5 seconds...");
                thread::sleep(Duration::from_secs(5));
            }
        }
    }
}