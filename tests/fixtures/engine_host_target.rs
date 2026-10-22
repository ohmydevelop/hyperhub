//! Persistent native target for the coordinated Host upgrade suite. Keeps an
//! established stream while commands open additional independently routed ones.
use std::io::{self, BufRead, Read, Write};
use std::net::{Ipv4Addr, TcpStream};
fn main() {
    println!("TARGET_PID {}", std::process::id());
    io::stdout().flush().unwrap();
    let mut streams = Vec::new();
    for line in io::stdin().lock().lines() {
        match line.unwrap().as_str() {
            "open" => {
                let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, 31415)).unwrap();
                streams.push(stream);
            }
            "quit" => break,
            "ping" => {}
            _ => panic!("unexpected fixture command"),
        }
        for stream in &mut streams {
            stream.write_all(b"ping").unwrap();
            let mut bytes = [0;4];
            stream.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"ping");
        }
        println!("TARGET_OK {} {}", std::process::id(), streams.len());
        io::stdout().flush().unwrap();
    }
}
