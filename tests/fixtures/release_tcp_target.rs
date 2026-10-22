//! Generic persistent-stream workload for the native target/release Suite.
use std::io::{self, BufRead, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

fn main() {
    let address: SocketAddr = std::env::args()
        .nth(1)
        .expect("origin address")
        .parse()
        .unwrap();
    let mut streams = Vec::<TcpStream>::new();
    println!("READY {}", std::process::id());
    io::stdout().flush().unwrap();
    for command in io::stdin().lock().lines() {
        match command.unwrap().as_str() {
            "open" => {
                let stream = TcpStream::connect_timeout(&address, Duration::from_secs(10)).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                streams.push(stream);
            }
            "ping" => {
                for (index, stream) in streams.iter_mut().enumerate() {
                    let bytes = (index as u64).to_be_bytes();
                    stream.write_all(&bytes).unwrap();
                    let mut reply = [0; 8];
                    stream.read_exact(&mut reply).unwrap();
                    assert_eq!(reply, bytes);
                }
            }
            "close" => streams.clear(),
            "quit" => break,
            other => panic!("unexpected workload command {other}"),
        }
        println!("OK {} {}", std::process::id(), streams.len());
        io::stdout().flush().unwrap();
    }
}
