use std::time::{Duration, Instant};

use ferrox_core::kcp::{dial, Config, Listener};

fn usage() -> ! {
    eprintln!("usage: kcp_interop server <port> | kcp_interop client <peer> <payload>");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        usage();
    }
    let mode = &args[1];
    let peer_arg = &args[2];

    match mode.as_str() {
        "server" => {
            let Ok(port) = peer_arg.parse() else {
                usage();
            };
            let listener =
                Listener::bind(([127, 0, 0, 1], port).into(), Config::default()).expect("bind");
            loop {
                let Ok(conn) = listener.accept() else { break };
                std::thread::spawn(move || {
                    let mut buf = vec![0u8; 65536];
                    while let Ok(n) = conn.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        if conn.write(&buf[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        }
        "client" => {
            let Some(payload) = args.get(3) else {
                usage();
            };
            let Ok(peer) = peer_arg.parse() else {
                usage();
            };
            let conn = dial(peer, Config::default(), 7).expect("dial");
            conn.write(payload.as_bytes()).unwrap();
            conn.set_read_deadline(Instant::now() + Duration::from_secs(10));
            let mut buf = vec![0u8; 65536];
            let mut received = Vec::with_capacity(payload.len());
            while received.len() < payload.len() {
                let n = conn.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
            }
            if received.as_slice() != payload.as_bytes() {
                eprintln!(
                    "echo mismatch: sent {} bytes, received {}",
                    payload.len(),
                    received.len()
                );
                std::process::exit(1);
            }
            println!("echo: {}", String::from_utf8_lossy(&received));
            conn.close();
        }
        _ => usage(),
    }
}
