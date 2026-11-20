//! The device lane's own traffic generator, so the bench ships no reference engine's binary.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::exit;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const MAGIC: &[u8; 4] = b"FXTB";
const UPLOAD: u8 = 0;
const DOWNLOAD: u8 = 1;
const ECHO: u8 = 2;
const RR: u8 = 3;

const LEASE: Duration = Duration::from_millis(250);

const USAGE: &str = "usage: ferrox-tun-bench <command> [options]

  tcp-server --listen ADDR:PORT
  tcp-client --connect ADDR:PORT [--streams N] [--seconds S] [--reverse] [--json F]
  rr-client --connect ADDR:PORT [--conns N] [--seconds S] [--size BYTES] [--json F]
  udp-server --listen ADDR:PORT [--echo]
  udp-client --connect ADDR:PORT [--seconds S] [--size BYTES] [--pps N] [--echo] [--gso] [--json F]
  monitor --pid PID [--seconds S] [--interval-ms N] [--json F]";

struct Args {
    list: Vec<String>,
}

impl Args {
    fn value(&self, name: &str) -> Option<&str> {
        self.list
            .windows(2)
            .find(|pair| pair[0] == name)
            .map(|pair| pair[1].as_str())
    }

    fn flag(&self, name: &str) -> bool {
        self.list.iter().any(|item| item == name)
    }

    fn number<T: std::str::FromStr>(&self, name: &str, default: T) -> T {
        match self.value(name) {
            None => default,
            Some(text) => text.parse().unwrap_or_else(|_| {
                eprintln!("{name} needs a whole number, got `{text}`");
                exit(2)
            }),
        }
    }

    fn endpoint(&self, name: &str) -> SocketAddr {
        let text = self.value(name).unwrap_or_else(|| {
            eprintln!("{name} is required");
            exit(2)
        });
        text.parse().unwrap_or_else(|_| {
            eprintln!("{name} needs an address:port, got `{text}`");
            exit(2)
        })
    }
}

fn json(path: Option<&str>, body: String) {
    if let Some(path) = path {
        if let Some(parent) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::write(path, body + "\n").is_err() {
            eprintln!("cannot write {path}");
            exit(1);
        }
    }
}

fn percentile(sorted: &[u64], fraction: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let last = sorted.len() - 1;
    let index = ((last as f64) * fraction).round() as usize;
    sorted[index.min(last)] as f64 / 1000.0
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("{USAGE}");
        exit(2);
    }
    let command = args[1].as_str();
    let args = Args {
        list: args[2..].to_vec(),
    };
    match command {
        "tcp-server" => tcp_server(args.endpoint("--listen")),
        "tcp-client" => tcp_client(&args),
        "rr-client" => rr_client(&args),
        "udp-server" => udp_server(args.endpoint("--listen"), args.flag("--echo")),
        "udp-client" => udp_client(&args),
        "monitor" => monitor(&args),
        _ => {
            eprintln!("{USAGE}");
            exit(2);
        }
    }
}

fn tcp_server(listen: SocketAddr) -> ! {
    let listener = TcpListener::bind(listen).unwrap_or_else(|error| {
        eprintln!("cannot listen on {listen}: {error}");
        exit(1)
    });
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        thread::spawn(move || serve(stream));
    }
    exit(0)
}

fn serve(mut stream: TcpStream) {
    let mut header = [0u8; 8];
    if stream.read_exact(&mut header).is_err() || &header[0..4] != MAGIC {
        return;
    }
    let mode = header[4];
    let size = u16::from_be_bytes([header[6], header[7]]);
    let mut buf = vec![0u8; 256 * 1024];
    match mode {
        UPLOAD => {
            while let Ok(n) = stream.read(&mut buf) {
                if n == 0 {
                    return;
                }
            }
        }
        DOWNLOAD => {
            buf.fill(0x5a);
            while stream.write_all(&buf).is_ok() {}
        }
        ECHO => loop {
            let Ok(n) = stream.read(&mut buf) else { return };
            if n == 0 || stream.write_all(&buf[..n]).is_err() {
                return;
            }
        },
        RR => {
            let size = size.clamp(1, 16384) as usize;
            loop {
                if stream.read_exact(&mut buf[..size]).is_err() {
                    return;
                }
                if stream.write_all(&buf[..size]).is_err() {
                    return;
                }
            }
        }
        _ => {}
    }
}

fn header(mode: u8, size: u16) -> [u8; 8] {
    let [high, low] = size.to_be_bytes();
    [MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], mode, 0, high, low]
}

fn tcp_client(args: &Args) {
    let endpoint = args.endpoint("--connect");
    let streams: usize = args.number("--streams", 1);
    let seconds: u64 = args.number("--seconds", 5);
    let reverse = args.flag("--reverse");
    let start = Instant::now();
    let deadline = start + Duration::from_secs(seconds);
    let bytes = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::with_capacity(streams.max(1));
    for _ in 0..streams.max(1) {
        let bytes = Arc::clone(&bytes);
        let failed = Arc::clone(&failed);
        handles.push(thread::spawn(move || {
            stream_run(endpoint, reverse, deadline, &bytes, &failed)
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
    let elapsed = start.elapsed().as_secs_f64();
    let total = bytes.load(Ordering::SeqCst);
    let failures = failed.load(Ordering::SeqCst);
    let gbps = total as f64 * 8.0 / 1e9 / elapsed;
    json(
        args.value("--json"),
        format!(
            "{{\"bytes\":{total},\"seconds\":{elapsed:.6},\"gbps\":{gbps:.6},\"streams\":{streams},\"reverse\":{reverse}}}"
        ),
    );
    println!(
        "{} streams {:.3} Gbit/s over {:.2} s",
        streams, gbps, elapsed
    );
    if failures > 0 || total == 0 {
        eprintln!("{failures} of {streams} streams failed");
        exit(1);
    }
}

fn stream_run(
    endpoint: SocketAddr,
    reverse: bool,
    deadline: Instant,
    bytes: &AtomicU64,
    failed: &AtomicU64,
) {
    let Ok(mut stream) = TcpStream::connect(endpoint) else {
        failed.fetch_add(1, Ordering::SeqCst);
        return;
    };
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(LEASE));
    let _ = stream.set_write_timeout(Some(LEASE));
    let mode = if reverse { DOWNLOAD } else { UPLOAD };
    if stream.write_all(&header(mode, 0)).is_err() {
        failed.fetch_add(1, Ordering::SeqCst);
        return;
    }
    let mut buf = vec![0xa5u8; 128 * 1024];
    let mut moved = 0u64;
    while Instant::now() < deadline {
        let step = if reverse {
            stream.read(&mut buf)
        } else {
            stream.write(&buf)
        };
        match step {
            Ok(0) => break,
            Ok(n) => moved += n as u64,
            // A full pipe is a stall, not the deadline: the loop asks again until the clock says stop.
            Err(error) if lease(&error) => continue,
            Err(_) => {
                failed.fetch_add(1, Ordering::SeqCst);
                break;
            }
        }
    }
    bytes.fetch_add(moved, Ordering::SeqCst);
}

fn rr_client(args: &Args) {
    let endpoint = args.endpoint("--connect");
    let conns: usize = args.number("--conns", 1);
    let seconds: u64 = args.number("--seconds", 5);
    let size: u16 = args.number("--size", 64);
    if size == 0 || size > 16_384 {
        eprintln!("--size must be 1..=16384, got {size}");
        exit(2);
    }
    let start = Instant::now();
    let deadline = start + Duration::from_secs(seconds);
    let mut handles = Vec::with_capacity(conns.max(1));
    for _ in 0..conns.max(1) {
        handles.push(thread::spawn(move || round_trips(endpoint, size, deadline)));
    }
    let mut samples = Vec::new();
    let mut errors = 0u64;
    for handle in handles {
        let (mut hist, failed) = handle.join().unwrap_or_default();
        samples.append(&mut hist);
        errors += failed;
    }
    let elapsed = start.elapsed().as_secs_f64();
    if samples.is_empty() {
        eprintln!("no transaction completed ({errors} errors)");
        exit(1);
    }
    samples.sort_unstable();
    let tps = samples.len() as f64 / elapsed;
    json(
        args.value("--json"),
        format!(
            "{{\"transactions\":{},\"seconds\":{elapsed:.6},\"tps\":{tps:.3},\"p50_us\":{:.3},\"p90_us\":{:.3},\"p99_us\":{:.3},\"p999_us\":{:.3},\"max_us\":{:.3},\"mean_us\":{:.3},\"conns\":{conns},\"size\":{size},\"errors\":{errors}}}",
            samples.len(),
            percentile(&samples, 0.50),
            percentile(&samples, 0.90),
            percentile(&samples, 0.99),
            percentile(&samples, 0.999),
            percentile(&samples, 1.0),
            samples.iter().sum::<u64>() as f64 / samples.len() as f64 / 1000.0,
        ),
    );
    println!("{tps:.0} tps, {} transactions", samples.len());
}

fn round_trips(endpoint: SocketAddr, size: u16, deadline: Instant) -> (Vec<u64>, u64) {
    let size = size as usize;
    let Ok(mut stream) = TcpStream::connect(endpoint) else {
        return (Vec::new(), 1);
    };
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(LEASE));
    let _ = stream.set_write_timeout(Some(LEASE));
    if stream.write_all(&header(RR, size as u16)).is_err() {
        return (Vec::new(), 1);
    }
    let mut buf = vec![0x3cu8; size];
    let mut samples = Vec::new();
    let mut errors = 0u64;
    while Instant::now() < deadline {
        let at = Instant::now();
        if !move_all(&mut stream, &buf, deadline) || !fill_all(&mut stream, &mut buf, deadline) {
            errors += 1;
            break;
        }
        samples.push(at.elapsed().as_nanos() as u64);
    }
    (samples, errors)
}

fn move_all(stream: &mut TcpStream, buf: &[u8], deadline: Instant) -> bool {
    let mut done = 0;
    while done < buf.len() {
        if Instant::now() >= deadline {
            return false;
        }
        match stream.write(&buf[done..]) {
            Ok(0) => return false,
            Ok(n) => done += n,
            Err(error) if lease(&error) => {}
            Err(_) => return false,
        }
    }
    true
}

fn fill_all(stream: &mut TcpStream, buf: &mut [u8], deadline: Instant) -> bool {
    let mut done = 0;
    while done < buf.len() {
        if Instant::now() >= deadline {
            return false;
        }
        match stream.read(&mut buf[done..]) {
            Ok(0) => return false,
            Ok(n) => done += n,
            Err(error) if lease(&error) => {}
            Err(_) => return false,
        }
    }
    true
}

fn lease(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
    )
}

fn udp_server(listen: SocketAddr, echo: bool) -> ! {
    let socket = UdpSocket::bind(listen).unwrap_or_else(|error| {
        eprintln!("cannot listen on {listen}: {error}");
        exit(1)
    });
    widen(&socket);
    let mut buf = vec![0u8; 65_535];
    loop {
        let Ok((n, from)) = socket.recv_from(&mut buf) else {
            continue;
        };
        if echo {
            let _ = socket.send_to(&buf[..n], from);
        }
    }
}

fn widen(socket: &UdpSocket) {
    #[cfg(not(unix))]
    let _ = socket;
    #[cfg(unix)]
    {
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(socket);
        for option in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
            let size: libc::c_int = 8 << 20;
            // Best effort: a smaller buffer still measures the engine, only the pps ceiling moves.
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    option,
                    &size as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
    }
}

fn stamp(buf: &mut [u8], sequence: u64) {
    let length = buf.len() as u32;
    buf[0..8].copy_from_slice(&sequence.to_le_bytes());
    buf[8..12].copy_from_slice(&length.to_le_bytes());
    for (offset, byte) in buf[12..].iter_mut().enumerate() {
        *byte = (sequence.wrapping_mul(31).wrapping_add(offset as u64) & 0xff) as u8;
    }
}

fn intact(buf: &[u8]) -> bool {
    if buf.len() < 12
        || u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]) as usize != buf.len()
    {
        return false;
    }
    let sequence = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    buf[12..].iter().enumerate().all(|(offset, byte)| {
        *byte == (sequence.wrapping_mul(31).wrapping_add(offset as u64) & 0xff) as u8
    })
}

fn udp_client(args: &Args) {
    let endpoint = args.endpoint("--connect");
    let seconds: u64 = args.number("--seconds", 5);
    let size: usize = args.number("--size", 1200).clamp(16, 65_000);
    let pps: u64 = args.number("--pps", 0);
    let gso = args.flag("--gso");
    let wildcard = if endpoint.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(wildcard).unwrap_or_else(|error| {
        eprintln!("cannot open a client socket: {error}");
        exit(1)
    });
    widen(&socket);
    if socket.connect(endpoint).is_err() {
        eprintln!("cannot reach {endpoint}");
        exit(1);
    }
    let _ = socket.set_nonblocking(true);
    let gso = gso && set_segment(&socket, size);
    let start = Instant::now();
    let deadline = start + Duration::from_secs(seconds);
    // `--pps 0` is the unreported `udp` scenario: offer as fast as the socket takes datagrams.
    let paced = pps > 0;
    let total = if paced { pps * seconds } else { u64::MAX };
    const BATCH: usize = 64;
    let mut segments = if gso { (64_000 / size).max(1) } else { 1 };
    let mut payload = vec![0u8; size * BATCH.max(segments)];
    let mut received = 0u64;
    let mut corrupt = 0u64;
    let mut sent = 0u64;
    let mut sequence = 0u64;
    let mut rbuf = vec![0u8; 65_535];
    while Instant::now() < deadline && sent < total {
        // Pace off the clock, so a delayed tick is made up instead of shrinking the offer.
        let mut want = if paced {
            let owed = ((pps as f64 * start.elapsed().as_secs_f64()) as u64).min(total);
            owed.saturating_sub(sent)
        } else {
            (BATCH * 8) as u64
        };
        while want > 0 && sent < total {
            if segments > 1 {
                for index in 0..segments {
                    let start = index * size;
                    stamp(&mut payload[start..start + size], sequence + index as u64);
                }
                match socket.send(&payload[..size * segments]) {
                    Ok(_) => {
                        let sent_now = segments as u64;
                        sent += sent_now;
                        sequence += sent_now;
                        want = want.saturating_sub(sent_now);
                    }
                    // The batch went nowhere, so drop back to single datagrams.
                    Err(_) => segments = 1,
                }
            } else {
                let chunk = want.min(BATCH as u64) as usize;
                let moved = send_batch(&socket, &mut payload, size, sequence, chunk);
                if moved == 0 {
                    break;
                }
                sent += moved as u64;
                sequence += moved as u64;
                want -= moved as u64;
            }
        }
        drain(&socket, &mut rbuf, &mut received, &mut corrupt);
        thread::sleep(Duration::from_micros(200));
    }
    let until = Instant::now() + Duration::from_millis(200);
    let mut quiet = 0;
    while Instant::now() < until && quiet < 10 {
        let before = received;
        drain(&socket, &mut rbuf, &mut received, &mut corrupt);
        quiet = if received == before { quiet + 1 } else { 0 };
        thread::sleep(Duration::from_millis(5));
    }
    let elapsed = start.elapsed().as_secs_f64();
    let measured = received as f64 / elapsed;
    json(
        args.value("--json"),
        format!(
            "{{\"sent\":{sent},\"received\":{received},\"corrupt\":{corrupt},\"seconds\":{elapsed:.6},\"pps\":{measured:.3},\"size\":{size}}}"
        ),
    );
    println!("{received} of {sent} echoed, {measured:.0} pps");
    // An echo that answers nothing is the engine's hole, not a zero to record for it.
    let echo = args.flag("--echo");
    if echo && received == 0 {
        exit(1);
    }
}

/// Stamps and sends one batch, so a 100k pps offer does not pay a syscall a datagram.
fn send_batch(
    socket: &UdpSocket,
    payload: &mut [u8],
    size: usize,
    sequence: u64,
    count: usize,
) -> usize {
    #[cfg(target_os = "linux")]
    {
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(socket);
        let count = count.min(payload.len() / size).max(1);
        let mut iov = Vec::with_capacity(count);
        for index in 0..count {
            let start = index * size;
            stamp(&mut payload[start..start + size], sequence + index as u64);
            iov.push(libc::iovec {
                iov_base: payload[start..].as_mut_ptr() as *mut libc::c_void,
                iov_len: size,
            });
        }
        let mut msgs: Vec<libc::mmsghdr> = (0..count)
            .map(|index| libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: std::ptr::null_mut(),
                    msg_namelen: 0,
                    msg_iov: unsafe { iov.as_mut_ptr().add(index) },
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            })
            .collect();
        let moved = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), count as libc::c_uint, 0) };
        if moved < 0 {
            return 0;
        }
        return moved as usize;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut moved = 0;
        for index in 0..count {
            let start = index * size;
            stamp(&mut payload[start..start + size], sequence + index as u64);
            if socket.send(&payload[start..start + size]).is_err() {
                break;
            }
            moved += 1;
        }
        moved
    }
}

fn drain(socket: &UdpSocket, buf: &mut [u8], received: &mut u64, corrupt: &mut u64) {
    loop {
        match socket.recv(buf) {
            Ok(0) => return,
            Ok(n) => {
                if intact(&buf[..n]) {
                    *received += 1;
                } else {
                    *corrupt += 1;
                }
            }
            Err(_) => return,
        }
    }
}

fn set_segment(socket: &UdpSocket, size: usize) -> bool {
    #[cfg(target_os = "linux")]
    {
        const UDP_SEGMENT: libc::c_int = 103;
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(socket);
        let segment = size as libc::c_int;
        let applied = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_UDP,
                UDP_SEGMENT,
                &segment as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        applied == 0
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (socket, size);
        false
    }
}

fn monitor(args: &Args) {
    let pid: u32 = args.number("--pid", 0);
    let seconds: u64 = args.number("--seconds", 5);
    let interval: u64 = args.number("--interval-ms", 500);
    if pid == 0 {
        eprintln!("--pid is required");
        exit(2);
    }
    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds);
    let mut cpu: u64 = 0;
    let mut max_rss: u64 = 0;
    let mut max_pss: u64 = 0;
    let mut samples: u64 = 0;
    let mut last_cpu = cpu_ticks(pid).unwrap_or(0);
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(interval.min(1000).max(50)));
        let Some(ticks) = cpu_ticks(pid) else { break };
        cpu += ticks.saturating_sub(last_cpu);
        last_cpu = ticks;
        max_rss = max_rss.max(rss_kb(pid).unwrap_or(0));
        max_pss = max_pss.max(pss_kb(pid).unwrap_or(0));
        samples += 1;
    }
    let elapsed = started.elapsed().as_secs_f64().max(0.001);
    let hz = clock_ticks().max(1) as f64;
    let average = if samples == 0 {
        0.0
    } else {
        cpu as f64 / hz / elapsed * 100.0
    };
    json(
        args.value("--json"),
        format!(
            "{{\"pid\":{pid},\"samples\":{samples},\"avg_cpu_pct\":{average:.3},\"max_rss_kb\":{max_rss},\"max_pss_kb\":{max_pss}}}"
        ),
    );
}

fn clock_ticks() -> i64 {
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::sysconf(libc::_SC_CLK_TCK) }
    }
    #[cfg(not(target_os = "linux"))]
    {
        100
    }
}

fn cpu_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = tail.split_whitespace().collect();
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some(utime + stime)
}

fn status_value(pid: u32, key: &str) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn rss_kb(pid: u32) -> Option<u64> {
    status_value(pid, "VmRSS:")
}

fn pss_kb(pid: u32) -> Option<u64> {
    let rollup = std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup")).ok()?;
    let mut total = 0u64;
    for line in rollup.lines() {
        if let Some(rest) = line.strip_prefix("Pss:") {
            total += rest.split_whitespace().next()?.parse::<u64>().ok()?;
        }
    }
    Some(total)
}
