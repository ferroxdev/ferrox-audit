//! TCP Fast Open, where the `ClientHello`'s first bytes ride the SYN instead of following the
//! handshake. A filter that reads names out of an established stream never sees the ones the SYN
//! carried; how much of the hello fits is the route's MSS and TCP option room, and the rest
//! follows once the handshake completes.
//!
//! `TCP_FASTOPEN_CONNECT` defers the handshake to the first write, and only when the kernel holds
//! a cookie for the destination: the first connect to a server is an ordinary handshake that asks
//! for one, so `crate::proxy::dial_kind` throws it away and dials again. A deferred socket has no
//! peer until that first write, which is why nothing here asks for one.

use std::io;
use std::net::TcpStream;

/// Whether this kernel lets a client put data in the SYN. Asked once, on a throwaway socket.
pub fn supported() -> bool {
    imp::supported()
}

/// Arm the socket so its first write, and only a cached cookie's worth of trust, rides the SYN.
pub fn arm(socket: &socket2::Socket) -> io::Result<()> {
    imp::arm(socket)
}

/// Whether `stream` is connected "later": the option is on, the kernel held the SYN back for the
/// first write, and nothing has been written yet.
pub fn deferred(stream: &TcpStream) -> bool {
    imp::deferred(stream)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use std::io;
    use std::net::TcpStream;
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::atomic::{AtomicU8, Ordering};

    use socket2::Socket;

    /// `TCP_SYN_SENT` in `tcp_info.tcpi_state`.
    const SYN_SENT: u8 = 2;

    fn set_connect(fd: RawFd) -> io::Result<()> {
        let on: libc::c_int = 1;
        // SAFETY: `fd` is a live socket, the option takes an int and `on` outlives the call.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN_CONNECT,
                std::ptr::from_ref(&on).cast(),
                std::mem::size_of_val(&on) as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn arm(socket: &Socket) -> io::Result<()> {
        set_connect(socket.as_raw_fd())
    }

    pub(super) fn supported() -> bool {
        static STATE: AtomicU8 = AtomicU8::new(0);
        match STATE.load(Ordering::Relaxed) {
            1 => return true,
            2 => return false,
            _ => {}
        }
        // SAFETY: plain socket(2); the descriptor is checked and closed below.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return false;
        }
        let asked = set_connect(fd);
        // SAFETY: `fd` was opened here and is not used again.
        unsafe { libc::close(fd) };
        match asked {
            Ok(()) => {
                STATE.store(1, Ordering::Relaxed);
                true
            }
            Err(error) => {
                // Cache only a refusal: a probe that lost a descriptor or hit a limit asks again.
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EINVAL | libc::ENOPROTOOPT | libc::ENOSYS)
                ) {
                    STATE.store(2, Ordering::Relaxed);
                }
                false
            }
        }
    }

    pub(super) fn deferred(stream: &TcpStream) -> bool {
        let mut info = [0u8; 256];
        let mut len = info.len() as libc::socklen_t;
        // SAFETY: `info`/`len` are valid out-parameters; the kernel fills the fields it has.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                info.as_mut_ptr().cast(),
                &raw mut len,
            )
        };
        rc == 0 && len > 0 && info[0] == SYN_SENT
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod imp {
    use std::io;
    use std::net::TcpStream;

    pub(super) fn arm(_: &socket2::Socket) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    pub(super) fn supported() -> bool {
        false
    }

    pub(super) fn deferred(_: &TcpStream) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_finished_handshake_is_never_deferred() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let peer =
            std::net::TcpStream::connect(listener.local_addr().expect("bound")).expect("a pair");
        let (_accepted, _) = listener.accept().expect("the pair");
        assert_eq!(
            supported(),
            supported(),
            "the kernel probe is answered once"
        );
        assert!(
            !deferred(&peer),
            "a connected socket has finished its handshake"
        );
    }
}
