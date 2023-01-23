#![feature(unix_socket_ancillary_data)]

use std::os::fd::{AsRawFd, RawFd};

use nix::fcntl;
use nix::sys::pidfd;
use nix::sys::signal::Signal;
use nix::sys::{
    mman, signal,
    socket::{self, SockaddrLike},
};
use nix::unistd::{ftruncate, Pid};

#[derive(Debug)]
#[repr(C)]
struct Data {
    socket: RawFd,
    send_pid: Pid,
    receive_pid: Pid,
}

const PATH: &str = "/some_arbitrary_path_10";

fn main() {
    let mut signal = signal::SigSet::empty();
    signal.add(Signal::SIGUSR1);
    signal::pthread_sigmask(signal::SigmaskHow::SIG_SETMASK, Some(&signal), None).unwrap();

    // Create a TCP socket listening on localhost:8080
    // ---------------------------------------------------------------------------------------------
    let socket = socket::socket(
        socket::AddressFamily::Inet6,
        socket::SockType::Stream,
        socket::SockFlag::empty(),
        None,
    )
    .unwrap();

    let local_host = libc::in6_addr {
        s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    };
    let addr = libc::sockaddr_in6 {
        sin6_family: u16::try_from(libc::AF_INET6).unwrap(),
        sin6_port: 8767,
        sin6_flowinfo: u32::default(),
        sin6_addr: local_host,
        sin6_scope_id: u32::default(),
    };
    let addr = unsafe {
        socket::SockaddrIn6::from_raw(
            std::ptr::addr_of!(addr).cast(),
            Some(u32::try_from(std::mem::size_of::<libc::sockaddr_in6>()).unwrap()),
        )
        .unwrap()
    };

    socket::bind(socket, &addr).unwrap();

    socket::listen(socket, 64).unwrap();

    // Store socket file descriptor in shared memory
    // ---------------------------------------------------------------------------------------------
    let shared_memory_object = std::mem::ManuallyDrop::new(
        mman::shm_open(
            PATH,
            fcntl::OFlag::O_RDWR | fcntl::OFlag::O_CREAT | fcntl::OFlag::O_EXCL,
            // TODO: Restrict these to minimum (likely read+write group)
            // Uses full permissions
            nix::sys::stat::Mode::all(),
        )
        .unwrap(),
    );

    let length = std::mem::size_of::<Data>();
    ftruncate(shared_memory_object.as_raw_fd(), length as i64).unwrap();
    let mapped_shared_memory = unsafe {
        mman::mmap(
            None,
            std::num::NonZeroUsize::new(length).unwrap(),
            mman::ProtFlags::PROT_WRITE | mman::ProtFlags::PROT_READ,
            mman::MapFlags::MAP_SHARED,
            Some(&*shared_memory_object),
            0,
        )
        .unwrap()
    };

    let ptr = mapped_shared_memory.cast::<Data>();
    let pid = Pid::this();
    unsafe {
        std::ptr::write(
            ptr,
            Data {
                socket,
                send_pid: pid,
                receive_pid: Pid::from_raw(0),
            },
        );
    }
    let data = unsafe { &*ptr };
    println!("fd: {data:?}");

    let mut sigset = signal::SigSet::empty();
    sigset.add(signal::Signal::SIGUSR1);
    sigset.wait().unwrap();

    println!("fd: {data:?}");

    let unix_socket = std::os::unix::net::UnixDatagram::unbound().unwrap();
    unix_socket.connect("./receive_socket").unwrap();
    send_fd(&unix_socket, data.socket);

    // // Allow `receive` to ptrace
    // let _result = unsafe {
    //     libc::prctl(
    //         libc::PR_SET_PTRACER,
    //         data.receive_pid.as_raw() as u32,
    //         0u32,
    //         0u32,
    //         0u32,
    //     )
    // };

    let pid_fd = pidfd::pid_open(data.receive_pid, false).unwrap();
    pidfd::pidfd_send_signal(pid_fd, Signal::SIGUSR1, None).unwrap();

    // Await SIGUSR1
    // ---------------------------------------------------------------------------------------------
    let mut sigset = signal::SigSet::empty();
    sigset.add(signal::Signal::SIGUSR1);
    sigset.wait().unwrap();
}

/// Sends a file descriptor over a unix datagram socket.
fn send_fd(socket: &std::os::unix::net::UnixDatagram, fd: RawFd) {
    let mut ancillary_buffer = [0; 32]; // TODO Why does this need to be 32?
    let mut ancillary = std::os::unix::net::SocketAncillary::new(ancillary_buffer.as_mut_slice());
    ancillary.add_fds(&[fd]);
    socket
        .send_vectored_with_ancillary(&[std::io::IoSlice::new(&[])], &mut ancillary)
        .unwrap();
}