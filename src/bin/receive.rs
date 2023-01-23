#![feature(unix_socket_ancillary_data)]

use std::os::fd::{AsFd, AsRawFd, RawFd};

use nix::fcntl;
use nix::sys::ptrace::Options;
use nix::sys::signal;
use nix::sys::{mman, pidfd, signal::Signal};
use nix::unistd::Pid;

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

    // Get shared memory object.
    let shared_memory_object = std::mem::ManuallyDrop::new(
        mman::shm_open(PATH, fcntl::OFlag::O_RDWR, nix::sys::stat::Mode::all()).unwrap(),
    );

    let length = std::mem::size_of::<Data>();
    // Map shared memory.
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

    // Read data.
    let ptr = mapped_shared_memory.cast::<Data>();
    let data = unsafe { &mut *ptr };
    println!("fd: {:?}", data);

    data.receive_pid = Pid::this();

    println!("fd: {:?}", data);

    let pid_fd = pidfd::pid_open(data.send_pid, false).unwrap();

    pidfd::pidfd_send_signal(pid_fd.as_fd(), Signal::SIGUSR1, None).unwrap();

    let unix_socket = std::os::unix::net::UnixDatagram::bind("./receive_socket").unwrap();

    let mut sigset = signal::SigSet::empty();
    sigset.add(signal::Signal::SIGUSR1);
    sigset.wait().unwrap();

    let new_socket = receive_fd(&unix_socket);

    // Get ptrace permissions
    // nix::sys::ptrace::seize(data.send_pid, Options::empty()).unwrap();s

    // Transfer socket file descriptor.

    // let new_socket = pidfd::pidfd_getfd(pid_fd.as_fd(), data.socket).unwrap();
    data.socket = new_socket.as_raw_fd();

    // Send SIGUSR1
    pidfd::pidfd_send_signal(pid_fd, Signal::SIGUSR1, None).unwrap();

    mman::shm_unlink(PATH).unwrap();
}

/// Receives a file descriptor over a unix datagram socket.
fn receive_fd(socket: &std::os::unix::net::UnixDatagram) -> RawFd {
    let mut ancillary_buffer = [0; 32]; // TODO Why does this need to be 32?
    let mut ancillary = std::os::unix::net::SocketAncillary::new(ancillary_buffer.as_mut_slice());
    let (_size, _truncated) = socket
        .recv_vectored_with_ancillary(&mut [std::io::IoSliceMut::new(&mut [])], &mut ancillary)
        .unwrap();
    match ancillary.messages().next().unwrap().unwrap() {
        std::os::unix::net::AncillaryData::ScmRights(scm_rights) => scm_rights.into_iter().next().unwrap(),
        std::os::unix::net::AncillaryData::ScmCredentials(_) => unreachable!(),
    }
}