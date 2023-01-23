use nix::fcntl;
use nix::sys::pidfd;
use nix::sys::signal::Signal;
use nix::sys::{mman, signal, socket};
use nix::unistd::{ftruncate, Pid};
use std::os::unix::prelude::RawFd;

#[derive(Debug)]
#[repr(C)]
struct Data {
    socket: RawFd,
    send_pid: Pid,
    receive_pid: Pid,
}

const PATH: &str = "/some_arbitrary_path_10";
use nix::sys::socket::SockaddrIn6;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::unix::io::AsRawFd;

fn main() {
    // Block SIGUSR1 so we can handle it
    let mut signal = signal::SigSet::empty();
    signal.add(Signal::SIGUSR1);
    signal::pthread_sigmask(signal::SigmaskHow::SIG_SETMASK, Some(&signal), None).unwrap();

    // Create, bind and listen on socket.
    let socket = {
        let socket = socket::socket(
            socket::AddressFamily::Inet6,
            socket::SockType::Stream,
            socket::SockFlag::empty(),
            None,
        )
        .unwrap();
        socket::bind(
            socket,
            &SockaddrIn6::from(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 0)),
        )
        .unwrap();
        socket::listen(socket, 64).unwrap();
        socket
    };

    // Create shared memory
    let mapped_shared_memory = {
        let shared_memory_object = mman::shm_open(
            PATH,
            fcntl::OFlag::O_RDWR | fcntl::OFlag::O_CREAT | fcntl::OFlag::O_EXCL,
            nix::sys::stat::Mode::all(),
        )
        .unwrap();
        let length = std::mem::size_of::<Data>();
        ftruncate(shared_memory_object.as_raw_fd(), length as i64).unwrap();
        unsafe {
            mman::mmap(
                None,
                std::num::NonZeroUsize::new(length).unwrap(),
                mman::ProtFlags::PROT_WRITE | mman::ProtFlags::PROT_READ,
                mman::MapFlags::MAP_SHARED,
                Some(&shared_memory_object),
                0,
            )
            .unwrap()
        }
    };

    // Write data to shared memory
    let ptr = mapped_shared_memory.cast::<Data>();
    let data = unsafe { &mut *ptr };
    let pid = Pid::this();
    unsafe {
        std::ptr::write(
            data,
            Data {
                socket,
                send_pid: pid,
                receive_pid: Pid::from_raw(0),
            },
        );
    }

    dbg!(&data);

    // Await 1 (at this point we manually start the receive process)
    let mut sigset = signal::SigSet::empty();
    sigset.add(signal::Signal::SIGUSR1);
    sigset.wait().unwrap();

    dbg!(&data);

    // Allow `receive` to ptrace to avoid EPERM error when the receive process attempts `pidfd_getfd` on the socket.
    unsafe {
        libc::prctl(libc::PR_SET_PTRACER, data.receive_pid.as_raw() as u32);
    }

    dbg!(&data);

    // Send 2
    let pid_fd = pidfd::pid_open(data.receive_pid, false).unwrap();
    pidfd::pidfd_send_signal(pid_fd, Signal::SIGUSR1, None).unwrap();

    dbg!(&data);

    // Await 3 (at this point we manually start the receive process)
    let mut sigset = signal::SigSet::empty();
    sigset.add(signal::Signal::SIGUSR1);
    sigset.wait().unwrap();

    println!("Some final cleanup work");
}
