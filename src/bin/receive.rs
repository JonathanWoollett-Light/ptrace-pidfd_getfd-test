use nix::fcntl;
use nix::sys::signal;
use nix::sys::{mman, pidfd, signal::Signal};
use nix::unistd::Pid;
use std::os::unix::io::AsFd;
use std::os::unix::io::AsRawFd;
use std::os::unix::prelude::RawFd;

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

    // Get shared memory
    let mapped_shared_memory = {
        let shared_memory_object = std::mem::ManuallyDrop::new(
            mman::shm_open(PATH, fcntl::OFlag::O_RDWR, nix::sys::stat::Mode::all()).unwrap(),
        );

        let length = std::mem::size_of::<Data>();
        unsafe {
            mman::mmap(
                None,
                std::num::NonZeroUsize::new(length).unwrap(),
                mman::ProtFlags::PROT_WRITE | mman::ProtFlags::PROT_READ,
                mman::MapFlags::MAP_SHARED,
                Some(&*shared_memory_object),
                0,
            )
            .unwrap()
        }
    };

    // Read data.
    let ptr = mapped_shared_memory.cast::<Data>();
    let data = unsafe { &mut *ptr };
    dbg!(&data);

    data.receive_pid = Pid::this();
    dbg!(&data);

    // Send 1
    let pid_fd = pidfd::pid_open(data.send_pid, false).unwrap();
    pidfd::pidfd_send_signal(pid_fd.as_fd(), Signal::SIGUSR1, None).unwrap();

    dbg!(&data);

    // Await 2 (we awaiting the send process giving us ptrace permission to take the socket)
    let mut sigset = signal::SigSet::empty();
    sigset.add(signal::Signal::SIGUSR1);
    sigset.wait().unwrap();

    dbg!(&data);

    let socket = pidfd::pidfd_getfd(pid_fd.as_fd(), data.socket).unwrap();
    data.socket = socket.as_raw_fd();

    dbg!(&data);

    // Send 3
    pidfd::pidfd_send_signal(pid_fd, Signal::SIGUSR1, None).unwrap();
    mman::shm_unlink(PATH).unwrap();
}
