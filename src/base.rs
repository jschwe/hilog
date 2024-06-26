//! Experimental re-implementation of `hilog-base`
//!
//! Directly sends logs to `hilogd` to improve performance


use hilog_sys::hilog_base::{HilogMsg, TagLen, HILOG_SOCKET_PATH, MAX_TAG_LEN, MessageMetaField, MAX_LOG_LEN};
use crate::{LogLevel, LogType};
use nix::errno::Errno;
use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, UnixAddr};
use nix::sys::time::TimeSpec;
use nix::sys::uio::writev;
use nix::{NixPath, time};
use nix::time::ClockId;
use nix::unistd::{getpid, gettid};
use std::ffi::CStr;
use std::io::IoSlice;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd};
use nix::errno::Errno::EINTR;

#[derive(Debug)]
pub(crate) enum LogError {
    CreateSocketFailed(Errno),
    ConnectFailed(Errno),
    GetTimeFailed(Errno),
    WritevFailed(Errno),
    TagTooLong(usize),
    MessageTooLong(usize),
}

pub(crate) fn send_message(
    log_type: LogType,
    level: LogLevel,
    tag: &CStr,
    message: &CStr,
) -> Result<(), LogError> {
    let socket_fd = loop {
        match socket(
            AddressFamily::Unix,
            SockType::Datagram,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
            None,
        ) {
            Ok(fd) => break fd,
            Err(errno) if errno == Errno::EINTR => continue,
            Err(errno) => return Err(LogError::CreateSocketFailed(errno)),
        }
    };

    // Comment from hilogbase code:
    // > The hilogbase interface cannot has mutex, so need to re-open and connect to the socketof the hilogd
    // > server each time you write logs. Although there is some overhead, you can only do this.
    // I think we could also consider making a pool of sockets, and checking the performance.
    loop {
        match connect(
            socket_fd.as_raw_fd(),
            &UnixAddr::new(HILOG_SOCKET_PATH).unwrap(),
        ) {
            Ok(()) => break,
            Err(errno) if errno == Errno::EINTR => continue,
            Err(errno) => return Err(LogError::ConnectFailed(errno)),
        }
    }

    // let mut ts = timespec {
    //     tv_sec: 0,
    //     tv_nsec: 0,
    // };
    // let mut ts_mono = timespec {
    //     tv_sec: 0,
    //     tv_nsec: 0,
    // };
    //
    // let _res = unsafe { clock_gettime(CLOCK_REALTIME, &mut ts as *mut _) };
    // let _res = unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts_mono as *mut _) };
    let ts = time::clock_gettime(ClockId::CLOCK_REALTIME).unwrap_or(TimeSpec::new(0, 0));
    let ts_mono = time::clock_gettime(ClockId::CLOCK_MONOTONIC).unwrap_or(TimeSpec::new(0, 0));

    let raw_tag = tag.to_bytes_with_nul();
    let raw_message = message.to_bytes_with_nul();
    if raw_tag.len() > MAX_TAG_LEN {
        return Err(LogError::TagTooLong(raw_tag.len()))
    }
    if raw_message.len() > MAX_LOG_LEN {
        return Err(LogError::MessageTooLong(raw_message.len()))

    }
    let tag_len = TagLen::new(raw_tag.len());
    // We know `len` <= MAX_LOG_LEN, i.e. the conversion never truncates.
    let len = size_of::<HilogMsg>() + raw_tag.len() +  raw_message.len();
    let header = HilogMsg {
        // We know `len` <= MAX_LOG_LEN + MAX_TAG_LEN + headersize, i.e. the conversion never truncates.
        len: len as u16,
        meta_bitfield: MessageMetaField::new(log_type, level, tag_len),
        tv_sec: ts.tv_sec() as u32,
        tv_nsec: ts.tv_nsec() as u32,
        mono_sec: ts_mono.tv_sec() as u32,
        pid: getpid().as_raw() as u32,
        tid: gettid().as_raw() as u32,
        // todo: expose
        domain: 0,
    };

    let io_vec = [
        IoSlice::new(header.as_bytes()),
        IoSlice::new(&raw_tag),
        IoSlice::new(&raw_message),
    ];
    let socket = socket_fd.as_fd();
    loop {
        match writev(socket, &io_vec) {
            Ok(written_bytes) => return Ok(()),
            Err(errno) if errno == Errno::EAGAIN || errno == EINTR => continue,
            Err(errno) => return Err(LogError::WritevFailed(errno)),
        }
    }

}
