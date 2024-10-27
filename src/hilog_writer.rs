use crate::{uninit_array, LogDomain};
use hilog_sys::{LogLevel, LogType, OH_LOG_Print};
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::{fmt, mem, ptr};

// https://gitee.com/openharmony/hiviewdfx_hilog/blob/master/frameworks/libhilog/include/hilog_base.h#L25
/// Maximum log entry length excluding trailing `\0`.
pub const MAX_LOG_LEN: usize = 4096 - 1;
/// Maximum log tag length excluding trailing `\0`.
pub const MAX_TAG_LEN: usize = 32 - 1;

fn hilog_log(log_type: LogType, level: LogLevel, domain: LogDomain, tag: &CStr, msg: &CStr) {
    let _res = unsafe {
        OH_LOG_Print(
            log_type,
            level,
            domain.0.into(),
            tag.as_ptr(),
            c"%{public}s".as_ptr(),
            msg.as_ptr(),
        )
    };
}

pub struct HiLogWriter<'a> {
    log_type: LogType,
    level: LogLevel,
    domain: LogDomain,
    len: usize,
    last_newline_index: usize,
    tag: &'a CStr,
    buffer: [MaybeUninit<u8>; MAX_LOG_LEN + 1],
}

impl<'a> HiLogWriter<'a> {
    pub fn new(log_type: LogType, level: LogLevel, domain: LogDomain, tag: &'a CStr) -> Self {
        Self {
            log_type,
            level,
            domain,
            len: 0,
            last_newline_index: 0,
            tag,
            buffer: uninit_array(),
        }
    }

    /// Output buffer up until the \0 which will be placed at `len` position.
    fn output_specified_len(&mut self, mut len: usize) {
        if len == 0 {
            return;
        } else if len > MAX_LOG_LEN {
            len = MAX_LOG_LEN;
        }

        let mut last_byte = MaybeUninit::new(b'\0');

        mem::swap(&mut last_byte, unsafe {
            self.buffer.get_unchecked_mut(len)
        });

        let c_msg: &CStr = unsafe { CStr::from_ptr(self.buffer.as_ptr().cast()) };
        hilog_log(
            self.log_type,
            self.level,
            self.domain,
            self.tag,
            c_msg,
        );

        unsafe { *self.buffer.get_unchecked_mut(len) = last_byte };
    }

    /// Copy `len` bytes from `index` position to starting position.
    /// Safety: `index + len` must be less than or equal to `MAX_LOG_LEN`.
    fn copy_bytes_to_start(&mut self, index: usize, mut len: usize) {
        if len == 0 {
            return;
        } else if index + len > MAX_LOG_LEN {
            len = MAX_LOG_LEN - index;
        }
        let dst = self.buffer.as_mut_ptr();
        let src = unsafe { self.buffer.as_ptr().add(index) };
        unsafe { ptr::copy(src, dst, len) };
    }

    /// Flush some bytes to hilog.
    ///
    /// If there is a newline, flush up to it.
    /// If there was no newline, flush all.
    ///
    /// Not guaranteed to flush everything.
    fn temporal_flush(&mut self) {
        let total_len = self.len;

        if total_len == 0 {
            return;
        }

        if self.last_newline_index > 0 {
            let copy_from_index = self.last_newline_index;
            let remaining_chunk_len = total_len - copy_from_index;

            self.output_specified_len(copy_from_index);
            self.copy_bytes_to_start(copy_from_index, remaining_chunk_len);
            self.len = remaining_chunk_len;
        } else {
            self.output_specified_len(total_len);
            self.len = 0;
        }
        self.last_newline_index = 0;
    }

    /// Flush everything remaining to hilog.
    pub fn flush(&mut self) {
        let total_len = self.len;

        if total_len == 0 {
            return;
        }

        self.output_specified_len(total_len);
        self.len = 0;
        self.last_newline_index = 0;
    }
}

impl<'a> fmt::Write for HiLogWriter<'a> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut incoming_bytes = s.as_bytes();

        // use mutex here
        while !incoming_bytes.is_empty() {
            let len = self.len;

            // write everything possible to buffer and mark last '\n'
            let new_len = len + incoming_bytes.len();
            let last_newline = self.buffer[len..MAX_LOG_LEN]
                .iter_mut()
                .zip(incoming_bytes)
                .enumerate()
                .fold(None, |acc, (i, (output, input))| {
                    output.write(*input);
                    if *input == b'\n' {
                        Some(i)
                    } else {
                        acc
                    }
                });

            // update last \n index
            if let Some(newline) = last_newline {
                self.last_newline_index = len + newline;
            }

            // calculate how many bytes were written
            let written_len = if new_len <= MAX_LOG_LEN {
                // if the len was not exceeded
                self.len = new_len;
                new_len - len // written len
            } else {
                // if new length was exceeded
                self.len = MAX_LOG_LEN;
                self.temporal_flush();

                MAX_LOG_LEN - len // written len
            };

            incoming_bytes = &incoming_bytes[written_len..];
        }

        Ok(())
    }
}
