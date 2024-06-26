//! `log` compatible logger to the `HiLog` logging system on OpenHarmony
//!
//! This crate is in its very early stages and still under development.
//! It's partially based on [`env_logger`], in particular the filtering
//! is compatible with [`env_logger`].
//!
//! [`env_logger`]: https://docs.rs/env_logger/latest/env_logger/

#[cfg(feature = "direct-logging")]
mod base;

use std::ffi::{CStr, CString};
use hilog_sys::{LogLevel, LogType, OH_LOG_IsLoggable, OH_LOG_Print};
use hilog_sys::hilog_base::{MAX_LOG_LEN, MAX_TAG_LEN};
use log::{LevelFilter, Log, Metadata, Record, SetLoggerError};

/// Service domain of logs
///
/// The user can set this value as required. The value can be used
/// when filtering `hilog` logs.
#[derive(Copy, Clone, Default, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct LogDomain(u16);

impl LogDomain {

    /// Creates a new LogDomain
    ///
    /// Valid values are 0-0xFFFF.
    pub fn new(domain: u16) -> Self {
        Self(domain)
    }
}


fn hilog_log(log_type: LogType, level: LogLevel, domain: LogDomain, tag: &CStr, msg: &CStr) {
    let _res = unsafe {
        OH_LOG_Print(
            log_type,
            level,
            domain.0.into(),
            tag.as_ptr(),
            c"%{public}s".as_ptr(),
            msg.as_ptr()
        )
    };
}

#[derive(Default)]
pub struct Builder {
    filter: env_filter::Builder,
    log_domain: LogDomain,
    built: bool,
}

impl Builder {
    pub fn new() -> Builder {
        Default::default()
    }


    /// Sets the Service domain for the logs
    ///
    /// Users can set a custom domain, which allows filtering by hilogd.
    pub fn set_domain(&mut self, domain: LogDomain) -> &mut Self {
        self.log_domain = domain;
        self
    }

    /// Adds a directive to the filter for a specific module.
    ///
    /// # Examples
    ///
    /// Only include messages for info and above for logs in `path::to::module`:
    ///
    /// ```
    /// use env_filter::Builder;
    /// use log::LevelFilter;
    ///
    /// let mut builder = Builder::new();
    ///
    /// builder.filter_module("path::to::module", LevelFilter::Info);
    /// ```
    pub fn filter_module(&mut self, module: &str, level: LevelFilter) -> &mut Self {
        self.filter.filter_module(module, level);
        self
    }

    /// Adds a directive to the filter for all modules.
    ///
    /// # Examples
    ///
    /// Only include messages for info and above for logs globally:
    ///
    /// ```
    /// use env_filter::Builder;
    /// use log::LevelFilter;
    ///
    /// let mut builder = Builder::new();
    ///
    /// builder.filter_level(LevelFilter::Info);
    /// ```
    pub fn filter_level(&mut self, level: LevelFilter) -> &mut Self {
        self.filter.filter_level(level);
        self
    }

    /// Adds filters to the logger.
    ///
    /// The given module (if any) will log at most the specified level provided.
    /// If no module is provided then the filter will apply to all log messages.
    ///
    /// # Examples
    ///
    /// Only include messages for info and above for logs in `path::to::module`:
    ///
    /// ```
    /// use env_filter::Builder;
    /// use log::LevelFilter;
    ///
    /// let mut builder = Builder::new();
    ///
    /// builder.filter(Some("path::to::module"), LevelFilter::Info);
    /// ```
    pub fn filter(&mut self, module: Option<&str>, level: LevelFilter) -> &mut Self {
        self.filter.filter(module, level);
        self
    }

    /// Initializes the global logger with the built env logger.
    ///
    /// This should be called early in the execution of a Rust program. Any log
    /// events that occur before initialization will be ignored.
    ///
    /// # Errors
    ///
    /// This function will fail if it is called more than once, or if another
    /// library has already initialized a global logger.
    pub fn try_init(&mut self) -> Result<(), SetLoggerError> {
        let logger = self.build();

        let max_level = logger.filter();
        let r = log::set_boxed_logger(Box::new(logger));

        if r.is_ok() {
            log::set_max_level(max_level);
        }

        r
    }

    /// Initializes the global logger with the built env logger.
    ///
    /// This should be called early in the execution of a Rust program. Any log
    /// events that occur before initialization will be ignored.
    ///
    /// # Panics
    ///
    /// This function will panic if it is called more than once, or if another
    /// library has already initialized a global logger.
    pub fn init(&mut self) {
        self.try_init()
            .expect("Builder::init should not be called after logger initialized");
    }

    /// Build an env logger.
    ///
    /// The returned logger implements the `Log` trait and can be installed manually
    /// or nested within another logger.
    pub fn build(&mut self) -> Logger {
        assert!(!self.built, "attempt to re-use consumed builder");
        self.built = true;

        Logger {
            domain: self.log_domain,
            filter: self.filter.build(),
        }
    }

}



pub struct Logger  {
    domain: LogDomain,
    filter: env_filter::Filter
}

impl Logger {
    /// Returns the maximum `LevelFilter` that this env logger instance is
    /// configured to output.
    pub fn filter(&self) -> LevelFilter {
        self.filter.filter()
    }

    fn is_loggable(&self, tag: &CStr, level: LogLevel) -> bool {
        unsafe {
            OH_LOG_IsLoggable(self.domain.0.into(), tag.as_ptr(), level)
        }
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.filter.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if ! self.enabled(record.metadata()) {
            return;
        }

        let mut path = [0; MAX_TAG_LEN];
        let len = if let Some(module_path) = record.module_path() {
            let len = module_path.len().clamp(0, MAX_TAG_LEN - 1);
            path[0..len].copy_from_slice(&module_path.as_bytes()[0..len]);
            len
        } else {
            0
        };
        // SAFETY: `len` is the length exclusive `\0`. We filled path until `len`
        // with contents from a valid `str`, and left a terminating `0` after that.
        let tag = unsafe { CStr::from_bytes_with_nul_unchecked(&path[0..=len]) };

        // Todo: I think we also need / want to split messages at newlines.
        let message = format!("{}", record.args());
        let bytes = message.into_bytes();
        let clamped_message = if bytes.len() >= MAX_LOG_LEN {
            let mut clamped = Vec::from(&bytes[0..MAX_LOG_LEN-1]);
            clamped.push(0);
            clamped

        } else {
            bytes
        };
        let c_msg = CString::from_vec_with_nul(clamped_message).unwrap_or_default();
        #[cfg(feature = "direct-logging")]
        {
            let res = base::send_message(LogType::LOG_APP, record.level().into(), tag, c_msg.as_ref());
            if let Err(e) = res {
                let error_msg = format!("Failed to send log message due to: {e:?}\0");
                let c_msg = CString::from_vec_with_nul(error_msg.into_bytes()).unwrap_or_default();
                hilog_log(LogType::LOG_APP, LogLevel::LOG_ERROR, self.domain,
                          c"hilog-rust",  c_msg.as_ref());
            } else {
                hilog_log(hilog_sys::LogType::LOG_APP, record.level().into(), self.domain, c"HILOG_RS_DBG", c"Send message returned without error code!")

            }
        }
        #[cfg(not(feature = "direct-logging"))]
        hilog_log(hilog_sys::LogType::LOG_APP, record.level().into(), self.domain, tag.as_ref(), c_msg.as_ref())
    }

    fn flush(&self) {}
}