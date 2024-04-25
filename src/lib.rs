//! `log` compatible logger to the `HiLog` logging system on OpenHarmony
//!
//! This crate is in its very early stages and still under development.
//! It's partially based on [`env_logger`], in particular the filtering
//! is compatible with [`env_logger`].
//!
//! [`env_logger`]: https://docs.rs/env_logger/latest/env_logger/

use std::ffi::{CStr, CString};
use hilog_sys::{LogLevel, LogType, OH_LOG_IsLoggable, OH_LOG_Print};
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

        // Todo: we could write to a fixed size array on the stack, since hilog anyway has a
        // maximum supported size for tag and log.
        let tag = record.module_path().and_then(|path| CString::new(path).ok())
            .unwrap_or_default();
        // Todo: I think we also need / want to split messages at newlines.
        let message = format!("{}\0", record.args());
        let c_msg = CString::from_vec_with_nul(message.into_bytes()).unwrap_or_default();
        hilog_log(hilog_sys::LogType::LOG_APP, record.level().into(), self.domain, tag.as_ref(), c_msg.as_ref())
    }

    fn flush(&self) {}
}