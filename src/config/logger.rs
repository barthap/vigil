// Vigil
//
// Microservices Status Page
// Copyright: 2018, Valerian Saliou <valerian@valeriansaliou.name>
// License: Mozilla Public License v2.0 (MPL v2.0)

use log;
use log::{Level, LevelFilter, Metadata, Record, SetLoggerError};

pub struct ConfigLogger;

impl log::Log for ConfigLogger {
  fn enabled(&self, metadata: &Metadata) -> bool {
    metadata.level() <= Level::Debug
  }

  fn log(&self, record: &Record) {
    if self.enabled(record.metadata()) {
      use nu_ansi_term::Color as C;
      let level = record.level();
      let level_color = match level {
        Level::Error => C::Red,
        Level::Warn => C::Yellow,
        Level::Info => C::Green,
        Level::Debug => C::Blue,
        Level::Trace => C::Cyan,
      };
      println!(
        "[{}] {}: {}",
        level_color.paint(level.as_str()),
        C::DarkGray.paint(record.module_path().unwrap_or("")),
        record.args()
      );
    }
  }

  fn flush(&self) {}
}

impl ConfigLogger {
  pub fn init(level: LevelFilter) -> Result<(), SetLoggerError> {
    log::set_max_level(level);
    log::set_boxed_logger(Box::new(ConfigLogger))
  }
}
