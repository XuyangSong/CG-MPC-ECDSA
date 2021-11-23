use anyhow::Result;
use log::Level;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use std::path::PathBuf;

pub fn init_log(path: PathBuf, level: Level) -> Result<()> {
    let logfile = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::default()))
        .build(path)?;

    let config = Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .build(
            Root::builder()
                .appender("logfile")
                .build(level.to_level_filter()),
        )?;

    log4rs::init_config(config)?;
    Ok(())
}
