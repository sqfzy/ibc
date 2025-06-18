use tracing_error::ErrorLayer;
use tracing_subscriber::{
    EnvFilter,
    fmt::{self, MakeWriter},
    prelude::*,
};

/// 初始化一个 subscriber，它将日志以 JSON 格式异步写入到指定的 `sink`。
///
/// # Arguments
/// * `sink` - 一个实现了 `MakeWriter` 的目标，例如 `std::io::stdout` 或 `non_blocking_writer`。
pub fn init_subscriber<W>(sink: W)
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    // `EnvFilter` 从 `RUST_LOG` 环境变量读取日志级别配置。
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("INFO"));

    #[cfg(feature = "debug")]
    {
        color_eyre::install().expect("Failed to install color_eyre");

        let formatting_layer = fmt::layer().with_ansi(true).pretty().with_writer(sink);

        let subscriber = tracing_subscriber::registry()
            .with(env_filter)
            .with(formatting_layer) // 便于机器分析
            .with(ErrorLayer::default()); // 便于追踪错误信息

        // 设置全局 subscriber
        tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set global tracing subscriber");

        return;
    }

    // 创建 JSON 格式化层
    let formatting_layer = fmt::layer()
        .json() // <-- 1. 结构化 (JSON)
        .with_writer(sink); // <-- 2. 异步写入 (通过传入的 sink)

    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(formatting_layer) // 便于机器分析
        .with(ErrorLayer::default()); // 便于追踪错误信息

    // 设置全局 subscriber
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set global tracing subscriber");
}
