# IBC AAKA Scheme - Backend Services (RC & MS)

本项目实现了论文 "A Provably Secure and Efficient Identity-Based Anonymous Authentication Scheme for Mobile Edge Computing" 中描述的后端服务，包括注册中心 (RC) 和 MEC 服务器 (MS)。

服务使用 Rust 编写，Web 框架为 Axum，并依赖 `ibc_aaka_scheme` 核心库。

## 项目结构

本项目是一个 Cargo workspace，包含以下成员：

-   `ibc_aaka_scheme/`: 包含核心密码学协议逻辑的库。
-   `aaka_rc_app/`: 注册中心 (RC) 的 Axum Web 服务应用。
-   `aaka_ms_server/`: MEC 服务器 (MS) 的 Axum Web 服务应用。
-   `aaka_user_app/`: (可选) 用于测试的命令行用户模拟器。

## 环境要求

-   Rust 工具链 (最新稳定版推荐，例如通过 `rustup` 安装)
-   Cargo (Rust 的包管理器和构建工具)
-   `jq` (命令行 JSON 处理工具，用于测试脚本提取数据，可选但推荐)
-   `curl` (用于手动测试 API 或被测试脚本使用)

## 设置与配置

1.  **克隆仓库:**
    ```bash
    git clone <your-repo-url>
    cd <your-repo-name>
    ```

2.  **创建 `.env` 文件 (可选):**
    在项目的根目录（workspace 根目录）创建一个名为 `.env` 的文件。这个文件用于配置服务的监听地址和（对于 MS）RC 服务的地址。复制以下内容并根据需要修改：

    ```dotenv
    # .env

    # RC 服务监听地址和端口
    RC_LISTEN_ADDR=0.0.0.0:3001

    # MS 服务监听地址和端口
    MS_LISTEN_ADDR=0.0.0.0:3002

    # MS 服务需要知道的 RC 服务 URL (用于自动获取参数)
    MS_RC_URL=http://localhost:3001

    # MS 服务器自身的身份 ID (用于向 RC 注册)
    MS_SERVER_ID="mec-server-1.edge"

    # MS 服务器的密钥和参数
    # MS_PARAMS_P_HEX=...
    # MS_PARAMS_P_PUB_HEX=...
    # MS_PARAMS_P_PUB_HAT_HEX=...
    # MS_PARAMS_G_HEX=...
    # MS_SSK_SID_MS_HEX=...
    ```

## 构建项目

在项目根目录运行以下命令来构建所有应用：

```bash
cargo build
