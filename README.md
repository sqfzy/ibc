# IBC AAKA Scheme - Backend Services (RC & MS)

本项目实现了论文 "A Provably Secure and Efficient Identity-Based Anonymous Authentication Scheme for Mobile Edge Computing" 中描述的后端服务，包括注册中心 (RC) 和 MEC 服务器 (MS)。

服务使用 Rust 编写，Web 框架为 Axum，并依赖 `ibc_aaka_scheme` 核心库。

## 项目结构

本项目包含以下成员：

-   `ibc_aaka_scheme/`: 包含核心密码学协议逻辑的库。
-   `aaka_rc_app/`: 注册中心 (RC) 的 Axum Web 服务应用。
-   `aaka_ms_server/`: MEC 服务器 (MS) 的 Axum Web 服务应用。
-   `aaka_user_app/`: 用于测试的命令行用户模拟器。

## 环境要求

-   Cargo (Rust 的包管理器和构建工具)
-   `nushell` (用于运行 Nu 脚本)
-   `httpie` (用于测试 HTTP API)

## 设置与配置

1.  **克隆仓库:**
    ```bash
    git clone <your-repo-url>
    cd <your-repo-name>
    ```

2. **相关配置**
    ```
    ./aaka_ms_server/config.json # MS 服务器配置文件
    ./aaka_rc_app/config.json # RC 服务器配置文件
    ./aaka_user_app/config.json # 用户应用配置文件

    ./aaka_ms_server/ms_state.json # 保存 MS 服务器状态文件，例如RC密钥
    ./aaka_user_app/user_key.json # 保存用户密钥

    ```

3. **环境变量**
`RC_ADDR`: RC服务地址


4. **测试**
    ```
    nu ./run_test.nu
    ```
