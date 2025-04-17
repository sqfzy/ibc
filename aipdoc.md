# 启动MS, RC服务
```shell
cargo run --bin aaka_rc_app # 默认在3001端口
```
```shell
cargo run --bin aaka_ms_server # 默认在3002端口
```

# **API 文档**

**版本:** 1.0
**基地址:** (根据部署情况填写，例如 `http://localhost:3002` for MS, `http://localhost:3001` for RC)

---

**1. MEC Server (MS) API**

MS 提供核心的用户认证接口。

**端点: `POST /auth/initiate`**

*   **功能:** 处理用户的认证请求，验证用户身份，并返回服务器的响应和（演示目的下）会话密钥。
*   **请求 Body (JSON):**
    *   格式: `AuthRequestPayload`
    *   字段:
        | 字段名    | 类型   | 描述                                                     | 示例值 (Hex)                                                                                                |
        | :-------- | :----- | :------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------- |
        | `m_hex`   | String | 用户计算的 $M = x(\hat{P}_{pub} + h_1 P)$ 点的十六进制表示 | `"8a..."`                                                                                                   |
        | `n`       | String | 用户计算的 $N = h_2(g_x) \oplus (ID_u\|\|R_u\|\|X)$ 的十六进制表示 | `"deadbeef..."`                                                                                             |
        | `sigma_hex` | String | 用户计算的签名 $\sigma = SID_u + x h_3$ 的标量的十六进制表示 | `"123abc..."`                                                                                               |
        | `timestamp` | u64    | 用户发起请求时的 Unix 时间戳 (秒)                        | `1678886400`                                                                                                |
*   **成功响应 (200 OK, JSON):**
    *   格式: `AuthSuccessResponse`
    *   字段:
        | 字段名            | 类型                | 描述                                                                | 示例值 (Hex)                                     |
        | :---------------- | :------------------ | :------------------------------------------------------------------ | :----------------------------------------------- |
        | `message`         | String              | 固定为 "Authentication successful"                                  | `"Authentication successful"`                    |
        | `response`        | `AuthResponsePayload` | 包含服务器响应的具体内容                                            | `{ "t_hex": "...", "y_hex": "...", "timestamp": ... }` |
        | `session_key_hex` | String              | **(仅演示用)** 服务器计算出的会话密钥的十六进制表示                 | `"bfab..."`                                      |
    *   `AuthResponsePayload` 结构:
        | 字段名      | 类型   | 描述                                                         | 示例值 (Hex)     |
        | :---------- | :----- | :----------------------------------------------------------- | :--------------- |
        | `t_hex`     | String | 服务器计算的认证符 $t = h_4$ 的标量的十六进制表示            | `"def456..."`    |
        | `y_hex`     | String | 服务器计算的临时公钥 $Y = yP$ 点的十六进制表示               | `"ab12..."`      |
        | `timestamp` | u64    | 服务器处理请求时的 Unix 时间戳 (秒)                          | `1678886401`     |
*   **失败响应 (例如 500 Internal Server Error):**
    *   **Content-Type:** `text/plain`
    *   **Body:** 包含错误信息的字符串，例如 `"Error: Authentication failed: SignatureVerificationFailed"` 或 `"Error: Authentication failed: InvalidTimestamp"`。

**调用流程 (前端/用户模拟器):**

1.  向 MS 的 `POST /auth/initiate` 发送该 JSON。
2.  **如果成功 (200 OK):**
    *   解析返回的 `AuthSuccessResponse` JSON。
    *   从 `response` 字段中提取 `t_hex`, `y_hex`, `timestamp`。
    *   将 hex 字符串反序列化为 `ServerAuthResponse` 结构体。
    *   调用 `ibc_aaka_scheme::user::process_server_response` 使用 `ServerAuthResponse` 和之前保存的 `UserState` 来验证服务器并计算会话密钥。
    *   (可选，演示用) 比较用户计算的密钥与响应中 `session_key_hex` 是否一致。
3.  **如果失败 (非 200):**
    *   读取响应体中的错误消息并显示给用户。

---

**2. Registration Center (RC) API**

RC 提供系统初始化和实体注册的管理接口。这些接口通常不直接暴露给普通用户。

**端点: `POST /setup`**

*   **功能:** 初始化系统参数和主密钥（如果尚未初始化）。幂等操作，如果已初始化，则不执行任何操作并返回现有参数。
*   **请求 Body:** 无
*   **成功响应 (200 OK, JSON):**
    *   格式: `SystemParametersResponse`
    *   字段:
        | 字段名            | 类型   | 描述                                          | 示例值 (Hex)     |
        | :---------------- | :----- | :-------------------------------------------- | :--------------- |
        | `p_hex`           | String | $G_1$ 生成元 $P$ 的十六进制表示                 | `"97f1..."`      |
        | `p_pub_hex`       | String | 系统公钥 $P_{pub} = sP$ 的十六进制表示          | `"1706..."`      |
        | `p_pub_hat_hex`   | String | 系统公钥 $\hat{P}_{pub} = \hat{s}P$ 的十六进制表示 | `"033a..."`      |
        | `g_hex`           | String | $g = e(P_1, P_2)$ ($G_T$ 元素) 的十六进制表示    | `"0add..."`      |
*   **失败响应 (例如 500 Internal Server Error):**
    *   **Content-Type:** `text/plain`
    *   **Body:** 包含错误信息的字符串。

**端点: `GET /params`**

*   **功能:** 获取当前系统的公共参数。
*   **请求 Body:** 无
*   **成功响应 (200 OK, JSON):**
    *   格式: `SystemParametersResponse` (同 `/setup` 响应)
*   **失败响应 (例如 500 Internal Server Error):**
    *   **Content-Type:** `text/plain`
    *   **Body:** `"Error: System parameters not initialized. Call /setup first."` (如果未 setup) 或其他内部错误。

**端点: `POST /register/user`**

*   **功能:** 注册一个新用户并返回其私钥对。
*   **请求 Body (JSON):**
    *   格式: `RegisterRequest`
    *   字段:
        | 字段名 | 类型   | 描述       | 示例值                |
        | :----- | :----- | :--------- | :-------------------- |
        | `id`   | String | 用户的身份标识 | `"alice@example.com"` |
*   **成功响应 (200 OK, JSON):**
    *   格式: `UserRegistrationResponse`
    *   字段:
        | 字段名      | 类型   | 描述                               | 示例值 (Hex)     |
        | :---------- | :----- | :--------------------------------- | :--------------- |
        | `r_u_hex`   | String | 用户公钥部分 $R_u$ ($G_1$) 的 hex 表示 | `"9424..."`      |
        | `sid_u_hex` | String | 用户私钥部分 $SID_u$ (标量) 的 hex 表示 | `"f0e1..."`      |
*   **失败响应 (例如 500 Internal Server Error):**
    *   **Content-Type:** `text/plain`
    *   **Body:** `"Error: System not initialized. Call /setup first."` 或其他内部错误。

**端点: `POST /register/server`**

*   **功能:** 注册一个新服务器并返回其私钥。
*   **请求 Body (JSON):**
    *   格式: `RegisterRequest`
    *   字段:
        | 字段名 | 类型   | 描述           | 示例值                   |
        | :----- | :----- | :------------- | :----------------------- |
        | `id`   | String | 服务器的身份标识 | `"mec-server-1.edge"`    |
*   **成功响应 (200 OK, JSON):**
    *   格式: `ServerRegistrationResponse`
    *   字段:
        | 字段名         | 类型   | 描述                                    | 示例值 (Hex)     |
        | :------------- | :----- | :-------------------------------------- | :--------------- |
        | `sid_ms_hex`   | String | 服务器私钥 $SID_{ms}$ ($G_2$ 点) 的 hex 表示 | `"b521..."`      |
*   **失败响应 (例如 500 Internal Server Error):**
    *   **Content-Type:** `text/plain`
    *   **Body:** `"Error: System not initialized. Call /setup first."` 或其他内部错误。

---

**通用注意事项:**

*   **Hex 编码:** 所有 `arkworks` 的点和标量在 JSON 中都使用**十六进制字符串**表示。字节向量 `n` 在 MS API 中也使用了十六进制。
*   **序列化:** 使用的是 `ark-serialize` 的**压缩**格式 (`serialize_compressed` / `deserialize_compressed`)。
*   **错误处理:** API 失败时返回非 2xx 状态码，响应体通常是包含错误信息的纯文本。
*   **安全性:** RC 的 API (特别是 `/setup`, `/register/*`) 应该受到严格的访问控制，不应公开暴露。MS 的 `/auth/initiate` 是核心业务接口。所有通信都应使用 HTTPS。
*   **状态管理:** RC 和 MS 的当前实现都是内存状态，重启后丢失。持久化需要额外实现。

这份文档应该能清晰地告诉你的前端伙伴如何与你实现的后端服务进行交互了。
