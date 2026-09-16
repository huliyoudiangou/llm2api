# LLM Gateway

一个支持多上游、多协议转换的 LLM 代理网关。将上游的 OpenAI / Anthropic / Responses API 统一转换为 OpenAI Chat 格式对外提供，同时支持 Anthropic Messages 和 OpenAI Responses 协议的透传与转换。客户端只用配置的"别名"发请求，网关按别名路由到对应上游、做协议互转、转发并记录 Token 用量。

## 核心特性

- **多协议兼容**：同时暴露 OpenAI Chat Completions (`/v1/chat/completions`)、Anthropic Messages (`/v1/messages`)、OpenAI Responses (`/v1/responses`) 三个接口
- **上游格式转换**：自动在上游协议与 OpenAI 协议之间双向转换，包括消息格式、工具调用 (tool use)、thinking / reasoning 字段、SSE 流式事件等
- **多上游管理**：支持配置多个上游，按名称区分；每个上游支持多 API Key 轮询和自定义请求头
- **模型别名（严格）**：客户端只能使用 `model_alias` 里配置的别名；裸上游模型名一律返回 400。别名将请求模型名映射到上游实际模型，支持跨上游路由、独立代理出口和历史 `reasoning_content` 回传
- **模型唯一来源 = custom_models**：每个上游的 `custom_models` 是模型唯一来源，完全由用户手工填写或点"获取模型列表"实时拉取后存入；启动/重载不再自动联网拉取上游 `/models`
- **按模型代理出口**：保存 SOCKS5 代理配置，并可在每个模型映射中独立选择代理出口；默认直连
- **智能重试**：429 / 502 / 503 / 504 自动重试。多 Key 遇到这些错误**立即切下一把 Key 不等待**；只有单 Key 才走指数退避（1→2→4…→30s 封顶）。不解析 `Retry-After`
- **流式透传**：SSE 流经过网关时保持实时转发，不缓冲整条响应
- **同协议真透传**：OpenAI Chat → OpenAI Chat 仅替换顶层 `model` 字段，不重建 messages，保留原始字节前缀以最大化上游 prompt/prefix cache 命中；Anthropic Messages / Responses API 同协议入口同样走轻量透传
- **Anthropic 缓存最大化**：自动在 system 和最后一个 user 消息上标记 `cache_control: {"type":"ephemeral"}`，不在每条历史消息重复打点；配合已发送的 `anthropic-beta: prompt-caching-2025-01-31` 提升缓存命中
- **使用统计（cc-switch 风格）**：自动记录每次请求的上游、模型、请求数、输入/输出/缓存读/缓存写/思考 token、耗时、首字延迟与状态，持久化到 `stats.json`
- **每日聚合与明细**：按「日期 + 上游 + 模型」聚合保留 90 天，另保留最近 500 条请求明细；费用估算单价配置在 `pricing.json`（每百万 token）
- **管理面板**：内嵌 Web UI，自托管、无任何外部资源依赖；支持热加载配置、查看统计、管理上游/别名/代理；可选密码认证
- **WorkBuddy (CodeBuddy) 账号池上游**（`api_type: "workbuddy"`，集成 [workbuddy2api](https://github.com/Sliverkiss/workbuddy2api) 能力）：把 CodeBuddy / WorkBuddy 账号当作上游用——内置 OAuth 设备授权登录、多账号轮转与在途租约、分级冷却/熔断（429 软冷却、402 硬冷却至次日 04:00、12153 session 失效禁用、6004 模型级限流独立冷却）、access token 临期自动刷新并原子写回凭证、会话粘性（同对话尽量同账号）、出站强制流式 + 帧规范化（tool_calls 函数名跨分片回填）、DeepSeek 思维链注入、Claude Code/Codex 指纹脱敏、CN / Global 双域按账号 realm 自动路由、模型列表动态探测、每日自动签到。详见下文「WorkBuddy 上游」

## 快速开始

```bash
# 直接运行（默认免登录，仅监听本机 127.0.0.1:8000）
go run .

# 指定端口并启用管理面板密码
go run . -port 8080 -password mypass

# 需要局域网访问时显式放开监听，并务必同时设置密码
go run . -listen 0.0.0.0 -port 8080 -password mypass

# 编译单文件二进制
go build -trimpath -ldflags "-s -w" -o llm-gateway.exe .
```

浏览器打开 `http://localhost:8000/` 进入管理面板。默认 `-password` 为空——直接可用；指定密码后需先登录。

首次运行会在当前目录自动生成空的 `config.json`（无需手工创建模板），之后在管理面板里添加上游与别名即可；
也可按下方「配置文件」一节手写 `config.json` 后重启。

新上游配置流程：

1. 管理面板 → "上游配置" → 添加上游；填名称、Base URL、API Key
2. 在"自定义模型"字段：手工填写，或点"获取模型列表"按钮，后端会实时调用上游 `/models` 拉取并自动填入
3. 保存上游配置
4. "模型映射" → 添加别名（请求名）→ 选上游 → 选实际模型（该上游的 custom_models 列表）→ 可选代理/回传 reasoning_content
5. 保存后，客户端用这个别名词请求 `/v1/*` 即可

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-port` | `8000` | 监听端口 |
| `-listen` | `127.0.0.1` | 监听地址；默认仅本机回环。需要局域网访问时指定（如 `-listen 0.0.0.0`），**并务必同时设置 `-password`** |
| `-config` | `config.json` | 配置文件路径 |
| `-password` | `""` | 管理面板密码；**留空则不启用认证**（直接打开即用） |
| `-debug` | `false` | 打印详细请求/响应日志 |
| `-wb-login` | `""` | WorkBuddy OAuth 设备授权登录（`url` 或 `poll`），完成即退出、不启服务；详见「WorkBuddy 上游」 |
| `-workbuddy-login` | `""` | 同 `-wb-login` |
| `-wb-realm` | `cn` | 登录域：`cn`（国内版 CodeBuddy）/ `global`（国际版 WorkBuddy） |
| `-wb-auth-dir` | `auths` | 登录命令写凭证的目录（相对 `-config` 所在目录或绝对路径） |
| `-wb-proxy` | `""` | 登录流走 SOCKS5 代理（需在 `socks5_proxies` 中配置该地址） |

## API 端点

公开接口：

| 路径 | 方法 | 说明 |
|------|------|------|
| `/v1/chat/completions` | POST | OpenAI Chat 接口 |
| `/v1/messages` | POST | Anthropic Messages 接口 |
| `/v1/responses` | POST | OpenAI Responses 接口 |
| `/v1/models` | GET | 列出可用模型（**只列别名**，不暴露上游 custom_models） |
| `/health` | GET | 健康检查，返回 `OK` |
| `/login` | GET/POST | 管理面板登录 |
| `/logout` | POST | 退出登录 |

管理接口（需认证）：

| 路径 | 方法 | 说明 |
|------|------|------|
| `/api/config` | GET/POST | 读取 / 更新配置 |
| `/api/stats` | GET/DELETE | 查看 / 清空统计（旧接口，面板已改用 `/api/usage`） |
| `/api/usage` | GET | 使用统计汇总：`?range=today\|7d\|14d\|30d\|all` |
| `/api/usage/log` | GET | 请求明细分页：`?page=1&size=20&status=ok\|err&q=关键词` |
| `/api/pricing` | GET/POST | 查看 / 保存费用估算单价 |
| `/api/reload` | POST | 修复历史统计中被误记成"模型名"的上游字段（**不重载 config.json**；改配置请用管理面板保存，或重启进程） |
| `/api/upstream/models` | POST | 用临时配置或已保存配置实时拉取上游的模型列表 |
| `/api/wb/status` | GET | WorkBuddy 账号池状态（**先重扫凭证目录**：手动增删的 `auths/` 文件即时生效）；含各号域/冷却/熔断/禁用/在途；`?credits=1` 附带余额查询（逐个调上游，较慢） |
| `/api/wb/checkin` | POST | 手动触发 WorkBuddy CN 账号每日签到；`?upstream=名称` 只签指定上游 |
| `/api/wb/login` | POST/GET | WorkBuddy 面板 OAuth 登录：`POST {action:"start",realm,dir?,proxy?}` 返回 `auth_url`+会话 id 并由**服务器后台接管轮询**（浏览器标签页可关）；`GET ?id=` 拉状态（`pending`/`success`/`expired`/`error`）。成功后凭证自动落盘 + 账号池热加载，无需重启 |

## 配置文件

`config.json` 结构：

```json
{
  "model_alias": {
    "claude-sonnet": {
      "target_model": "z-ai/glm-5.2",
      "upstream": "nvidia",
      "socks5_proxy": "127.0.0.1:1080",
      "with_reasoning": false,
      "system_prompt": "你是一位资深的编程助手"
    }
  },
  "reasoning_effort_map": {
    "low": "high",
    "medium": "high",
    "xhigh": "max"
  },
  "socks5_proxies": [
    {
      "addr": "127.0.0.1:1080",
      "username": "",
      "password": "",
      "name": "proxy-1"
    }
  ],
  "upstreams": {
    "nvidia": {
      "base_url": "https://integrate.api.nvidia.com/v1",
      "api_key": "nvapi-xxx",
      "api_type": "openai",
      "custom_models": ["z-ai/glm-5.2"],
      "custom_headers": {
        "X-Custom-Header": "value"
      }
    },
    "responses-main": {
      "base_url": "https://example.com/v1",
      "api_key": "sk-xxx",
      "api_type": "openai-responses",
      "responses_reasoning_format": ""
    }
  }
}
```

### 字段说明

- **`model_alias`** — 模型别名映射。`key` 是客户端请求的模型名（客户端只能用这个 key）；`target_model` 是上游实际模型名；`upstream` 指定路由到哪个上游（现在已无"默认上游"，每条别名显式指定上游）；`socks5_proxy` 指定 `socks5_proxies` 中的代理地址（留空直连）；`with_reasoning` 控制是否向上游回传历史 assistant 消息中的 `reasoning_content`；`system_prompt` 是**角色提示**（可选）：每次请求自动注入到上游请求的最前面，客户端自带 system 内容会合并在其后；留空则完全不注入，保持默认行为
- **`reasoning_effort_map`** — 推理力度映射，将上游不支持的 effort 级别映射到可用级别
- **`socks5_proxies`** — SOCKS5 代理配置列表，供模型映射的 `socks5_proxy` 引用
- **`upstreams`** — 上游配置集合，每个键为上游名称
  - `base_url`：上游 API 根地址
  - `api_key`：API Key；每行一个，可配置多个，按轮询顺序分发
  - `api_type`：`openai`、`anthropic`、`openai-responses` 或 `workbuddy`（WorkBuddy/CodeBuddy 账号池，见下文）
  - `custom_models`：**自定义模型列表，是模型唯一来源**；不依赖上游 `/models` 自动拉取，完全手工维护或点"获取模型列表"按钮自动填入
  - `custom_headers`：**自定义请求头**，键值对；发往该上游的所有请求（对话转发、"获取模型列表"探测、连接保活）都会附加；同名头覆盖网关默认头（如 `Authorization`、`anthropic-version`），`Host` / `Content-Length` 不可覆盖
  - `responses_reasoning_format`：仅用于 Responses 上游；空值使用标准 `reasoning.effort`，`legacy_reasoning_effort` 使用兼容字段 `reasoning_effort`
- **无 `default_upstream` 字段** — 已移除"默认上游"概念；别名的 `upstream` 必须显式指向某个上游（后端保存时会校验引用的上游/代理是否存在，孤儿引用返回 400）

### API Key 多 Key 轮询

`api_key` 字段支持多行写入多个 Key，网关按轮询顺序分发请求。某个 Key 触发 429 / 502 / 503 / 504 时：
- 有多把 Key → **立即切下一把 Key**，不等待
- 只有一把 Key → 指数退避重试（1s → 2s → 4s … 30s 封顶）

每个请求的「状态码重试」（含多 Key 切换）最多 8 次，超过后把最后一次上游错误原样返回客户端——避免上游持续 429/5xx 时形成零等待重试风暴。传输级错误（拨号失败/连接重置）另有 4 次上限。不再解析上游的 `Retry-After` 响应头（不同上游格式不一致，避免歧义）。

### 按模型选择 SOCKS5 出口

SOCKS5 代理先统一配置在 `socks5_proxies` 中，再由模型映射的 `socks5_proxy` 引用其 `addr`：

- `socks5_proxy` 为空时直连
- 每个模型映射可以选择不同的代理出口
- Chat、Anthropic Messages、Responses 的流式和非流式请求都会使用对应出口
- 代理配置删除后引用失效：前端下拉显示"（已失效）"项；保存时后端校验孤儿代理引用并返回 400
- 不提供全局启用、轮询或收到 429 后自动切换 SOCKS5 的功能

### Reasoning 参数

- `with_reasoning` 只控制是否将历史 assistant 消息中的 `reasoning_content` 回传上游
- `with_reasoning` 不会主动启用模型思考，也不控制响应是否返回 `reasoning_content`
- 当前请求的 `thinking` 和 `reasoning_effort` 独立转发，不受 `with_reasoning` 开关影响
- `reasoning_effort_map` 只转换匹配到的 effort 值，未配置的值保持原样

### 角色提示（system_prompt）

每个别名可配置 `system_prompt` 作为该模型的固定角色提示：

- **留空（默认）**：完全不注入，请求原样转发，行为与之前版本一致
- **已配置**：每次请求自动注入，按协议映射为对应字段——
  - OpenAI Chat 上游：注入为 messages 最前面的 `system` 消息
  - Anthropic 上游：注入为请求的 `system` 字段（自动带 cache_control 缓存标记）
  - Responses 上游：注入为 `instructions` 字段
- 客户端请求中自带的 system 内容会**合并在角色提示之后**（角色提示优先）
- 配置了 `system_prompt` 的别名会跳过同协议快速透传，走完整转换路径完成注入
- 管理面板「模型映射」表格中可直接填写，不填即默认

## WorkBuddy 上游（`api_type: "workbuddy"`）

把 **CodeBuddy（国内版 `cn`）/ WorkBuddy（国际版 `global`）账号**当作一类上游接入，功能对齐
[Sliverkiss/workbuddy2api](https://github.com/Sliverkiss/workbuddy2api)（MIT），但复用本网关的别名路由、代理出口、协议互转（Chat / Anthropic Messages / Responses 三入口都可用）、统计与面板——不额外跑独立进程。

官方不提供 OpenAI 形态的开放 API，WorkBuddy 账号经 **OAuth 设备授权**换取 access/refresh token，网关侧做 token 自动刷新、多账号调度与流量治理。

> ⚠️ 合规边界同上游项目：非官方网关，仅限**本人授权账号**、本机 / 私有环境测试；账号封禁、条款违约风险自负。凭证目录含明文 token，妥善保管。

### 快速上手

**推荐：管理面板登录**（无需命令行）。打开 `http://localhost:8000/`，「WorkBuddy 账号池」卡片：

1. 选域（国内版 / 国际版）+ 出口代理（国际版通常需走 Clash，国内版直连），点 **「浏览器登录」**；
2. 浏览器打开弹出的授权链接完成登录（国内版微信扫码 / 国际版邮箱·验证码·SSO）；
3. **回来这个页面可以关掉，不影响入库**——登录由网关服务器后台接管（15 分钟窗口），成功后自动落盘 `auths/workbuddy-<uid>.json`、自动进账号池，账号表立即出现该号，**无需重启**。

再「多上游配置」里加一个接口类型 = WorkBuddy 的上游（凭证目录 `auths`、点「获取模型列表」探测）、建别名即可用。重复登录可叠加多账号；面板上也能 **「手动签到」** 与查看各号 **可用/冷却/熔断/禁用** 状态。

<details><summary>命令行方式（面板不可用 / 远程无头部署时的兜底）</summary>

```bash
# 两段式：url 取授权链接 → 浏览器登录 → poll 落盘
llm-gateway.exe -wb-login=url  -wb-realm=cn -config config.json
llm-gateway.exe -wb-login=poll -wb-realm=cn -config config.json
# 国际版：-wb-realm=global；走代理加 -wb-proxy=127.0.0.1:7897（需先在 SOCKS5 代理配置里登记）
```

</details>

运行中的网关自动发现 `auths/` 里的凭证变化：面板登录成功即时入池；手动拷入/删除凭证文件后，点账号池卡片的 **「刷新状态」**（或 `/api/wb/status`）即重扫生效；后台每 30 分钟也会自动重扫兜底。用新凭证**重新登录/覆盖**同一账号时，其禁用/冷却/熔断标记自动清除、恢复调度；凭证未变的刷新只更新状态、不动运行期数据。

### 配置字段（上游级，仅 `api_type: "workbuddy"` 生效）

```json
"upstreams": {
  "workbuddy": {
    "api_type": "workbuddy",
    "custom_models": ["deepseek-v4-flash", "glm-5.2", "global:gpt-5.6-sol"],
    "wb_auth_dir": "auths",
    "wb_realm": "all",
    "wb_max_in_flight": 3,
    "wb_prompt_mode": "passthrough",
    "wb_prompt_text": "",
    "wb_sanitize": true,
    "wb_checkin": true
  }
}
```

- 不需要 `base_url` / `api_key`：端点由账号域内置决定（`cn` → `copilot.tencent.com`，`global` → `www.workbuddy.ai`）
- `custom_models` 是模型唯一来源（与其他上游一致，供别名选择）；点「获取模型列表」会**从账号池按域实时探测**（每域取最多 2 个账号的结果并集）：`wb_realm=cn` 只探国内版、`global` 只探国际版、`all` 两域都探并合并。**命名与路由严格对齐**：显式单域上游返回裸名（域由上游兜底）；`all` 混池时国际版结果自动加 `global:` 前缀。某域池内无账号时**不列该域模型**（避免配出必然 503 的别名）；账号探测全失败才回退内置静态名单
- `wb_realm`：账号域过滤——`all`（默认，池内 cn/global 账号都可用）/ `cn` / `global`
- **`cn:` / `global:` 前缀**（与上游项目同协议）：模型名带前缀即强制路由到对应域（优先级高于 `wb_realm`）；无前缀默认 `cn`。Global 域先打 `/console/chat/completions`，404/405 自动回退 `/v2/chat/completions`
- `wb_max_in_flight`：单账号最大在途请求（默认 3），占满的账号不参与选号
- `wb_prompt_mode`：`passthrough`（默认，透传客户端 system）/ `custom`（用网关自有提示词替换 system，从源头消除模板句误报；`wb_prompt_text` 自定义，留空用内置工程助手提示词）
- `wb_sanitize`（默认 true）：出站指纹脱敏——剥离 `x-anthropic-billing-header` / `cc_*` 键值，对 Claude Code / Codex CLI 固定模板句做最小改写，消除上游按逐字指纹拦截的 `11128` 反探测
- `wb_checkin`（默认关）：后台窗口（09 点后）为 CN 账号自动每日签到（幂等）
- 进阶可选项：`wb_chat_base_cn` / `wb_chat_base_global`（端点覆盖）、`wb_user_agent` / `wb_client_version` / `wb_cli_version` / `wb_client_name`（归因与 UA）、`wb_device_token`（设备风控头）
- 账号凭证明文文件与上游项目格式完全一致（嵌套形 `{"auth":{...},"account":{...}}`，兼容扁平形）；刷新后轮转的 refresh token 会**原子写回原文件**，重启后凭文件里的 refresh token 继续可用

### 账号池与流量治理

- **选号**：域 + 模型过滤 → 剔除禁用/冷却/熔断/在途满 → 最久未用者优先、均匀轮转；单请求最多换号 4 次（`no_healthy_account` 时返回 503）
- **分级冷却/熔断**（对齐上游项目状态机语义）：
  - `402` / 余额关键词 → 硬冷却至**次日 04:00**（等签到恢复）
  - `429` / 限流文案 → 软冷却 600s 起、连击指数退避封顶 2h；业务码 `6004`（模型级用量超限）带「将在 … 重置」时**只冷却该模型**，切其他模型立即可用
  - `12153` offline session → **禁用**该账号（需重新登录）；`11140 request illegal` → 禁用；`14017 trial` → 软冷却
  - 上游偶发 `404` → 60s 浅冷却；`5xx` 连击 3 次 → 熔断 30m 起、指数退避封顶 6h
  - 内容审核拦截（`11128` 类）与参数解析失败（`11101`）**不罚账号**：前者直接回防火墙口径 400，后者照常换号再试
- **会话粘性**：同对话（`conversationId` / `metadata.conversation_id`，兜底最后一条 user 消息）尽量绑定同账号（TTL 30min），保证多轮上下文与上游缓存命中；绑定号被冷却/禁用时自动解绑重分配
- **token 治理**：请求前 access token 剩余 <10min 即刷新；后台每 30min 为剩余 <12h 的账号保活刷新；刷新失败遇 session 失效自动禁用
- **观测**：`/api/wb/status` 看池状态（禁用原因/冷却截止/在途/失败连击/token 过期），`?credits=1` 附带各账号剩余积分；`/api/wb/checkin` 手动签到
- 冷却/熔断状态为**内存态**（重启清零，凭证本身已落盘不受影响）

### 与上游项目的能力差异

本网关只接入「账号当上游」的核心链路；上游项目的定时猫猫旅行 / 活跃上报 / 开学季抽奖、Upstash Redis 镜像、成本账本择优选号、`/healthz`/`/status` 独立端点、`credit.sh`/`signin.sh` 等**未集成**（签到与余额已提供等效端点）。需要这些边缘能力请直接用原项目。

## 协议转换矩阵

| 下游 \ 上游 | OpenAI Chat | WorkBuddy | Anthropic Messages | Responses API |
|-------------|:-----------:|:---------:|:-----------------:|:-------------:|
| **OpenAI Chat** | 直通 | 改写转发¹ | 格式转换 | 格式转换 |
| **Anthropic** | 格式转换 | 格式转换 | 直通 | 格式转换 |
| **Responses** | 格式转换 | 格式转换 | 格式转换 | 直通 |

直通（passthrough）模式下，请求体只替换 `model` 字段后原样转发，转换开销最低。

¹ WorkBuddy 上游按 OpenAI Chat 协议转发（强制 `stream:true`，非流式客户端由网关本地聚合 SSE），并叠加账号鉴权头、出站改写管线与帧规范化；三种下游入口（Chat / Anthropic / Responses）均可路由到 WorkBuddy 上游。

## 请求流程

```
客户端请求（model 必须是已配置的别名，否则 400）
    │
    ▼
模型解析（别名 → target_model → 上游）
    │
    ▼
格式转换（Anthropic / Responses → 上游所需协议）
    │
    ▼
上游调用（按别名代理出口 + 多 Key 轮询 + 自动重试）
    │
    ▼
响应转换（上游协议 → 下游协议）
    │
    ▼
使用统计记录（上游/耗时/token 拆分/状态） → 返回客户端
```

## 管理面板

- **使用统计**：顶部汇总卡片（请求数 / 成功率 / 输入·输出·缓存·思考 token / 平均耗时 / 首字延迟 / 估算费用）+ 每日趋势柱状图；下方"模型用量 / 上游用量 / 请求明细 / 累计统计"四张明细表
- **表格翻页**：窗口宽度不足时表格自动按列分页（首列固定，`‹ 列 2/3 ›` 切换），行数过多时按行分页，请求明细走服务端分页（每页 10/20/50/100 条），均支持搜索与状态筛选
- **费用估算**：面板底部"费用估算设置"中按模型填写每百万 token 单价（别名或上游模型名均可，支持 `default` 兜底），保存后立即对历史聚合重新计价
- **上游配置**：可折叠卡片增删改上游；折叠摘要显示名称、协议、Base URL、Key 数和自定义模型数
- **上游编辑**：展开卡片后分别编辑名称、接口类型、Base URL、多行 API Key、自定义请求头和自定义模型；"自定义模型"字段旁有"获取模型列表"按钮，点击后弹起抓取并自动填入；Responses 上游额外显示推理参数格式
- **自定义请求头**：上游卡片中每行一条、格式 `名称: 值`；折叠摘要显示已配置的请求头数量，保存时空值头自动丢弃、键值自动去除首尾空白
- **模型映射**：可视化配置别名路由、跨上游跳转、代理出口以及历史 `reasoning_content` 回传。上游列和模型列在下拉为空时显示 disabled 占位；非空时直接列选项、无空占位项，避免列表为空时的误操作
- **SOCKS5 代理配置**：可视化管理代理条目，并在模型映射中选择对应出口；删除代理后引用显示"（已失效）"
- **推理力度映射**：位于模型映射底部的折叠高级设置，自定义 effort 级别转换规则
- **保存校验**：别名 key 为空/重复 → toast 拦截；后端额外校验别名引用的上游/代理是否存在，孤儿引用返回 400
- **完全自托管**：管理面板的所有 HTML/CSS/JS 都内嵌在 main.go 里，不引用任何外部 CDN / 字体 / 图标，离线/内网环境无障碍使用

## 目录结构

仓库只保留必要内容：

```
llm2api/
├── go.mod         # 模块定义（stdlib-only，无第三方依赖）
├── main.go        # 网关主体：协议转换 + 上游路由 + 内嵌管理面板
├── workbuddy.go   # WorkBuddy (CodeBuddy) 账号池上游：登录/池治理/出站改写/SSE
├── README.md      # 本文件
└── .gitignore     # 忽略密钥与运行时数据
```

编译运行 `go build` / `go run .` 即可（纯标准库，无需联网拉依赖）；下列文件由程序生成或本地维护，属本地数据，不要提交：

| 文件 | 说明 |
|------|------|
| `config.json` | 配置；首次运行自动创建为空配置，之后在管理面板里填 |
| `stats.json` | 使用统计（每日聚合 + 请求明细） |
| `pricing.json` | 费用估算单价（可选） |
| `auths/` | WorkBuddy 账号凭证目录（`workbuddy-<uid>.json`，明文 token，`-wb-login` 落盘） |

## 环境要求

- Go 1.21+
- Windows / Linux / macOS

## 注意事项

- 默认 `api_type` 为 `openai`，如上游是 Anthropic 或 Responses API 请对应填写
- 自定义请求头在网关默认头之后应用：同名头会覆盖默认值（例如自定义 `Authorization` 走其他鉴权方案）；需要额外租户/网关标识头时直接填写即可
- 仅在上游要求或支持历史 `reasoning_content` 时启用 `with_reasoning`；不支持该字段的上游可能拒绝请求
- Anthropic 直通模式下，系统消息中的 `x-anthropic-billing-header` 会被自动清洗
- 流式请求会自动注入 `stream_options.include_usage: true` 以确保 token 统计准确
- 管理面板 `-password` 默认为空（不启用认证）。**服务默认只监听本机回环 `127.0.0.1`**，局域网设备无法访问；确需局域网访问时用 `-listen 0.0.0.0` 放开并务必同时设置 `-password`
- 管理接口的写请求（POST/DELETE）带异源 `Origin` 头时会被拒绝（防跨站 CSRF）；`curl` 等不带 `Origin` 的脚本不受影响
- `config.json` / `stats.json` / `pricing.json` 均为「临时文件 + 原子改名」写入，进程崩溃不会留下半截 JSON；文件损坏时启动会备份为 `*.bad-<时间戳>` 后再以空配置继续，不再用空配置覆盖原件
- 已不再有"默认上游"概念：所有别名必须显式指定上游；客户端只能用已配置的别名调 `/v1/*`
