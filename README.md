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

## 快速开始

```bash
# 直接运行（默认免登录，监听 0.0.0.0:8000）
go run main.go

# 指定端口并启用管理面板密码
go run main.go -port 8080 -password mypass
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
| `-config` | `config.json` | 配置文件路径 |
| `-password` | `""` | 管理面板密码；**留空则不启用认证**（直接打开即用） |
| `-debug` | `false` | 打印详细请求/响应日志 |

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

## 配置文件

`config.json` 结构：

```json
{
  "model_alias": {
    "claude-sonnet": {
      "target_model": "z-ai/glm-5.2",
      "upstream": "nvidia",
      "socks5_proxy": "127.0.0.1:1080",
      "with_reasoning": false
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

- **`model_alias`** — 模型别名映射。`key` 是客户端请求的模型名（客户端只能用这个 key）；`target_model` 是上游实际模型名；`upstream` 指定路由到哪个上游（现在已无"默认上游"，每条别名显式指定上游）；`socks5_proxy` 指定 `socks5_proxies` 中的代理地址（留空直连）；`with_reasoning` 控制是否向上游回传历史 assistant 消息中的 `reasoning_content`
- **`reasoning_effort_map`** — 推理力度映射，将上游不支持的 effort 级别映射到可用级别
- **`socks5_proxies`** — SOCKS5 代理配置列表，供模型映射的 `socks5_proxy` 引用
- **`upstreams`** — 上游配置集合，每个键为上游名称
  - `base_url`：上游 API 根地址
  - `api_key`：API Key；每行一个，可配置多个，按轮询顺序分发
  - `api_type`：`openai`、`anthropic` 或 `openai-responses`
  - `custom_models`：**自定义模型列表，是模型唯一来源**；不依赖上游 `/models` 自动拉取，完全手工维护或点"获取模型列表"按钮自动填入
  - `custom_headers`：**自定义请求头**，键值对；发往该上游的所有请求（对话转发、"获取模型列表"探测、连接保活）都会附加；同名头覆盖网关默认头（如 `Authorization`、`anthropic-version`），`Host` / `Content-Length` 不可覆盖
  - `responses_reasoning_format`：仅用于 Responses 上游；空值使用标准 `reasoning.effort`，`legacy_reasoning_effort` 使用兼容字段 `reasoning_effort`
- **无 `default_upstream` 字段** — 已移除"默认上游"概念；别名的 `upstream` 必须显式指向某个上游（后端保存时会校验引用的上游/代理是否存在，孤儿引用返回 400）

### API Key 多 Key 轮询

`api_key` 字段支持多行写入多个 Key，网关按轮询顺序分发请求。某个 Key 触发 429 / 502 / 503 / 504 时：
- 有多把 Key → **立即切下一把 Key**，不等待
- 只有一把 Key → 指数退避重试（1s → 2s → 4s … 30s 封顶）

不再解析上游的 `Retry-After` 响应头（不同上游格式不一致，避免歧义）。

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

## 协议转换矩阵

| 下游 \ 上游 | OpenAI Chat | Anthropic Messages | Responses API |
|-------------|:-----------:|:-----------------:|:-------------:|
| **OpenAI Chat** | 直通 | 格式转换 | 格式转换 |
| **Anthropic** | 格式转换 | 直通 | 格式转换 |
| **Responses** | 格式转换 | 格式转换 | 直通 |

直通（passthrough）模式下，请求体只替换 `model` 字段后原样转发，转换开销最低。

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
├── main.go      # 项目唯一入口：全部业务逻辑 + 内嵌管理面板
├── README.md    # 本文件
└── .gitignore   # 忽略密钥与运行时数据
```

部署只需要 `main.go` 一个文件即可编译运行；下列文件由程序自动生成，属本地数据，不要提交：

| 文件 | 说明 |
|------|------|
| `config.json` | 配置；首次运行自动创建为空配置，之后在管理面板里填 |
| `stats.json` | 使用统计（每日聚合 + 请求明细） |
| `pricing.json` | 费用估算单价（可选） |

## 环境要求

- Go 1.21+
- Windows / Linux / macOS

## 注意事项

- 默认 `api_type` 为 `openai`，如上游是 Anthropic 或 Responses API 请对应填写
- 自定义请求头在网关默认头之后应用：同名头会覆盖默认值（例如自定义 `Authorization` 走其他鉴权方案）；需要额外租户/网关标识头时直接填写即可
- 仅在上游要求或支持历史 `reasoning_content` 时启用 `with_reasoning`；不支持该字段的上游可能拒绝请求
- Anthropic 直通模式下，系统消息中的 `x-anthropic-billing-header` 会被自动清洗
- 流式请求会自动注入 `stream_options.include_usage: true` 以确保 token 统计准确
- 管理面板 `-password` 默认为空（不启用认证），请仅在可信网络中使用；需启用认证时用 `-password` 指定
- 已不再有"默认上游"概念：所有别名必须显式指定上游；客户端只能用已配置的别名调 `/v1/*`
