# CPA Key Model Access 插件

CLIProxyAPI（CPA）的原生动态库扩展插件。在 CPA 保持顶层 API Key 基础认证的前提下，基于请求与目录上下文读取调用者身份，提供**全局模型禁用**与**按 API Key 细粒度模型访问控制（Allow / Deny）**，并支持下游客户端模型目录的动态过滤。

---

## 1. 解决的核心问题

1. **缺乏按 Key 细粒度的模型权限隔离**：CPA 原生仅支持对上游 OAuth 凭据进行模型禁用，无法为不同的下游 API Key 分配不同的可用模型范围。当多个团队或不同用途的客户端共享同一套 CPA 实例时，无法防止低权限 Key 滥用高成本或特定渠道模型。
2. **缺乏一键全局强拦截机制**：当某个模型发生故障、超额或需要全网下线时，传统方式需要逐个凭据或逐个 Key 配置，容易出现疏漏；需要提供一个对所有凭据、所有 Key 立即生效的全局拦截防线。
3. **客户端模型目录展示与权限脱节**：下游客户端（如 OpenAI SDK、Codex、Claude Desktop、Chatbox 等）拉取 `/v1/models` 目录时，如果返回全量模型，用户在选择器中依然能看到已被禁用的模型，发起调用后才报错，用户体验割裂。

---

## 2. 技术方案与核心架构

### 2.1 判定流转引擎

插件采用分层级联判定逻辑，严格按照以下优先级执行检查：

```text
下游请求到达 CPA
       │
       ▼
[阶段 1: 全局禁用 (Global Deny)]
       ├── 命中全局禁用规则 ────────────► 立即拒绝 (403: global_deny)
       ▼ 未命中
[阶段 2: Key 级禁用 (Key Deny)]
       ├── 命中该 Key 的 deny_models ───► 立即拒绝 (403: key_deny)
       ▼ 未命中
[阶段 3: Key 级允许 (Key Allow)]
       ├── Key 配置了 allow_models:
       │     ├── 命中白名单 ─────────────► 放行并转发至上游
       │     └── 未命中白名单 ───────────► 拒绝访问 (403: not_allowed)
       └── Key 未配置 allow_models:
             └── 默认放行 ───────────────► 放行并转发至上游
```

- **多模式通配匹配**：支持精确模型名称、家族通配符（如 `gpt-*`、`claude-*`）、内部预热路由通配符（`warmup-*/*`）及自定义模式。匹配过程忽略大小写。
- **后缀与别名归一化**：自动识别 CPA 的推理级别后缀（如 `(high)`、`(8192)`）与别名映射，确保规则始终匹配到实际生效的模型标识。

### 2.2 请求拦截 (RequestInterceptor)

- 挂载 CPA 原生 C-ABI `RequestInterceptor` 钩子。
- 依赖 CPA 鉴权后注入的确定性调用者身份标识（`Metadata.caller_scope`），插件仅使用该 scope 检索策略，不在插件内明文持久化或传递真实 API Key。
- 遇到规则拒绝时，主动返回标准化的结构化 `403` 错误，阻断请求流向上游。

### 2.3 目录动态过滤 (CatalogFilter)

- 拦截并过滤下游获取模型列表的请求，涵盖 OpenAI（`data/id`）、Codex（`models/slug`）、Claude 目录及 Gemini（`models/name`）。
- 结合全局禁用清单与当前发起请求的 API Key 策略，实时剔除不可用的模型条目。
- 保证客户端“所见即可用”，从源头上避免客户端误选不可用模型。

### 2.4 内嵌管理面板与原子持久化

- **无缝嵌入 CPAMC**：插件 Web UI 注册为原生管理面板，自动复用 CPAMC 既有会话与主题风格，无需单独输入管理凭据。
- **直观的模型选择器**：管理界面内置统一的模型选择器与通配符分组，告别繁琐的手动输入与拼写错误。
- **原子化文件存储**：策略独立持久化存储为 TOML 或 YAML 文件，支持基于 ETag / `If-Match` 的并发修改保护与内存热重载。

---

## 3. 配置示例

### 3.1 CPA `config.yaml` 声明

在 CPA 主配置文件中启用插件：

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    key-model-access:
      enabled: true
      priority: 100
      policy_file: "plugins/key-model-access/config.toml"
```

### 3.2 策略文件 (`config.toml`) 结构示例

```toml
version = 3

# 全局禁用清单：对所有 Key 和所有凭据生效
global_deny_models = [
  "gemini-3.1-flash-lite",
  "*-deprecated"
]

# 按 Key 细粒度策略
[[policies]]
caller_scope = "f7291f3315e5ab0d3c02015a081879d748693f231d8370b43f38f57be991734a"
allow_models = [
  "gpt-5*",
  "claude-sonnet-*"
]
deny_models = [
  "*-preview",
  "warmup-*/*"
]
```

---

## 4. 管理接口 (Management API)

所有管理端点均受 CPA Management Key 保护：

| 方法 | 路径 | 功能说明 |
|---|---|---|
| `GET` | `/v0/management/plugins/key-model-access/status` | 查看插件运行状态、策略来源与健康检查 |
| `GET` | `/v0/management/plugins/key-model-access/policies` | 获取当前完整策略文件内容（含 ETag） |
| `PUT` | `/v0/management/plugins/key-model-access/policies` | 提交并原子更新策略文件（支持 `If-Match` 并发保护） |
| `POST` | `/v0/management/plugins/key-model-access/reload` | 从磁盘强制重载策略配置 |
| `GET` | `/v0/resource/plugins/key-model-access/settings` | Web UI 静态管理面板入口 |

---

## 5. 构建与安装

### 5.1 编译要求
- Go 1.24+
- 支持 CGO 的 C 编译器（GCC / Clang）
- `CGO_ENABLED=1`

### 5.2 常用构建命令

```bash
# 运行单元测试
make test

# 构建当前平台动态库
make build

# 打包发布压缩包与校验码
make package
```

### 5.3 插件安装

将编译生成的动态库文件放入 CPA 的插件目录：

- Linux / FreeBSD: `<CPA>/plugins/<GOOS>/<GOARCH>/key-model-access.so`
- macOS: `<CPA>/plugins/<GOOS>/<GOARCH>/key-model-access.dylib`
- Windows: `<CPA>/plugins/<GOOS>/<GOARCH>/key-model-access.dll`
