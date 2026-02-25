# IoT Firmware Vulnerability Hunter — 项目结构与功能报告

> 版本：v0.6.0 (Phase 27)  
> 最后更新：2026年2月24日  
> 技术栈：Tauri v2 + Rust + Vue 3 + TypeScript

---

## 一、项目概览

**IoT Firmware Vulnerability Hunter** 是一个基于 AI Agent 的 IoT 固件漏洞自动化挖掘工具。系统采用「顾问-主攻手」双角色协作架构，通过 Claude API 驱动自主分析流程，能够对 IoT 设备固件进行提取、逆向、漏洞发现和 PoC 生成。

### 核心特性
- AI 驱动的自主漏洞挖掘（Claude API + tool_use）
- 顾问-主攻手双角色协作（战略规划 + 战术执行）
- 11 种内置工具（Shell/Python/Docker/**reverse_analyze**(Ghidra+Joern)/HTTP 等）
- Anthropic Skills 模块化知识体系（**16 个专业技能包** + 自动生成）
- 知识库系统（分析结果自动沉淀复用 + 删除管理）
- 技能详情查看（点击加载完整 SKILL.md / 参考文档 / 脚本路径）+ **技能删除**
- 自定义背景图（支持导入本地图片 + 透明度调节）
- **日间/夜间主题切换**（CSS 变量驱动，全局生效）
- **模型 API 连通性测试**（设置页一键测试，返回模型/回复/token 用量）
- **用户可配置的 Agent 高级参数**（API 超时秒数、摘要阈值、顾问介入间隔）
- **API 请求超时保护 + 心跳事件反馈**（可配置超时 + 1s 心跳）
- **高精度消息历史自动摘要**（可配置阈值，无超时，完整保留已获取信息）
- 桌面原生应用（Tauri + WebView2，支持 Windows/macOS/Linux）

---

## 二、项目目录结构

```
iot-firmware-hunter/
├── index.html                      # Vite 入口 HTML
├── package.json                    # 前端依赖配置
├── tsconfig.json                   # TypeScript 配置
├── vite.config.ts                  # Vite 构建配置
│
├── src/                            # ===== 前端（Vue 3）=====
│   ├── main.ts                     # 应用入口
│   ├── App.vue                     # 根组件（布局 + 路由）
│   ├── vite-env.d.ts               # Vite 类型声明
│   │
│   ├── components/                 # 公共组件
│   │   ├── Sidebar.vue             # 侧边导航栏
│   │   └── BackgroundEffect.vue    # 背景动效（自定义图片 + 渐变 + 粒子）
│   │
│   ├── views/                      # 页面视图
│   │   ├── Dashboard.vue           # 仪表盘（总览页）
│   │   ├── Analysis.vue            # 分析控制台（主操作页）
│   │   ├── Skills.vue              # 技能管理页
│   │   ├── Knowledge.vue           # 知识库浏览页
│   │   └── Settings.vue            # 设置页（API/SSH 配置）
│   │
│   ├── stores/                     # 状态管理
│   │   └── agent.ts                # Pinia Store（核心状态 + Tauri IPC）
│   │
│   ├── styles/                     # 全局样式
│   └── assets/                     # 静态资源
│
├── src-tauri/                      # ===== 后端（Rust / Tauri）=====
│   ├── Cargo.toml                  # Rust 依赖配置
│   ├── tauri.conf.json             # Tauri 应用配置
│   ├── build.rs                    # 构建脚本
│   │
│   └── src/
│       ├── main.rs                 # Tauri 应用入口
│       ├── lib.rs                  # Tauri 命令注册 + IPC 层
│       │
│       ├── agent/                  # ===== Agent 核心系统 =====
│       │   ├── mod.rs              # 模块声明
│       │   ├── types.rs            # 核心类型定义
│       │   ├── orchestrator.rs     # 编排器（主控循环）
│       │   ├── advisor.rs          # 顾问 Agent
│       │   ├── attacker.rs         # 主攻手 Agent
│       │   ├── skills.rs           # 技能管理器
│       │   └── knowledge.rs        # 知识库
│       │
│       └── tools/                  # ===== 工具系统 =====
│           ├── mod.rs              # 模块声明
│           ├── registry.rs         # 工具注册表 + 执行引擎
│           └── ssh.rs              # SSH 连接管理
│
├── skills/                         # ===== 技能包（Anthropic Skills 格式）=====
│   ├── firmware-extraction/        # 固件提取与分析
│   │   ├── SKILL.md
│   │   ├── references/advanced-extraction.md
│   │   └── scripts/detect_encryption.py
│   ├── command-injection/          # 命令注入挖掘
│   │   ├── SKILL.md
│   │   └── references/vendor-patterns.md
│   ├── buffer-overflow/            # 缓冲区溢出分析
│   │   ├── SKILL.md
│   │   ├── references/arch-specifics.md
│   │   └── scripts/find_gadgets.py
│   ├── hardcoded-credentials/      # 硬编码凭证与后门
│   │   └── SKILL.md
│   ├── reverse-engineering/        # Ghidra + Joern 逆向分析
│   │   ├── SKILL.md
│   │   ├── references/ghidra-scripts.md
│   │   ├── references/cpg-queries.md
│   │   └── scripts/joern_batch_scan.py
│   ├── auth-bypass/                # 认证绕过
│   │   └── SKILL.md
│   ├── crypto-weakness/            # 加密弱点
│   │   └── SKILL.md
│   ├── iot-network-analysis/       # 网络协议分析
│   │   └── SKILL.md
│   ├── firmware-decryption/        # 固件解密与密钥恢复
│   │   ├── SKILL.md
│   │   ├── scripts/xor_key_recovery.py
│   │   └── scripts/block_cipher_detect.py
│   ├── rtos-analysis/              # RTOS 安全分析
│   │   ├── SKILL.md
│   │   └── references/tcpip-stack-cves.md
│   ├── bootloader-security/        # Bootloader 安全
│   │   └── SKILL.md
│   ├── format-string-exploitation/ # 格式化字符串漏洞
│   │   └── SKILL.md
│   ├── privilege-escalation/       # 权限提升
│   │   └── SKILL.md
│   ├── supply-chain-analysis/      # 供应链安全分析
│   │   ├── SKILL.md
│   │   └── scripts/version_scanner.py
│   ├── hardware-debug-interfaces/  # 硬件调试接口安全
│   │   └── SKILL.md
│   └── skill-creator/              # Anthropic 技能创建器（参考模板）
│       ├── SKILL.md
│       ├── references/
│       └── scripts/
│
├── dist/                           # Vite 构建输出
├── public/                         # 公共静态资源
└── .vscode/                        # VS Code 配置
```

---

## 三、系统架构

### 3.1 整体架构图

```
┌─────────────────────────────────────────────────────────────┐
│                    Tauri Desktop App                        │
│  ┌──────────────────────┐  ┌─────────────────────────────┐  │
│  │    Vue 3 Frontend    │  │       Rust Backend           │  │
│  │                      │  │                              │  │
│  │  ┌────────────────┐  │  │  ┌────────────────────────┐  │  │
│  │  │  Dashboard     │  │  │  │     Orchestrator       │  │  │
│  │  │  Analysis      │◄─┼──┼─►│  (主控循环)             │  │  │
│  │  │  Skills        │  │  │  │                        │  │  │
│  │  │  Knowledge     │  │  │  │  ┌─────────┐ ┌──────┐  │  │  │
│  │  │  Settings      │  │  │  │  │ Advisor │ │Attack│  │  │  │
│  │  └────────────────┘  │  │  │  │ (顾问)  │ │(主攻)│  │  │  │
│  │                      │  │  │  └────┬────┘ └──┬───┘  │  │  │
│  │  ┌────────────────┐  │  │  │       │         │      │  │  │
│  │  │  Pinia Store   │  │  │  │       ▼         ▼      │  │  │
│  │  │  (agent.ts)    │  │  │  │   Claude API (Anthropic)│  │  │
│  │  └────────────────┘  │  │  └────────────────────────┘  │  │
│  │                      │  │                              │  │
│  │  Tauri IPC (invoke)  │  │  ┌─────────┐ ┌───────────┐  │  │
│  │  Event Listen        │  │  │  Skills  │ │ Knowledge │  │  │
│  └──────────────────────┘  │  │  Manager │ │   Base    │  │  │
│                            │  └─────────┘ └───────────┘  │  │
│                            │                              │  │
│                            │  ┌────────────────────────┐  │  │
│                            │  │    Tool Registry       │  │  │
│                            │  │  SSH │ Shell │ Python   │  │  │
│                            │  │  Docker │ Ghidra │ IDA  │  │  │
│                            │  │  HTTP │ File R/W        │  │  │
│                            │  └──────────┬─────────────┘  │  │
│                            └─────────────┼───────────────┘  │
└───────────────────────────────────────────┼─────────────────┘
                                            │ SSH
                                            ▼
                                ┌─────────────────────┐
                                │  Remote Ubuntu Server│
                                │  (分析环境)           │
                                │  binwalk, ghidra,    │
                                │  python3, docker...  │
                                └─────────────────────┘
```

### 3.2 Agent 协作流程

```
用户启动分析
     │
     ▼
┌─────────────┐
│ Orchestrator │ ─── 主循环入口
└──────┬──────┘
       │
       ▼
┌──────────────┐   触发条件：任务开始 / 连续失败3n次 / 每5次定期检查
│  Advisor 介入? ├──Yes──► Advisor.consult() ──► Claude API ──► 战略建议
│              │                                                    │
└──────┬───────┘                                                    │
       │No                                                          │
       ▼◄──────────────────────────────────────────────────────────┘
┌──────────────┐
│  Attacker    │ ──► Claude API (tool_use) ──► 返回工具调用列表
│  execute_round│
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  执行工具调用  │ ──► ToolRegistry.execute()
│  shell_exec   │     ├── SSH 远程执行
│  python_exec  │     ├── 本地 PowerShell
│  ghidra_analyze│    ├── Ghidra headless
│  load_skill   │     ├── 加载技能知识
│  ...          │     └── ...
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  结果判定      │
│  ├─ 发现漏洞 ──► 保存 Finding + 知识库 + 自动生成技能 ──► 结束
│  ├─ 工具成功 ──► 重置失败计数 ──► 继续循环
│  ├─ 工具失败 ──► 失败计数+1 ──► 继续循环
│  └─ 超限 ─────► 结束
└──────────────┘
```

---

## 四、核心模块详解

### 4.1 Orchestrator（编排器）

**文件：** `src-tauri/src/agent/orchestrator.rs`（~425 行）

**职责：** 单 Agent 主流程控制器，协调顾问和主攻手的交互。

**关键逻辑：**
- `new(data_dir, project_skills_dir)` — 初始化所有子系统
- `run()` — 主循环：
  1. 检查尝试次数限制
  2. 顾问介入条件判定（`TaskStart` / `ConsecutiveFailure(interval)` / `PeriodicCheck(interval)` / `SelfAwareStuck`，**间隔由用户配置 `advisor_check_interval` 决定**）
  3. 调用 Attacker 执行一轮分析（**并行启动心跳任务，每 1s 推送 Heartbeat 事件**）
  4. 处理工具调用结果
  5. 检测 `[LOAD_SKILL:xxx]` 标记
  6. 发现漏洞时保存到知识库和技能库
- `build_advisor_context()` — 构建顾问所需的上下文摘要
- `extract_finding()` — 从 AI 输出中解析漏洞信息
- `emit_event()` — 向前端推送实时事件
- **`summarize_messages()`** — 消息历史摘要压缩（v0.3.0 新增，v0.4.0 大幅优化）：当消息超过用户配置的 `summarize_threshold` 条时，调用 advisor_model API 生成摘要，保留第 1 条 + AI 摘要 + 最近 6 条。**该请求不设置超时**，确保摘要完整性。max_tokens 提升至 8192，消息内容不再截断，完整保留所有工具参数、结果、密码、路径等关键数据

**心跳机制（v0.3.0 新增，v0.4.0 加快至 1s）：**
在每次 API 调用期间，`tokio::spawn` 启动心跳任务，每 **1 秒**发送 `Heartbeat { phase, elapsed_secs }` 事件到前端，让用户知道系统仍在工作，避免误判为卡死。

### 4.2 Advisor（顾问 Agent）

**文件：** `src-tauri/src/agent/advisor.rs`（~124 行）

**职责：** 提供战略指导、漏洞知识、方向调整。不直接执行工具。

**HTTP 超时配置（v0.3.0 新增，v0.4.0 可配置）：**
- 请求超时：用户配置的 `api_timeout_secs`（默认 120s），连接超时：15s（`reqwest::Client::builder().timeout().connect_timeout().build()`）
- **每次请求动态构建 Client**，允许用户修改超时后立即生效

**接口：**
```rust
pub async fn consult(
    &self,
    config: &AgentConfig,
    trigger: &AdvisorTrigger,
    context: &str,
    loaded_skills: &[String],
) -> Result<String>
```

**System Prompt 内容：** 根据触发类型动态生成，包含技能推荐、攻击面分析、方向纠偏等指导。

### 4.3 Attacker（主攻手 Agent）

**文件：** `src-tauri/src/agent/attacker.rs`（~182 行）

**职责：** 执行实际的漏洞挖掘操作，拥有工具调用能力。

**HTTP 超时配置（v0.3.0 新增，v0.4.0 可配置）：**
- 请求超时：用户配置的 `api_timeout_secs`（默认 120s），连接超时：15s（与 Advisor 一致）
- **每次请求动态构建 Client**，允许用户修改超时后立即生效

**接口：**
```rust
pub async fn execute_round(
    &self,
    config: &AgentConfig,
    messages: &[Value],
    tools: &[ToolDef],
    advisor_hint: Option<&str>,
) -> Result<AttackerResponse>
```

**返回结构 `AttackerResponse`：**
- `text` — AI 文本输出
- `tool_calls` — 工具调用列表
- `raw_content` — 原始 API 响应（含 tool_use blocks）
- `found_vulnerability` — 是否发现漏洞（检测 `[VULNERABILITY_FOUND]` 标记）
- `wants_advisor` — 是否请求顾问帮助（检测 `[NEED_ADVISOR]` 标记）
- `stuck_reason` — 卡住原因
- `stop_reason` — API 停止原因

### 4.4 SkillManager（技能管理器）

**文件：** `src-tauri/src/agent/skills.rs`（~464 行）

**职责：** 管理技能的索引、加载、搜索和创建。

**核心数据结构：**
```rust
pub struct Skill {
    pub id: String,                           // 技能唯一标识
    pub name: String,                         // 显示名称
    pub category: SkillCategory,              // 分类
    pub description: String,                  // 描述
    pub content: String,                      // SKILL.md 正文
    pub references: HashMap<String, String>,  // 参考文档（文件名→内容）
    pub script_paths: Vec<String>,            // 关联脚本路径
    pub tags: Vec<String>,                    // 标签
    pub source_path: String,                  // 磁盘路径
}

pub enum SkillCategory {
    FirmwareAnalysis,    // 固件分析
    Exploitation,        // 漏洞利用
    ReverseEngineering,  // 逆向工程
    NetworkAnalysis,     // 网络分析
    PostAnalysis,        // 事后分析（自动生成）
    Custom,              // 自定义
}
```

**技能源：**
| 来源 | 路径 | 说明 |
|------|------|------|
| 项目技能 | `{project_root}/skills/` | Anthropic 格式技能包，优先扫描 |
| 数据技能 | `%APPDATA%/com.iot-hunter/skills/` | 自动生成的 post_analysis 技能 |

**关键方法：**
- `init()` — 扫描所有技能源，构建索引
- `load_skill(skill_id)` — 按需加载完整技能内容（含 references）
- `get_loaded_context()` — 返回已加载技能的 prompt 格式文本
- `save_analysis_skill()` — 保存分析结果为新技能
- `search_skills(query)` — 模糊搜索技能
- `get_skill_scripts(skill_id)` — 获取技能关联的脚本路径
- **`delete_skill(skill_id)`** — 删除指定技能（删除磁盘目录 + 移除索引，v0.3.0 新增）

### 4.5 KnowledgeBase（知识库）

**文件：** `src-tauri/src/agent/knowledge.rs`（~80 行）

**职责：** 持久化存储分析结果，供后续任务学习复用。支持条目增删查。

**数据结构：**
```rust
pub struct KnowledgeEntry {
    pub id: String,
    pub title: String,
    pub device_type: String,
    pub firmware_info: String,
    pub vulnerabilities_found: Vec<String>,
    pub techniques_used: Vec<String>,
    pub lessons_learned: String,
    pub created_at: String,
}
```

**关键方法：**
- `init()` — 初始化，从 JSON 文件加载已有条目
- `save_entry()` — 保存新条目
- `delete_entry(id)` — 按 ID 删除条目，自动持久化（v0.2.0 新增）
- `search(query)` — 模糊搜索条目
- `get_all()` — 获取所有条目

**存储位置：** `%APPDATA%/com.iot-hunter/knowledge/db.json`（JSON 数组）

### 4.6 ToolRegistry（工具注册表）

**文件：** `src-tauri/src/tools/registry.rs`（~584 行）

**职责：** 管理所有可用工具定义，执行工具调用。

**工具列表：**

| 工具名 | 执行环境 | 功能 |
|--------|---------|------|
| `shell_exec` | 远程 SSH | 执行 Shell 命令（binwalk, strings, readelf, etc.） |
| `shell_exec_local` | 本地 PowerShell | 本地文件操作、下载等 |
| `python_exec` | 远程 SSH | 执行 Python 脚本（PoC、自动化分析） |
| `docker_exec` | 远程 SSH | Docker 容器中执行（QEMU 架构模拟） |
| `ghidra_analyze` | 远程 SSH | Ghidra headless 分析（反编译、函数列表、危险调用） |
| `ida_analyze` | 远程/MCP | IDA Pro 交互式分析 |
| `file_read` | 远程 SSH | 读取文件内容 |
| `file_write` | 远程 SSH | 写入文件 |
| `http_request` | 本地 | 发送 HTTP 请求（测试 Web 接口） |
| `load_skill` | 本地 | 按需加载技能模块 |
| `upload_firmware` | SSH | 上传固件到远程分析环境 |

**工具执行流程：**
```
Claude API 返回 tool_use → Orchestrator 解析 → ToolRegistry.execute(name, args) → 结果返回给下一轮对话
```

### 4.7 SshManager（SSH 管理器）

**文件：** `src-tauri/src/tools/ssh.rs`

**职责：** 管理 SSH 连接，执行远程命令。

**接口：**
- `connect()` — 建立 SSH 连接（支持密码/密钥认证）
- `exec(cmd)` — 执行远程命令并返回 stdout/stderr/exit_code
- `upload_file()` — SFTP 上传文件
- `download_file()` — SFTP 下载文件

---

## 五、前端模块

### 5.1 技术栈
- **Vue 3** — Composition API + `<script setup>`
- **Vue Router** — 页面路由
- **Pinia** — 状态管理
- **Tauri IPC** — `invoke()` 调用后端命令 + `listen()` 接收事件
- **animate.css** — 动画效果
- **VueUse** — 实用工具函数

### 5.2 页面功能

| 页面 | 文件 | 功能 |
|------|------|------|
| 仪表盘 | `Dashboard.vue` | 系统概览、最近分析记录、统计数据 |
| 分析控制台 | `Analysis.vue` | 固件路径输入、启动分析、实时日志、工具调用追踪、漏洞发现展示 |
| 技能管理 | `Skills.vue` | 技能列表浏览（按分类）、搜索过滤、**点击查看完整技能内容**（含参考文档与脚本路径）、**悬停删除技能** |
| 知识库 | `Knowledge.vue` | 历史分析记录浏览、漏洞知识搜索、**删除已保存条目** |
| 设置 | `Settings.vue` | API Key、API URL、模型选择、**API 连通性测试**、SSH 连接配置与测试、**Agent 高级配置（超时/摘要阈值/顾问间隔）**、自定义背景图导入与透明度调节 |

### 5.3 Pinia Store（agent.ts）

**核心状态：**
```typescript
config: AgentConfig          // API + SSH 配置（含 background_image, background_opacity）
isInitialized: boolean       // Agent 是否已初始化
isRunning: boolean           // 是否正在分析
sessionState: string         // 会话状态（支持心跳状态显示，如 "AttackerExecuting (12s)"）
logs: LogEntry[]             // 实时日志
findings: Finding[]          // 发现的漏洞
progress: { attempt, maxAttempts, consecutiveFailures }
advisorMessages: []          // 顾问消息
firmwarePath: string         // 固件路径
targetDescription: string    // 目标描述
backgroundDataUrl: string    // 自定义背景图 base64 data URL
theme: 'dark' | 'light'     // 当前主题（localStorage 持久化，v0.3.0 新增）
```

**主要方法：**
- `loadConfig()` / `saveConfig()` — 配置持久化
- `initAgent()` — 初始化 Agent 系统
- `startAnalysis()` — 启动固件分析
- `setupEventListener()` — 监听后端 `agent-event` 事件（**含 `heartbeat` 事件处理，更新 sessionState**）
- `loadBackgroundImage(path)` — 加载本地图片为 base64 data URL
- **`toggleTheme()`** — 切换日间/夜间主题（v0.3.0 新增）
- **`testModelApi(apiKey, apiBaseUrl, model)`** — 测试模型 API 连通性，返回模型名/回复/token 用量（v0.4.0 新增）

---

## 六、Tauri IPC 命令

| 命令名 | 方向 | 功能 |
|--------|------|------|
| `init_agent` | 前端→后端 | 初始化 Agent 系统（创建 Orchestrator） |
| `start_analysis` | 前端→后端 | 启动固件分析任务 |
| `stop_analysis` | 前端→后端 | 中止正在进行的分析 |
| `export_report` | 前端→后端 | 导出分析报告（Markdown 格式） |
| `get_skills` | 前端→后端 | 获取所有技能索引列表 |
| `get_skill_content` | 前端→后端 | 获取技能完整内容（含 references/scripts） |
| `get_knowledge` | 前端→后端 | 获取知识库所有条目 |
| `delete_knowledge` | 前端→后端 | 删除指定 ID 的知识库条目 |
| `delete_skill` | 前端→后端 | 删除指定 ID 的技能包（v0.3.0 新增） |
| `test_ssh` | 前端→后端 | 测试 SSH 连接 |
| `test_model_api` | 前端→后端 | **测试模型 API 连通性（30s 超时，返回模型名/回复/token 用量，v0.4.0 新增）** |
| `save_config` | 前端→后端 | 保存配置到磁盘 |
| `load_config` | 前端→后端 | 从磁盘加载配置 |
| `read_image_base64` | 前端→后端 | 读取图片文件并返回 base64 data URL |
| `agent-event` | 后端→前端 | 实时事件推送（日志、进度、工具调用、漏洞发现等） |

---

## 七、事件系统

后端通过 Tauri 的 `AppHandle.emit()` 向前端推送 `AgentEvent`：

| 事件类型 | 字段 | 说明 |
|---------|------|------|
| `log` | level, message, timestamp | 系统日志 |
| `state_change` | state | 会话状态变化 |
| `tool_call` | tool, args_preview | 工具被调用 |
| `tool_result` | tool, result_preview, is_error | 工具执行结果 |
| `advisor_message` | trigger, message | 顾问发出建议 |
| `finding` | finding | 发现漏洞 |
| `progress` | attempt, max_attempts, consecutive_failures | 进度更新 |
| `complete` | success, message | 分析完成 |
| `heartbeat` | phase, elapsed_secs | **心跳事件，每 1s 推送一次，表明 API 调用仍在进行（v0.3.0 新增，v0.4.0 加快至 1s）** |

---

## 八、核心类型定义

```rust
// 配置
AgentConfig { api_key, api_base_url, model, max_retries, advisor_model, ssh_config, background_image, background_opacity, api_timeout_secs, summarize_threshold, advisor_check_interval }
SshConfig { host, port, username, auth: Password|Key }

// 工具
ToolDef { name, description, parameters }
ToolCall { id, name, arguments }

// 会话
Session { id, created_at, config, state, history, attempt_count, failure_count, ... }
SessionState { Idle | Running | AdvisorConsulting | AttackerExecuting | VulnerabilityFound | LimitExceeded | Error }

// Agent 事件（AgentEvent 枚举）
Log { level, message }
StateChange { state }
ToolCall { tool, args_preview }
ToolResult { tool, result_preview, is_error }
AdvisorMessage { trigger, message }
FindingEvent { finding }
Progress { attempt, max_attempts, consecutive_failures }
Complete { success, message }
Heartbeat { phase, elapsed_secs }   // v0.3.0 新增

// 漏洞
Finding { id, severity, title, description, location, poc, cwe, discovered_at }
Severity { Critical | High | Medium | Low | Info }

// 顾问触发
AdvisorTrigger { None | TaskStart | ConsecutiveFailure(n) | PeriodicCheck(n) | SelfAwareStuck(reason) }
```

---

## 九、依赖清单

### Rust 依赖
| 包名 | 版本 | 用途 |
|------|------|------|
| tauri | 2.x | 桌面应用框架 |
| tauri-plugin-dialog | 2.6 | 原生文件对话框（图片选择等） |
| tokio | 1.x | 异步运行时 |
| reqwest | 0.12 | HTTP 客户端（Claude API 调用） |
| ssh2 | 0.9 | SSH2 协议实现 |
| serde / serde_json | 1.x | 序列化/反序列化 |
| chrono | 0.4 | 日期时间处理 |
| uuid | 1.x | UUID 生成 |
| anyhow | 1.x | 错误处理 |
| thiserror | 2.x | 自定义错误类型 |
| tracing | 0.1 | 日志/追踪 |
| futures | 0.3 | 异步工具 |
| async-trait | 0.1 | 异步 trait 支持 |
| directories | 5.x | 跨平台数据目录定位 |
| base64 | 0.22 | Base64 编解码（图片 data URL） |

### 前端依赖
| 包名 | 版本 | 用途 |
|------|------|------|
| vue | 3.5 | UI 框架 |
| vue-router | 4.6 | 路由 |
| pinia | 3.0 | 状态管理 |
| @tauri-apps/api | 2.x | Tauri 前端 API |
| @tauri-apps/plugin-dialog | 2.6 | 原生文件对话框前端 API |
| @vueuse/core | 14.2 | Vue 实用工具 |
| animate.css | 4.1 | CSS 动画库 |

---

## 十、数据存储

| 数据 | 位置 | 格式 |
|------|------|------|
| 用户配置 | `%APPDATA%/com.iot-hunter/config.json` | JSON |
| 数据技能 | `%APPDATA%/com.iot-hunter/skills/` | Anthropic SKILL.md |
| 分析技能 | `%APPDATA%/com.iot-hunter/skills/post_analysis/` | 自动生成 |
| 知识库 | `%APPDATA%/com.iot-hunter/knowledge/db.json` | JSON 数组 |
| 项目技能 | `{project_root}/skills/` | Anthropic SKILL.md |

---

## 十一、构建产物

| 产物 | 路径 | 说明 |
|------|------|------|
| 可执行文件 | `src-tauri/target/release/iot-firmware-hunter.exe` | Windows 原生应用 |
| MSI 安装包 | `src-tauri/target/release/bundle/msi/` | Windows Installer |
| NSIS 安装包 | `src-tauri/target/release/bundle/nsis/` | NSIS 安装程序 |

构建命令：`npm run tauri build`

---

## 十二、版本变更日志

### v0.6.0 (Phase 27)

**新增功能：**
1. **`reverse_analyze` 统一逆向工具** — 将原 `ghidra_analyze` 扩展为 `reverse_analyze`，集成 Ghidra（本地 Windows）和 Joern（远程 SSH）两大引擎：
   - **Ghidra 类型**（6 种，本地执行）：decompile、functions、strings、xrefs、imports、dangerous_calls
   - **Joern 类型**（4 种，远程 SSH 执行）：joern_scan（批量危险函数扫描）、joern_taint（污点分析 source→sink）、joern_hardcoded（硬编码凭证检测）、joern_query（自定义 Scala 查询）
   - 新增 `target_path` 参数供 Joern 使用（远程路径）、`language` 参数支持手动指定语言前端
2. **Joern 语言自动检测** — `exec_joern` 方法通过 SSH 自动检测目标类型：文件→`--language ghidra`（ELF 二进制），目录→`--language c`（源码），解决 `Could not guess language` 错误
3. **顾问策略增强** — `advisor.rs` 系统提示新增 Joern CPG 分析能力描述、Ghidra+Joern 组合策略建议、工具组合建议输出项
4. **主攻手工作流更新** — `attacker.rs` 分析流程新增第 5 步 Joern CPG 分析（远程执行），第 6 步 Ghidra 定位为「对 Joern 标记的可疑函数反编译验证」，统一通过 `reverse_analyze` 工具调用
5. **`load_skill` 描述补全** — 工具描述从 8 个技能补充至全部 16 个，新增：bootloader-security、firmware-decryption、format-string-exploitation、hardware-debug-interfaces、privilege-escalation、rtos-analysis、skill-creator、supply-chain-analysis
6. **清理孤儿文件** — 删除无法加载的旧格式文件 `arm_mips_analysis.md` 和 `firmware_extraction.md`

### v0.5.0 (Phase 26)

**新增功能：**
1. **Joern CPG 分析集成** — 新增 Joern 代码属性图分析能力，包含污点分析、危险函数检测、命令注入/缓冲区溢出模式匹配、批量扫描工作流。
2. **逆向分析技能整合** — 将原 `ghidra-re` 和 `joern-analysis` 两个技能合并为 `reverse-engineering`（总数 16→15），统一管理 Ghidra 反编译和 Joern CPG 分析，包含 `references/ghidra-scripts.md`、`references/cpg-queries.md`、`scripts/joern_batch_scan.py`。

**优化改进：**
1. **移除顾问触发条件提示** — `Analysis.vue` 顾问建议空状态中删除了触发条件提示文字，简化 UI。
2. **更新 `load_skill` 工具描述** — `registry.rs` 中 `load_skill` 工具可用技能列表更新为 `reverse-engineering（Ghidra + Joern 逆向分析）`。

### v0.4.0 (Phase 24–25)

**新增功能：**
1. **模型 API 连通性测试** — 后端新增 `test_model_api` IPC 命令，发送最小请求到 API（30s 超时），返回模型名、回复内容、token 用量。前端 Settings.vue API 配置区新增「测试 API 连接」按钮 + 结果显示。
2. **用户可配置 API 超时** — `AgentConfig` 新增 `api_timeout_secs`（默认 120，范围 30–600）。Attacker/Advisor 不再硬编码超时，改为每次请求动态构建 `reqwest::Client`。
3. **用户可配置摘要阈值** — `AgentConfig` 新增 `summarize_threshold`（默认 16，范围 8–100）。替代了硬编码的 `> 16` 判断。
4. **用户可配置顾问介入间隔** — `AgentConfig` 新增 `advisor_check_interval`（默认 5，范围 1–50）。`Session::should_consult_advisor()` 中的 `% 3` 和 `% 5` 硬编码替换为 `% interval`。
5. **Settings.vue 新增「Agent 高级配置」区块** — 包含 API 超时、摘要阈值、顾问介入间隔三个数字输入框 + 说明提示。

**优化改进：**
1. **心跳间隔 3s → 1s** — API 调用期间心跳更快，用户反馈更即时。
2. **摘要请求移除超时** — `summarize_messages()` 的 `reqwest::Client` 不再设置 `.timeout()`，确保长对话历史的摘要不会因超时被截断。
3. **摘要质量大幅提升** —
   - `max_tokens` 从 2048 提升至 **8192**
   - 消息内容不再截断（移除了 `.chars().take(800)` 等限制），完整保留工具参数和结果
   - System Prompt 全面重写，分 5 大板块：固件结构与文件发现、漏洞与安全发现、工具执行记录、当前进度与下一步、已失败方向
   - 核心原则：「宁可冗余也不能遗漏任何已获取的关键信息」，解决了后期摘要丢失信息导致分析进度重置的问题

### v0.3.0 (Phase 21–23)

**新增功能：**
1. **日间/夜间主题切换** — `global.css` 全面重构，移除所有硬编码紫色，改用 CSS 变量驱动（`--bg-deep`, `--bg-card`, `--accent`, `--text-primary` 等）。支持 `[data-theme="light"]` 明亮模式。侧边栏新增主题切换 SVG 按钮，状态通过 Pinia Store + localStorage 持久化。
2. **技能库删除** — 后端 `SkillManager::delete_skill()` 删除磁盘目录 + 移除索引，IPC 命令 `delete_skill`，前端 Skills.vue 悬停显示 × 删除按钮 + 确认弹窗。
3. **7 个新技能包**（总数 8→15）— 新增：firmware-decryption、rtos-analysis、bootloader-security、format-string-exploitation、privilege-escalation、supply-chain-analysis、hardware-debug-interfaces。包含 3 个新 Python 脚本和 1 个新参考文档。
4. **API 请求超时保护** — Attacker 和 Advisor 的 `reqwest::Client` 新增 120s 请求超时 + 15s 连接超时，防止 API 无限等待导致 AttackerExecuting 卡死。
5. **心跳事件机制** — Orchestrator 在 API 调用期间 `tokio::spawn` 每 3s 发送 `Heartbeat { phase, elapsed_secs }` 事件，前端实时显示等待时间（如 "AttackerExecuting (12s)"），用户不再误判为系统卡死。
6. **消息历史自动摘要** — `Orchestrator::summarize_messages()` 方法，当对话消息超过 16 条时，调用 advisor_model API 生成摘要，压缩为：第 1 条消息 + AI 摘要 + 最近 6 条。有效防止上下文窗口爆炸，改善长时间分析的稳定性。

**UI 改进：**
- 侧边栏背景透明化，背景图可完整覆盖全屏
- 移除侧边栏中文标题“固件安全分析”
- 移除仪表盘副标题“嵌入式设备固件漏洞智能挖掘系统”
- Analysis.vue 紫色硬编码替换为 CSS 变量
- BackgroundEffect.vue 简化渐变为 `var(--bg-deep)`

### v0.2.0 (Phase 20)

**Bug 修复：**
- 修复自定义背景图不显示的问题：`BackgroundEffect.vue` 的 `.gradient-bg` 渐变层使用了完全不透明的 `rgba(15, 10, 26, 1)` 底色，遮盖了下层的自定义图片。修复方式：为 `.gradient-bg` 添加 `.has-custom` 条件类，当用户自定义背景存在时，将底色改为半透明 `rgba(15, 10, 26, 0.55)`，并通过 z-index 分层确保 custom-bg(0) → gradient-bg(1) → particles(2) 正确叠加。

**新增功能：**
1. **知识库条目删除** — 后端 `KnowledgeBase::delete_entry()` + IPC 命令 `delete_knowledge` + 前端 Knowledge.vue 卡片悬停显示 × 删除按钮，点击确认后删除。
2. **技能详情查看** — IPC 命令 `get_skill_content` 调用 `SkillManager::load_skill()` 返回完整 Skill 结构（含 content、references、script_paths）。前端 Skills.vue 点击技能卡片弹出 Teleport 模态窗，展示技能正文、参考文档、脚本路径和元标签。
3. **项目结构报告更新** — 更新 `docs/project-report.md` 至 v0.2.0。

**UI 改进：**
- 移除 Skills.vue 中残留的 emoji 图标（📝 📤）
- 技能卡片支持 hover 高亮与点击交互

### v0.1.0 (Phase 1–19)

- 初始版本，包含完整的 AI Agent 系统、工具注册、技能管理、知识库、SSH 连接、Ghidra 集成、报告导出、UI 框架等全部基础功能。详见各模块说明。
