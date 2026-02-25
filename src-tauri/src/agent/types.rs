use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

// ── 核心类型定义 ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub api_key: String,
    pub api_base_url: String,
    pub model: String,
    pub max_retries: u32,
    pub advisor_model: String,
    pub ssh_config: Option<SshConfig>,
    #[serde(default)]
    pub ghidra_path: String,
    #[serde(default)]
    pub local_download_path: String,
    #[serde(default)]
    pub report_export_path: String,
    #[serde(default)]
    pub background_image: String,
    #[serde(default = "default_bg_opacity")]
    pub background_opacity: f64,
    #[serde(default = "default_api_timeout")]
    pub api_timeout_secs: u64,
    #[serde(default = "default_summarize_threshold")]
    pub summarize_threshold: u32,
    #[serde(default = "default_advisor_interval")]
    pub advisor_check_interval: u32,
}

fn default_bg_opacity() -> f64 {
    0.3
}

fn default_api_timeout() -> u64 {
    120
}

fn default_summarize_threshold() -> u32 {
    16
}

fn default_advisor_interval() -> u32 {
    5
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            api_base_url: "https://api.siliconflow.cn/v1".into(),
            model: String::new(),
            max_retries: 15,
            advisor_model: String::new(),
            ssh_config: None,
            ghidra_path: String::new(),
            local_download_path: String::new(),
            report_export_path: String::new(),
            background_image: String::new(),
            background_opacity: 0.3,
            api_timeout_secs: 120,
            summarize_threshold: 16,
            advisor_check_interval: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SshAuth {
    Password { password: String },
    Key { private_key_path: String, passphrase: Option<String> },
}

// ── 工具相关 ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub tool_use_id: String,
    pub content: String,
    pub is_error: bool,
}

// ── 消息类型 ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: MessageRole,
    pub content: MessageContent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    User,
    Assistant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse { id: String, name: String, input: serde_json::Value },
    #[serde(rename = "tool_result")]
    ToolResult { tool_use_id: String, content: String, is_error: Option<bool> },
}

// ── 会话与任务 ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub config: AgentConfig,
    pub state: SessionState,
    pub history: Vec<ChatMessage>,
    pub attempt_count: u32,
    pub failure_count: u32,
    pub consecutive_failures: u32,
    pub findings: Vec<Finding>,
    pub advisor_interventions: u32,
}

impl Session {
    pub fn new(config: AgentConfig) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            created_at: Utc::now(),
            config,
            state: SessionState::Idle,
            history: Vec::new(),
            attempt_count: 0,
            failure_count: 0,
            consecutive_failures: 0,
            findings: Vec::new(),
            advisor_interventions: 0,
        }
    }

    /// 顾问触发条件检测
    pub fn should_consult_advisor(&self) -> AdvisorTrigger {
        let interval = self.config.advisor_check_interval.max(1);
        // 任务开始
        if self.attempt_count == 0 {
            return AdvisorTrigger::TaskStart;
        }
        // 连续失败达到 interval 的倍数时触发
        if self.consecutive_failures > 0 && self.consecutive_failures % interval == 0 {
            return AdvisorTrigger::ConsecutiveFailure(self.consecutive_failures);
        }
        // 每 interval 次尝试定期检查
        if self.attempt_count > 0 && self.attempt_count % interval == 0 {
            return AdvisorTrigger::PeriodicCheck(self.attempt_count);
        }
        AdvisorTrigger::None
    }

    pub fn is_over_limit(&self) -> bool {
        self.attempt_count >= self.config.max_retries as u32
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionState {
    Idle,
    Running,
    AdvisorConsulting,
    AttackerExecuting,
    VulnerabilityFound,
    LimitExceeded,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdvisorTrigger {
    None,
    TaskStart,
    ConsecutiveFailure(u32),
    PeriodicCheck(u32),
    SelfAwareStuck(String),
}

// ── 漏洞发现 ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub location: String,
    pub poc: Option<String>,
    pub cwe: Option<String>,
    pub discovered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

// ── 前端事件推送 ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AgentEvent {
    #[serde(rename = "log")]
    Log { level: String, message: String, timestamp: String },
    #[serde(rename = "state_change")]
    StateChange { state: SessionState },
    #[serde(rename = "tool_call")]
    ToolCallEvent { tool: String, args_preview: String },
    #[serde(rename = "tool_result")]
    ToolResultEvent { tool: String, result_preview: String, is_error: bool },
    #[serde(rename = "advisor_message")]
    AdvisorMessage { trigger: String, message: String },
    #[serde(rename = "finding")]
    FindingEvent { finding: Finding },
    #[serde(rename = "progress")]
    Progress { attempt: u32, max_attempts: u32, consecutive_failures: u32 },
    #[serde(rename = "complete")]
    Complete { success: bool, message: String },
    #[serde(rename = "heartbeat")]
    Heartbeat { phase: String, elapsed_secs: u64 },
}
