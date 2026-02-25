use anyhow::Result;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{AppHandle, Emitter};
use tokio::time::{Instant, interval, Duration};

use crate::agent::advisor::Advisor;
use crate::agent::attacker::Attacker;
use crate::agent::skills::SkillManager;
use crate::agent::knowledge::{KnowledgeBase, KnowledgeEntry};
use crate::agent::types::*;
use crate::tools::ToolRegistry;

/// 编排器：单 Agent 主流程控制器
/// 将顾问-主攻手协作模式组织为一个清晰的主循环
pub struct Orchestrator {
    advisor: Advisor,
    attacker: Attacker,
    skill_manager: SkillManager,
    knowledge_base: KnowledgeBase,
    tool_registry: ToolRegistry,
    cancel_flag: Arc<AtomicBool>,
}

impl Orchestrator {
    pub fn new(data_dir: PathBuf, project_skills_dir: Option<PathBuf>) -> Self {
        let mut skill_manager = SkillManager::new(data_dir.join("skills"));
        if let Some(proj_dir) = project_skills_dir {
            skill_manager.set_project_skills_dir(proj_dir);
        }
        Self {
            advisor: Advisor::new(),
            attacker: Attacker::new(),
            skill_manager,
            knowledge_base: KnowledgeBase::new(data_dir.join("knowledge").join("db.json")),
            tool_registry: ToolRegistry::new(),
            cancel_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 获取取消标志的引用（供外部调用停止）
    pub fn cancel_token(&self) -> Arc<AtomicBool> {
        self.cancel_flag.clone()
    }

    /// 初始化所有子系统
    pub async fn init(&mut self, ssh_config: Option<&SshConfig>, ghidra_path: Option<&str>, local_download_path: Option<&str>) -> Result<()> {
        self.skill_manager.init().await?;
        self.knowledge_base.init().await?;
        self.tool_registry.init(ssh_config, ghidra_path, local_download_path).await?;
        Ok(())
    }

    /// 主运行循环
    pub async fn run(
        &mut self,
        app_handle: &AppHandle,
        config: &AgentConfig,
        firmware_path: &str,
        target_description: &str,
    ) -> Result<Vec<Finding>> {
        let mut session = Session::new(config.clone());
        session.state = SessionState::Running;

        self.emit_event(app_handle, AgentEvent::StateChange { state: session.state.clone() });
        self.emit_event(app_handle, AgentEvent::Log {
            level: "info".into(),
            message: format!("开始分析固件: {}", firmware_path),
            timestamp: chrono::Utc::now().to_rfc3339(),
        });

        // API 消息历史（给 Claude 的消息）
        let mut messages: Vec<Value> = Vec::new();

        // 初始用户消息
        let initial_prompt = format!(
            "## 目标固件分析任务\n\n固件路径: {}\n设备描述: {}\n\n请开始分析此固件，寻找安全漏洞。首先使用 binwalk 或其他工具检查固件格式。",
            firmware_path, target_description
        );

        let mut advisor_hint: Option<String> = None;

        // 重置取消标志
        self.cancel_flag.store(false, Ordering::SeqCst);

        // 记录远程固件路径，用于后续清理
        let remote_firmware_dir = "~/iot_firmware_analysis/";

        // ── 主循环 ──
        loop {
            // ── 检查是否被用户取消 ──
            if self.cancel_flag.load(Ordering::SeqCst) {
                session.state = SessionState::Error("用户手动停止".into());
                self.emit_event(app_handle, AgentEvent::Complete {
                    success: false,
                    message: "分析已被用户手动停止".into(),
                });
                break;
            }

            session.attempt_count += 1;

            // 发送进度
            self.emit_event(app_handle, AgentEvent::Progress {
                attempt: session.attempt_count,
                max_attempts: config.max_retries,
                consecutive_failures: session.consecutive_failures,
            });

            // ── 检查是否超出限制 ──
            if session.is_over_limit() {
                session.state = SessionState::LimitExceeded;
                self.emit_event(app_handle, AgentEvent::Complete {
                    success: false,
                    message: format!("已达到最大尝试次数 ({})，未能发现漏洞", config.max_retries),
                });
                break;
            }

            // ── 顾问介入检查 ──
            let trigger = session.should_consult_advisor();
            match &trigger {
                AdvisorTrigger::None => {},
                _ => {
                    session.state = SessionState::AdvisorConsulting;
                    self.emit_event(app_handle, AgentEvent::StateChange { state: session.state.clone() });

                    let trigger_desc = match &trigger {
                        AdvisorTrigger::TaskStart => "任务开始".to_string(),
                        AdvisorTrigger::ConsecutiveFailure(n) => format!("连续失败 {} 次", n),
                        AdvisorTrigger::PeriodicCheck(n) => format!("定期检查 (第 {} 次尝试)", n),
                        AdvisorTrigger::SelfAwareStuck(r) => format!("主攻手求助: {}", r),
                        AdvisorTrigger::None => unreachable!(),
                    };

                    self.emit_event(app_handle, AgentEvent::Log {
                        level: "info".into(),
                        message: format!("顾问介入: {}", trigger_desc),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    });

                    // 构建顾问上下文
                    let context = self.build_advisor_context(&session, &messages, firmware_path, target_description);
                    
                    match self.advisor.consult(
                        config,
                        &trigger,
                        &context,
                        &self.skill_manager.loaded_skill_names(),
                    ).await {
                        Ok(advice) => {
                            session.advisor_interventions += 1;
                            advisor_hint = Some(advice.clone());
                            self.emit_event(app_handle, AgentEvent::AdvisorMessage {
                                trigger: trigger_desc,
                                message: advice,
                            });
                        }
                        Err(e) => {
                            self.emit_event(app_handle, AgentEvent::Log {
                                level: "warn".into(),
                                message: format!("顾问调用失败: {}", e),
                                timestamp: chrono::Utc::now().to_rfc3339(),
                            });
                        }
                    }
                }
            }

            // ── 主攻手执行 ──
            session.state = SessionState::AttackerExecuting;
            self.emit_event(app_handle, AgentEvent::StateChange { state: session.state.clone() });

            // 首轮添加初始消息
            if messages.is_empty() {
                let mut user_msg = initial_prompt.clone();
                if let Some(ref hint) = advisor_hint {
                    user_msg.push_str(&format!("\n\n## 顾问建议\n{}", hint));
                }
                // 附加技能上下文
                let skill_ctx = self.skill_manager.get_loaded_context();
                if !skill_ctx.is_empty() {
                    user_msg.push_str(&skill_ctx);
                }
                messages.push(json!({"role": "user", "content": user_msg}));
            }

            // ── 消息历史摘要压缩 ──
            // 当消息轮次过多时，用 AI 对旧消息进行摘要，保留最近的上下文
            if messages.len() > config.summarize_threshold as usize {
                self.emit_event(app_handle, AgentEvent::Log {
                    level: "info".into(),
                    message: format!("消息历史过长 ({} 条，阈值 {})，正在进行摘要压缩...", messages.len(), config.summarize_threshold),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });

                match self.summarize_messages(config, &messages).await {
                    Ok(summary) => {
                        // 保留第一条（初始 prompt）和最近 6 条消息
                        let first_msg = messages[0].clone();
                        let recent: Vec<Value> = messages.iter().rev().take(6).rev().cloned().collect();
                        messages.clear();
                        messages.push(first_msg);
                        messages.push(json!({
                            "role": "user",
                            "content": format!(
                                "## 之前的分析摘要\n\n以下是之前多轮分析的摘要，请基于此继续：\n\n{}\n\n---\n请继续分析。",
                                summary
                            )
                        }));
                        // 为了保持 user/assistant 交替，插入一个 assistant 确认
                        messages.push(json!({
                            "role": "assistant",
                            "content": [{"type": "text", "text": "已了解之前的分析摘要，我将基于此继续深入分析。"}]
                        }));
                        // 追加最近的消息
                        messages.extend(recent);

                        self.emit_event(app_handle, AgentEvent::Log {
                            level: "info".into(),
                            message: format!("摘要压缩完成，消息数: {} → {}", messages.len() + 16, messages.len()),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                    Err(e) => {
                        self.emit_event(app_handle, AgentEvent::Log {
                            level: "warn".into(),
                            message: format!("消息摘要失败（将保留完整历史）: {}", e),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }

            // 调用主攻手（带心跳）
            let tools = self.tool_registry.get_tool_defs();
            let api_start = Instant::now();
            let heartbeat_handle = app_handle.clone();
            let heartbeat_cancel = Arc::new(AtomicBool::new(false));
            let heartbeat_cancel_clone = heartbeat_cancel.clone();

            // 启动心跳任务：每 1 秒向前端发送等待状态
            let heartbeat_task = tokio::spawn(async move {
                let mut ticker = interval(Duration::from_secs(1));
                ticker.tick().await; // 跳过第一次立即触发
                loop {
                    ticker.tick().await;
                    if heartbeat_cancel_clone.load(Ordering::SeqCst) {
                        break;
                    }
                    let elapsed = api_start.elapsed().as_secs();
                    let _ = heartbeat_handle.emit("agent-event", &AgentEvent::Heartbeat {
                        phase: "AI 推理中".into(),
                        elapsed_secs: elapsed,
                    });
                }
            });

            let response = match self.attacker.execute_round(
                config,
                &messages,
                &tools,
                advisor_hint.as_deref(),
            ).await {
                Ok(r) => {
                    heartbeat_cancel.store(true, Ordering::SeqCst);
                    heartbeat_task.abort();
                    r
                }
                Err(e) => {
                    heartbeat_cancel.store(true, Ordering::SeqCst);
                    heartbeat_task.abort();
                    session.consecutive_failures += 1;
                    session.failure_count += 1;
                    let err_msg = if e.to_string().contains("timed out") || e.to_string().contains("timeout") {
                        format!("主攻手调用超时 ({}s)，将重试: {}", api_start.elapsed().as_secs(), e)
                    } else {
                        format!("主攻手调用失败: {}", e)
                    };
                    self.emit_event(app_handle, AgentEvent::Log {
                        level: "error".into(),
                        message: err_msg,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    });
                    continue;
                }
            };

            // 清除顾问建议（已使用）
            advisor_hint = None;

            // ── 处理响应 ──
            
            // 添加 assistant 消息到历史
            messages.push(json!({
                "role": "assistant",
                "content": response.raw_content,
            }));

            // 检查是否发现漏洞（记录但不立即停止，让 AI 继续分析其他漏洞）
            if response.found_vulnerability {
                session.state = SessionState::VulnerabilityFound;
                let finding = self.extract_finding(&response.text);
                session.findings.push(finding.clone());
                
                self.emit_event(app_handle, AgentEvent::FindingEvent { finding: finding.clone() });
                self.emit_event(app_handle, AgentEvent::StateChange { state: session.state.clone() });

                // 保存到知识库
                let _ = self.knowledge_base.save_entry(KnowledgeEntry {
                    id: uuid::Uuid::new_v4().to_string(),
                    title: finding.title.clone(),
                    device_type: target_description.to_string(),
                    firmware_info: firmware_path.to_string(),
                    vulnerabilities_found: vec![finding.title.clone()],
                    techniques_used: vec!["auto-analysis".to_string()],
                    lessons_learned: response.text.clone(),
                    created_at: chrono::Utc::now().to_rfc3339(),
                }).await;

                // 保存分析总结为技能
                let _ = self.skill_manager.save_analysis_skill(
                    &format!("分析: {}", finding.title),
                    &response.text,
                    vec![target_description.to_string()],
                ).await;

                self.emit_event(app_handle, AgentEvent::Log {
                    level: "info".into(),
                    message: format!("🎯 记录漏洞: {}，继续分析...", finding.title),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });

                // 只有在同时标记了 [ANALYSIS_COMPLETE] 时才停止
                // 否则继续循环，让 AI 挖掘更多漏洞
            }

            // 检查是否标记分析完成（统一出口）
            if response.analysis_complete {
                let vuln_count = session.findings.len();
                self.emit_event(app_handle, AgentEvent::Log {
                    level: "info".into(),
                    message: "主攻手标记分析完成".into(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
                self.emit_event(app_handle, AgentEvent::Complete {
                    success: vuln_count > 0,
                    message: if vuln_count > 0 {
                        format!("分析完成，共发现 {} 个漏洞", vuln_count)
                    } else {
                        "分析完成，未发现漏洞".into()
                    },
                });
                break;
            }

            // 检查是否需要请求顾问
            if response.wants_advisor {
                if response.stuck_reason.is_some() {
                    // 下一轮触发顾问
                    session.consecutive_failures += 1;
                }
            }

            // ── 执行工具调用 ──
            if !response.tool_calls.is_empty() {
                let mut tool_results: Vec<Value> = Vec::new();

                for tc in &response.tool_calls {
                    self.emit_event(app_handle, AgentEvent::ToolCallEvent {
                        tool: tc.name.clone(),
                        args_preview: serde_json::to_string(&tc.arguments)
                            .unwrap_or_default()
                            .chars().take(200).collect(),
                    });

                    let result = self.tool_registry.execute(&tc.name, &tc.arguments).await;

                    let (content, is_error) = match result {
                        Ok(output) => {
                            session.consecutive_failures = 0; // 成功执行重置计数
                            (output, false)
                        }
                        Err(e) => {
                            session.consecutive_failures += 1;
                            session.failure_count += 1;
                            (format!("Error: {}", e), true)
                        }
                    };

                    self.emit_event(app_handle, AgentEvent::ToolResultEvent {
                        tool: tc.name.clone(),
                        result_preview: content.chars().take(500).collect(),
                        is_error,
                    });

                    tool_results.push(json!({
                        "type": "tool_result",
                        "tool_use_id": tc.id,
                        "content": content,
                        "is_error": is_error,
                    }));
                }

                // 添加工具结果到消息历史
                messages.push(json!({
                    "role": "user",
                    "content": tool_results,
                }));

            } else if response.stop_reason == "end_turn" {
                // 模型结束但没有发现漏洞，也没有工具调用
                if response.analysis_complete {
                    // AI 标记了分析完成，停止循环
                    self.emit_event(app_handle, AgentEvent::Complete {
                        success: !session.findings.is_empty(),
                        message: if session.findings.is_empty() {
                            "分析完成，未发现漏洞".into()
                        } else {
                            format!("分析完成，共发现 {} 个漏洞", session.findings.len())
                        },
                    });
                    break;
                }
                // 提示继续
                messages.push(json!({
                    "role": "user",
                    "content": "请继续分析。如果你需要执行操作，请使用工具。如果你已经完成了所有分析，请输出总结并标记 [ANALYSIS_COMPLETE]。如果你卡住了，请标记 [NEED_ADVISOR]。"
                }));
                session.consecutive_failures += 1;
            }

            // ── 检查是否被用户取消（工具执行后再检查一次）──
            if self.cancel_flag.load(Ordering::SeqCst) {
                session.state = SessionState::Error("用户手动停止".into());
                self.emit_event(app_handle, AgentEvent::Complete {
                    success: false,
                    message: "分析已被用户手动停止".into(),
                });
                break;
            }

            // 检查主攻手是否想加载技能
            if response.text.contains("[LOAD_SKILL:") {
                // 解析 [LOAD_SKILL:skill_id]
                if let Some(start) = response.text.find("[LOAD_SKILL:") {
                    let rest = &response.text[start + 12..];
                    if let Some(end) = rest.find(']') {
                        let skill_id = rest[..end].to_string();
                        match self.skill_manager.load_skill(&skill_id).await {
                            Ok(skill) => {
                                let skill_name = skill.name.clone();
                                self.emit_event(app_handle, AgentEvent::Log {
                                    level: "info".into(),
                                    message: format!("已加载技能: {}", skill_name),
                                    timestamp: chrono::Utc::now().to_rfc3339(),
                                });
                            }
                            Err(e) => {
                                self.emit_event(app_handle, AgentEvent::Log {
                                    level: "warn".into(),
                                    message: format!("加载技能失败: {}", e),
                                    timestamp: chrono::Utc::now().to_rfc3339(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // ── 分析结束清理：删除远程固件文件 ──
        self.cleanup_remote_firmware(app_handle, remote_firmware_dir, firmware_path).await;

        // ── 自动导出分析报告 ──
        if !config.report_export_path.is_empty() {
            self.auto_export_report(
                app_handle,
                &config.report_export_path,
                firmware_path,
                target_description,
                &session.findings,
            ).await;
        }

        Ok(session.findings)
    }

    /// 清理远程服务器上的固件文件和提取产物
    async fn cleanup_remote_firmware(&self, app_handle: &AppHandle, remote_dir: &str, firmware_path: &str) {
        // 只有连了 SSH 且固件在远程服务器上时才清理
        let firmware_filename = std::path::Path::new(firmware_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        // 通过 shell 清理，shell 会自动展开 ~
        let cleanup_cmd = format!(
            "rm -rf {}* /tmp/_extracted_* /tmp/ghidra_proj 2>/dev/null; echo 'cleanup done'",
            remote_dir
        );

        match self.tool_registry.execute("shell_exec", &json!({"command": cleanup_cmd})).await {
            Ok(_) => {
                self.emit_event(app_handle, AgentEvent::Log {
                    level: "info".into(),
                    message: format!("已清理远程固件文件: {}{}", remote_dir, firmware_filename),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            }
            Err(e) => {
                self.emit_event(app_handle, AgentEvent::Log {
                    level: "warn".into(),
                    message: format!("清理远程文件失败（可忽略）: {}", e),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            }
        }
    }

    /// 分析完成后自动导出报告到本地路径
    async fn auto_export_report(
        &self,
        app_handle: &AppHandle,
        export_path: &str,
        firmware_path: &str,
        target_description: &str,
        findings: &[Finding],
    ) {
        use std::path::Path;

        let export_dir = Path::new(export_path);
        if let Err(e) = tokio::fs::create_dir_all(export_dir).await {
            self.emit_event(app_handle, AgentEvent::Log {
                level: "warn".into(),
                message: format!("创建报告导出目录失败: {}", e),
                timestamp: chrono::Utc::now().to_rfc3339(),
            });
            return;
        }

        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
        let safe_name: String = firmware_path
            .replace(['\\', '/', ':', '*', '?', '"', '<', '>', '|'], "_")
            .chars()
            .rev()
            .take(30)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        let report_filename = format!("report_{}_{}.md", safe_name, timestamp);
        let report_path = export_dir.join(&report_filename);

        let mut report = String::new();
        report.push_str("# IoT 固件漏洞分析报告\n\n");
        report.push_str(&format!("**生成时间**: {}\n\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S")));
        report.push_str("---\n\n");
        report.push_str("## 分析目标\n\n");
        report.push_str(&format!("- **固件路径**: `{}`\n", firmware_path));
        report.push_str(&format!("- **目标描述**: {}\n\n", target_description));

        report.push_str("## 漏洞发现\n\n");
        if findings.is_empty() {
            report.push_str("本次分析未发现漏洞。\n\n");
        } else {
            report.push_str(&format!("共发现 **{}** 个漏洞：\n\n", findings.len()));
            for (i, f) in findings.iter().enumerate() {
                report.push_str(&format!("### 漏洞 #{}: {}\n\n", i + 1, f.title));
                report.push_str(&format!("- **严重性**: {:?}\n", f.severity));
                if !f.location.is_empty() {
                    report.push_str(&format!("- **位置**: `{}`\n", f.location));
                }
                if let Some(ref cwe) = f.cwe {
                    report.push_str(&format!("- **CWE**: {}\n", cwe));
                }
                report.push_str(&format!("\n{}\n\n", f.description));
                if let Some(ref poc) = f.poc {
                    report.push_str(&format!("**PoC**:\n```\n{}\n```\n\n", poc));
                }
            }
        }

        report.push_str("---\n\n*本报告由 IoT Firmware Vulnerability Hunter 自动生成*\n");

        match tokio::fs::write(&report_path, &report).await {
            Ok(_) => {
                self.emit_event(app_handle, AgentEvent::Log {
                    level: "info".into(),
                    message: format!("📄 分析报告已自动导出: {}", report_path.display()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            }
            Err(e) => {
                self.emit_event(app_handle, AgentEvent::Log {
                    level: "warn".into(),
                    message: format!("自动导出报告失败: {}", e),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            }
        }
    }

    fn build_advisor_context(
        &self,
        session: &Session,
        messages: &[Value],
        firmware_path: &str,
        target_description: &str,
    ) -> String {
        let mut ctx = format!(
            "## 当前分析状态\n\n\
            - 目标固件: {}\n\
            - 设备描述: {}\n\
            - 当前尝试次数: {}\n\
            - 连续失败次数: {}\n\
            - 总失败次数: {}\n\
            - 顾问介入次数: {}\n\n",
            firmware_path, target_description,
            session.attempt_count, session.consecutive_failures,
            session.failure_count, session.advisor_interventions,
        );

        // 附加最近几轮的交互摘要
        ctx.push_str("## 最近的分析活动\n\n");
        let recent: Vec<&Value> = messages.iter().rev().take(6).collect();
        for msg in recent.iter().rev() {
            if let Some(role) = msg["role"].as_str() {
                let content_preview = if let Some(text) = msg["content"].as_str() {
                    text.chars().take(500).collect::<String>()
                } else {
                    serde_json::to_string(&msg["content"])
                        .unwrap_or_default()
                        .chars().take(500).collect()
                };
                ctx.push_str(&format!("**{}**: {}\n\n", role, content_preview));
            }
        }

        // 附加知识库搜索结果
        let kb_results = self.knowledge_base.search(target_description);
        if !kb_results.is_empty() {
            ctx.push_str("## 相关历史经验\n\n");
            for entry in kb_results.iter().take(3) {
                ctx.push_str(&format!("- {}: {}\n", entry.title, entry.lessons_learned.chars().take(200).collect::<String>()));
            }
        }

        ctx
    }

    fn extract_finding(&self, text: &str) -> Finding {
        // 从 [VULNERABILITY_FOUND] 标记中解析
        let mut title = "未知漏洞".to_string();
        let mut severity = Severity::Medium;
        let description = text.to_string();
        let mut location = String::new();
        let mut poc = None;
        let mut cwe = None;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("标题:") || trimmed.starts_with("Title:") {
                title = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
            } else if trimmed.starts_with("严重性:") || trimmed.starts_with("Severity:") {
                let sev_str = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim().to_lowercase();
                severity = match sev_str.as_str() {
                    "critical" | "致命" => Severity::Critical,
                    "high" | "高" => Severity::High,
                    "medium" | "中" => Severity::Medium,
                    "low" | "低" => Severity::Low,
                    _ => Severity::Info,
                };
            } else if trimmed.starts_with("位置:") || trimmed.starts_with("Location:") {
                location = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
            } else if trimmed.starts_with("类型:") || trimmed.starts_with("CWE:") {
                cwe = Some(trimmed.splitn(2, ':').nth(1).unwrap_or("").trim().to_string());
            }
        }

        // 提取 PoC 代码块
        if let Some(poc_start) = text.find("PoC:") {
            poc = Some(text[poc_start..].to_string());
        }

        Finding {
            id: uuid::Uuid::new_v4().to_string(),
            severity,
            title,
            description,
            location,
            poc,
            cwe,
            discovered_at: chrono::Utc::now(),
        }
    }

    fn emit_event(&self, app_handle: &AppHandle, event: AgentEvent) {
        let _ = app_handle.emit("agent-event", &event);
    }

    /// 使用 AI 对消息历史进行摘要，避免上下文过长
    /// 此调用不设置超时，确保摘要完整性
    async fn summarize_messages(&self, config: &AgentConfig, messages: &[Value]) -> Result<String> {
        let client = reqwest::Client::builder()
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        // 将除最近 6 条外的消息序列化为摘要输入
        let msgs_to_summarize = if messages.len() > 6 {
            &messages[..messages.len() - 6]
        } else {
            messages
        };

        // 构建摘要内容：提取每条消息的完整信息（不截断）
        let mut summary_input = String::new();
        for (i, msg) in msgs_to_summarize.iter().enumerate() {
            let role = msg["role"].as_str().unwrap_or("unknown");
            let content = if let Some(text) = msg["content"].as_str() {
                text.to_string()
            } else if let Some(arr) = msg["content"].as_array() {
                // 结构化内容（tool_use / tool_result 等）
                let mut parts = Vec::new();
                for block in arr {
                    match block["type"].as_str() {
                        Some("text") => {
                            let t = block["text"].as_str().unwrap_or("");
                            parts.push(format!("[text] {}", t));
                        }
                        Some("tool_use") => {
                            let name = block["name"].as_str().unwrap_or("?");
                            let args = serde_json::to_string(&block["input"]).unwrap_or_default();
                            parts.push(format!("[tool_call: {}] args: {}", name, args));
                        }
                        Some("tool_result") => {
                            let content = block["content"].as_str().unwrap_or("");
                            let is_err = block["is_error"].as_bool().unwrap_or(false);
                            let status = if is_err { "ERROR" } else { "OK" };
                            parts.push(format!("[tool_result: {}] {}", status, content));
                        }
                        _ => {}
                    }
                }
                parts.join("\n")
            } else {
                serde_json::to_string(&msg["content"]).unwrap_or_default()
            };
            summary_input.push_str(&format!("--- 消息 {} ({}) ---\n{}\n\n", i + 1, role, content));
        }

        let body = json!({
            "model": &config.advisor_model,
            "max_tokens": 8192,
            "system": "你是一个高精度安全分析摘要助手。你的任务是将多轮固件安全分析对话完整地浓缩为一份详尽的结构化摘要。\n\n## 核心原则：绝对不得丢失任何已获取的信息\n\n摘要必须完整保留以下所有内容：\n\n### 1. 固件结构与文件发现\n- binwalk/解压结果：完整的文件系统结构、所有发现的目录和文件\n- 关键二进制文件：完整路径、架构、大小、功能说明\n- 配置文件：完整路径和关键内容\n- 发现的所有端口、服务、网络配置\n\n### 2. 漏洞与安全发现（最重要）\n- 每个发现的完整详情：漏洞类型、位置、严重性、完整的证据\n- 所有发现的硬编码凭证、后门、弱加密等（包含完整的字符串/密码/密钥值）\n- 所有厉害函数调用（strcpy, sprintf, system 等）的完整位置\n- 命令注入点、缓冲区溢出点、认证绕过等的完整分析\n\n### 3. 工具执行记录\n- 每个工具调用的命令、参数和关键输出结果\n- 成功的操作和失败的操作（包含失败原因）\n- Ghidra/IDA 反编译发现的函数、逻辑、漏洞模式\n\n### 4. 当前进度与下一步方向\n- 明确说明当前分析进度百分比\n- 已完成的分析阶段\n- 待探索的方向和线索\n- 还未分析的文件或区域\n\n### 5. 已尝试但失败的方向\n- 列出所有失败的尝试和具体原因，避免重复\n\n## 格式要求\n使用详细的 Markdown 格式，包含代码块、路径、具体数值。字数不限，宁可冗余也不能遗漏任何已获取的关键信息。",
            "messages": [{
                "role": "user",
                "content": format!("请对以下 {} 条固件安全分析对话进行完整摘要。注意：不要省略或截断任何已获取的具体数据（如密码、路径、函数名、地址、输出结果等），这些信息对后续分析至关重要：\n\n{}", msgs_to_summarize.len(), summary_input)
            }],
        });

        let resp = client
            .post(format!("{}/messages", &config.api_base_url))
            .header("x-api-key", &config.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?;

        let resp_json: Value = resp.json().await?;

        if let Some(err) = resp_json["error"].as_object() {
            return Err(anyhow::anyhow!(
                "Summary API error: {}",
                err.get("message").and_then(|m| m.as_str()).unwrap_or("unknown")
            ));
        }

        // 提取摘要文本
        if let Some(content) = resp_json["content"].as_array() {
            let texts: Vec<&str> = content.iter()
                .filter_map(|b| b["text"].as_str())
                .collect();
            Ok(texts.join("\n"))
        } else {
            Err(anyhow::anyhow!("Unexpected summary response format"))
        }
    }
}
