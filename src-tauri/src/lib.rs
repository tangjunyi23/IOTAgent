mod agent;
mod tools;

use agent::orchestrator::Orchestrator;
use agent::types::*;
use agent::skills::SkillManager;
use agent::knowledge::KnowledgeBase;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tauri::State;
use serde_json::json;

type OrchestratorState = Arc<Mutex<Option<Orchestrator>>>;
type CancelToken = Arc<Mutex<Option<Arc<std::sync::atomic::AtomicBool>>>>;

fn get_data_dir() -> PathBuf {
    directories::ProjectDirs::from("com", "iot-hunter", "iot-firmware-hunter")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("./data"))
}

/// 获取项目 skills 目录（可执行文件同级目录或开发时的项目根目录）
fn get_project_skills_dir() -> Option<PathBuf> {
    // 尝试从可执行文件路径推断
    if let Ok(exe) = std::env::current_exe() {
        // release: exe 在 src-tauri/target/release/ 下，skills 在项目根
        // 往上找 skills/ 目录
        let mut dir = exe.parent().map(|p| p.to_path_buf());
        for _ in 0..5 {
            if let Some(ref d) = dir {
                let candidate = d.join("skills");
                if candidate.exists() && candidate.is_dir() {
                    return Some(candidate);
                }
                dir = d.parent().map(|p| p.to_path_buf());
            }
        }
    }
    // fallback: 当前工作目录
    let cwd_skills = PathBuf::from("./skills");
    if cwd_skills.exists() {
        return Some(cwd_skills.canonicalize().unwrap_or(cwd_skills));
    }
    None
}

/// 初始化 Agent 系统
#[tauri::command]
async fn init_agent(
    config: AgentConfig,
    state: State<'_, OrchestratorState>,
) -> Result<String, String> {
    let data_dir = get_data_dir();
    let project_skills = get_project_skills_dir();
    let mut orch = Orchestrator::new(data_dir, project_skills);
    let ghidra_path = if config.ghidra_path.is_empty() { None } else { Some(config.ghidra_path.as_str()) };
    let local_download_path = if config.local_download_path.is_empty() { None } else { Some(config.local_download_path.as_str()) };
    orch.init(config.ssh_config.as_ref(), ghidra_path, local_download_path).await.map_err(|e| e.to_string())?;
    
    let mut lock = state.lock().await;
    *lock = Some(orch);
    
    Ok(json!({"status": "initialized"}).to_string())
}

/// 开始固件分析
#[tauri::command]
async fn start_analysis(
    app_handle: tauri::AppHandle,
    config: AgentConfig,
    firmware_path: String,
    target_description: String,
    state: State<'_, OrchestratorState>,
    cancel_state: State<'_, CancelToken>,
) -> Result<String, String> {
    let mut lock = state.lock().await;
    let orch = lock.as_mut().ok_or("Agent not initialized")?;

    // 保存取消令牌
    let token = orch.cancel_token();
    {
        let mut cancel_lock = cancel_state.lock().await;
        *cancel_lock = Some(token);
    }
    
    let findings = orch.run(&app_handle, &config, &firmware_path, &target_description)
        .await
        .map_err(|e| e.to_string())?;

    // 清除取消令牌
    {
        let mut cancel_lock = cancel_state.lock().await;
        *cancel_lock = None;
    }
    
    Ok(serde_json::to_string(&findings).map_err(|e| e.to_string())?)
}

/// 停止固件分析
#[tauri::command]
async fn stop_analysis(
    cancel_state: State<'_, CancelToken>,
) -> Result<String, String> {
    let lock = cancel_state.lock().await;
    if let Some(ref token) = *lock {
        token.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(json!({"status": "stopping"}).to_string())
    } else {
        Err("没有正在运行的分析任务".into())
    }
}

/// 导出分析报告到本地路径
#[tauri::command]
async fn export_report(
    export_path: String,
    firmware_path: String,
    target_description: String,
    findings: Vec<serde_json::Value>,
    logs: Vec<serde_json::Value>,
    advisor_messages: Vec<serde_json::Value>,
) -> Result<String, String> {
    use std::path::Path;

    let export_dir = Path::new(&export_path);
    // 确保导出目录存在
    tokio::fs::create_dir_all(export_dir).await.map_err(|e| format!("创建导出目录失败: {}", e))?;

    // 生成带时间戳的文件名
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    let safe_name = firmware_path
        .replace(['\\', '/', ':', '*', '?', '"', '<', '>', '|'], "_")
        .chars()
        .rev()
        .take(30)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    let report_filename = format!("report_{}_{}.md", safe_name, timestamp);
    let report_path = export_dir.join(&report_filename);

    // 构建 Markdown 报告
    let mut report = String::new();
    report.push_str("# IoT 固件漏洞分析报告\n\n");
    report.push_str(&format!("**生成时间**: {}\n\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S")));
    report.push_str("---\n\n");

    // 基本信息
    report.push_str("## 一、分析目标\n\n");
    report.push_str(&format!("| 项目 | 内容 |\n|------|------|\n"));
    report.push_str(&format!("| 固件路径 | `{}` |\n", firmware_path));
    report.push_str(&format!("| 目标描述 | {} |\n", target_description));
    report.push_str("\n");

    // 漏洞发现
    report.push_str("## 二、漏洞发现\n\n");
    if findings.is_empty() {
        report.push_str("本次分析未发现漏洞。\n\n");
    } else {
        report.push_str(&format!("共发现 **{}** 个漏洞：\n\n", findings.len()));
        for (i, f) in findings.iter().enumerate() {
            let severity = f.get("severity").and_then(|v| v.as_str()).unwrap_or("Unknown");
            let title = f.get("title").and_then(|v| v.as_str()).unwrap_or("未知");
            let description = f.get("description").and_then(|v| v.as_str()).unwrap_or("");
            let location = f.get("location").and_then(|v| v.as_str()).unwrap_or("");
            let cwe = f.get("cwe").and_then(|v| v.as_str());
            let poc = f.get("poc").and_then(|v| v.as_str());

            report.push_str(&format!("### 漏洞 #{}: {}\n\n", i + 1, title));
            report.push_str(&format!("- **严重性**: {}\n", severity));
            if !location.is_empty() {
                report.push_str(&format!("- **位置**: `{}`\n", location));
            }
            if let Some(cwe_id) = cwe {
                report.push_str(&format!("- **CWE**: {}\n", cwe_id));
            }
            report.push_str(&format!("\n**描述**:\n\n{}\n\n", description));
            if let Some(poc_content) = poc {
                report.push_str(&format!("**PoC**:\n\n```\n{}\n```\n\n", poc_content));
            }
            report.push_str("---\n\n");
        }
    }

    // 顾问建议
    report.push_str("## 三、顾问建议记录\n\n");
    if advisor_messages.is_empty() {
        report.push_str("本次分析中顾问未介入。\n\n");
    } else {
        for (i, msg) in advisor_messages.iter().enumerate() {
            let trigger = msg.get("trigger").and_then(|v| v.as_str()).unwrap_or("未知");
            let message = msg.get("message").and_then(|v| v.as_str()).unwrap_or("");
            report.push_str(&format!("### 建议 #{} ({})\n\n", i + 1, trigger));
            report.push_str(&format!("{}\n\n", message));
        }
    }

    // 运行日志摘要（只记录关键日志）
    report.push_str("## 四、关键分析日志\n\n");
    let key_logs: Vec<&serde_json::Value> = logs.iter().filter(|l| {
        let log_type = l.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let level = l.get("level").and_then(|v| v.as_str()).unwrap_or("");
        matches!(log_type, "tool_call" | "tool_result" | "finding" | "complete" | "state")
            || matches!(level, "error" | "warn")
    }).collect();

    if key_logs.is_empty() {
        report.push_str("无关键日志记录。\n\n");
    } else {
        report.push_str("| 时间 | 级别 | 内容 |\n|------|------|------|\n");
        for log in key_logs.iter().take(100) {
            let time = log.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
            let level = log.get("level").and_then(|v| v.as_str()).unwrap_or("");
            let message = log.get("message").and_then(|v| v.as_str()).unwrap_or("");
            // 转义 Markdown 表格中的 | 字符
            let safe_message = message.replace('|', "\\|").replace('\n', " ");
            report.push_str(&format!("| {} | {} | {} |\n", time, level, safe_message));
        }
        report.push_str("\n");
    }

    report.push_str("---\n\n");
    report.push_str("*本报告由 IoT Firmware Vulnerability Hunter 自动生成*\n");

    // 写入文件
    tokio::fs::write(&report_path, &report).await.map_err(|e| format!("写入报告失败: {}", e))?;

    let path_str = report_path.to_string_lossy().to_string();
    Ok(json!({
        "status": "exported",
        "path": path_str,
        "filename": report_filename,
        "size": report.len()
    }).to_string())
}

/// 获取技能列表
#[tauri::command]
async fn get_skills() -> Result<String, String> {
    let data_dir = get_data_dir();
    let mut sm = SkillManager::new(data_dir.join("skills"));
    if let Some(proj_dir) = get_project_skills_dir() {
        sm.set_project_skills_dir(proj_dir);
    }
    sm.init().await.map_err(|e| e.to_string())?;
    let index = sm.get_index().to_vec();
    Ok(serde_json::to_string(&index).map_err(|e| e.to_string())?)
}

/// 获取知识库内容
#[tauri::command]
async fn get_knowledge() -> Result<String, String> {
    let data_dir = get_data_dir();
    let mut kb = KnowledgeBase::new(data_dir.join("knowledge").join("db.json"));
    kb.init().await.map_err(|e| e.to_string())?;
    let entries = kb.get_all().to_vec();
    Ok(serde_json::to_string(&entries).map_err(|e| e.to_string())?)
}

/// 删除知识库条目
#[tauri::command]
async fn delete_knowledge(id: String) -> Result<String, String> {
    let data_dir = get_data_dir();
    let mut kb = KnowledgeBase::new(data_dir.join("knowledge").join("db.json"));
    kb.init().await.map_err(|e| e.to_string())?;
    let deleted = kb.delete_entry(&id).await.map_err(|e| e.to_string())?;
    Ok(json!({ "deleted": deleted }).to_string())
}

/// 获取技能详细内容
#[tauri::command]
async fn get_skill_content(skill_id: String) -> Result<String, String> {
    let data_dir = get_data_dir();
    let mut sm = SkillManager::new(data_dir.join("skills"));
    if let Some(proj_dir) = get_project_skills_dir() {
        sm.set_project_skills_dir(proj_dir);
    }
    sm.init().await.map_err(|e| e.to_string())?;
    let skill = sm.load_skill(&skill_id).await.map_err(|e| e.to_string())?;
    Ok(serde_json::to_string(skill).map_err(|e| e.to_string())?)
}

/// 删除技能
#[tauri::command]
async fn delete_skill(skill_id: String) -> Result<String, String> {
    let data_dir = get_data_dir();
    let mut sm = SkillManager::new(data_dir.join("skills"));
    if let Some(proj_dir) = get_project_skills_dir() {
        sm.set_project_skills_dir(proj_dir);
    }
    sm.init().await.map_err(|e| e.to_string())?;
    let deleted = sm.delete_skill(&skill_id).await.map_err(|e| e.to_string())?;
    Ok(json!({ "deleted": deleted }).to_string())
}

/// 测试 SSH 连接
#[tauri::command]
async fn test_ssh(config: SshConfig) -> Result<String, String> {
    let mut ssh = tools::ssh::SshManager::new(config);
    ssh.connect().map_err(|e| e.to_string())?;
    let output = ssh.exec("uname -a && which binwalk && which python3").map_err(|e| e.to_string())?;
    Ok(json!({
        "connected": true,
        "system_info": output.stdout,
        "tools_available": output.stdout
    }).to_string())
}

/// 测试模型 API 连通性
#[tauri::command]
async fn test_model_api(api_key: String, api_base_url: String, model: String) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let body = serde_json::json!({
        "model": model,
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "Hello, respond with exactly: API_OK"}],
    });

    let resp = client
        .post(format!("{}/messages", api_base_url))
        .header("x-api-key", &api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                "API 连接超时（请检查网络或 API URL）".to_string()
            } else if e.is_connect() {
                format!("API 连接失败：{}", e)
            } else {
                format!("API 请求失败：{}", e)
            }
        })?;

    let status = resp.status();
    let resp_json: serde_json::Value = resp.json().await.map_err(|e| format!("解析响应失败：{}", e))?;

    if let Some(err) = resp_json["error"].as_object() {
        let msg = err.get("message").and_then(|m| m.as_str()).unwrap_or("unknown");
        return Err(format!("API 错误 ({}): {}", status, msg));
    }

    let reply = resp_json["content"].as_array()
        .and_then(|arr| arr.first())
        .and_then(|b| b["text"].as_str())
        .unwrap_or("")
        .to_string();
    let model_used = resp_json["model"].as_str().unwrap_or(&model).to_string();
    let input_tokens = resp_json["usage"]["input_tokens"].as_u64().unwrap_or(0);
    let output_tokens = resp_json["usage"]["output_tokens"].as_u64().unwrap_or(0);

    Ok(json!({
        "success": true,
        "model": model_used,
        "reply": reply,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens
    }).to_string())
}

/// 保存配置
#[tauri::command]
async fn save_config(config: AgentConfig) -> Result<(), String> {
    let data_dir = get_data_dir();
    tokio::fs::create_dir_all(&data_dir).await.map_err(|e| e.to_string())?;
    let config_path = data_dir.join("config.json");
    let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    tokio::fs::write(config_path, json).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// 加载配置
#[tauri::command]
async fn load_config() -> Result<String, String> {
    let data_dir = get_data_dir();
    let config_path = data_dir.join("config.json");
    if config_path.exists() {
        let content = tokio::fs::read_to_string(config_path).await.map_err(|e| e.to_string())?;
        Ok(content)
    } else {
        Ok(serde_json::to_string(&AgentConfig::default()).map_err(|e| e.to_string())?)
    }
}

/// 读取图片文件并返回 base64 data URL
#[tauri::command]
async fn read_image_base64(path: String) -> Result<String, String> {
    use base64::Engine;
    use std::path::Path;

    let file_path = Path::new(&path);
    if !file_path.exists() {
        return Err("图片文件不存在".into());
    }

    let bytes = tokio::fs::read(file_path).await.map_err(|e| format!("读取图片失败: {}", e))?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);

    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("png")
        .to_lowercase();
    let mime = match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "svg" => "image/svg+xml",
        _ => "image/png",
    };

    Ok(format!("data:{};base64,{}", mime, encoded))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let orchestrator_state: OrchestratorState = Arc::new(Mutex::new(None));
    let cancel_token: CancelToken = Arc::new(Mutex::new(None));

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(orchestrator_state)
        .manage(cancel_token)
        .invoke_handler(tauri::generate_handler![
            init_agent,
            start_analysis,
            stop_analysis,
            export_report,
            get_skills,
            get_skill_content,
            delete_skill,
            get_knowledge,
            delete_knowledge,
            test_ssh,
            test_model_api,
            save_config,
            load_config,
            read_image_base64,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

