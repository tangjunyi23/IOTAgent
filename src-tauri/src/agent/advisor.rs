use anyhow::Result;
use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;
use crate::agent::types::*;

/// 顾问 Agent：提供战略指导、漏洞知识、方向调整
/// 不直接执行工具，只输出文本建议
pub struct Advisor;

impl Advisor {
    pub fn new() -> Self {
        Self
    }

    fn build_client(&self, config: &AgentConfig) -> Client {
        Client::builder()
            .timeout(Duration::from_secs(config.api_timeout_secs))
            .connect_timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| Client::new())
    }

    /// 向顾问请求建议
    pub async fn consult(
        &self,
        config: &AgentConfig,
        trigger: &AdvisorTrigger,
        context: &str,
        loaded_skills: &[String],
    ) -> Result<String> {
        let system_prompt = self.build_system_prompt(trigger, loaded_skills);

        let messages = vec![json!({
            "role": "user",
            "content": context
        })];

        let body = json!({
            "model": &config.advisor_model,
            "max_tokens": 4096,
            "system": system_prompt,
            "messages": messages,
        });

        let client = self.build_client(config);

        let resp = client
            .post(format!("{}/messages", &config.api_base_url))
            .header("x-api-key", &config.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?;

        let resp_json: Value = resp.json().await?;

        // 提取文本响应
        if let Some(content) = resp_json["content"].as_array() {
            let texts: Vec<&str> = content.iter()
                .filter_map(|b| b["text"].as_str())
                .collect();
            Ok(texts.join("\n"))
        } else if let Some(err) = resp_json["error"].as_object() {
            Err(anyhow::anyhow!("Advisor API error: {}", err.get("message").and_then(|m| m.as_str()).unwrap_or("unknown")))
        } else {
            Err(anyhow::anyhow!("Unexpected advisor response format"))
        }
    }

    fn build_system_prompt(&self, trigger: &AdvisorTrigger, loaded_skills: &[String]) -> String {
        let trigger_context = match trigger {
            AdvisorTrigger::TaskStart => {
                "这是任务的开始阶段。你需要分析目标固件，提供全面的攻击策略和优先级排序。"
            }
            AdvisorTrigger::ConsecutiveFailure(n) => {
                &format!("主攻手已经连续失败 {} 次。你需要重新评估策略，指出可能的错误方向，并建议新的攻击路径。", n)
            }
            AdvisorTrigger::PeriodicCheck(n) => {
                &format!("已进行 {} 次尝试。进行定期检查，防止主攻手陷入思维定式。提供新的思路或确认当前方向。", n)
            }
            AdvisorTrigger::SelfAwareStuck(reason) => {
                &format!("主攻手报告自己卡住了：{}。帮助分析原因并指导下一步。", reason)
            }
            AdvisorTrigger::None => "提供一般性的指导建议。"
        };

        let skills_info = if loaded_skills.is_empty() {
            "当前没有加载特定技能模块。".to_string()
        } else {
            format!("已加载的技能模块：{}", loaded_skills.join(", "))
        };

        format!(r#"你是一位资深的 IoT 安全顾问，专注于嵌入式设备固件安全研究。

## 你的角色
- 你是战略层面的指导者，不直接执行操作
- 你分析主攻手的进展，提供方向性建议
- 你拥有丰富的漏洞知识库，熟悉常见的嵌入式安全问题

## 当前触发原因
{trigger_context}

## {skills_info}

## 你的专业领域
1. **固件分析策略**：binwalk 提取、文件系统分析、关键文件定位
2. **二进制逆向**：
   - **Ghidra**（本地 Windows）：反编译、函数列表、交叉引用、危险函数调用检测
   - **Joern**（远程 SSH 服务器）：代码属性图（CPG）分析、污点追踪、数据流分析、批量模式匹配
   - **组合策略**：先用 Joern 批量扫描定位危险模式和数据流，再用 Ghidra 反编译深入验证具体函数
3. **漏洞类型知识**：
   - 命令注入（CGI 脚本、Web 接口）— Joern 污点分析可追踪 recv/getenv → system/popen
   - 缓冲区溢出（strcpy, sprintf, gets 等危险函数）— Joern 可检测固定缓冲区 + 无界拷贝模式
   - 硬编码凭证（默认密码、API Key）— Joern 可检测 strcmp 中的字面量参数
   - 不安全的加密实现
   - 认证绕过
   - 信息泄露
   - 后门（隐藏 telnet/SSH 端口、调试接口）
4. **PoC 构建指导**：如何验证漏洞、构建有效的 PoC

## 输出格式
请提供：
1. **情况分析**：当前进展评估
2. **推荐策略**：具体的下一步操作建议（按优先级排序）
3. **工具组合建议**：建议何时使用 Joern（批量扫描、污点分析）、何时使用 Ghidra（反编译验证）
4. **需要加载的技能**：是否需要激活特定技能模块（如 reverse-engineering）
5. **注意事项**：可能的陷阱和应避免的方向"#, 
            trigger_context = trigger_context,
            skills_info = skills_info
        )
    }
}
