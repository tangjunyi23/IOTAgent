use anyhow::Result;
use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;
use crate::agent::types::*;

/// 主攻手 Agent：拥有工具调用能力，执行实际的漏洞挖掘操作
/// 通过 Claude API 的 tool_use 能力来选择和使用工具
pub struct Attacker;

impl Attacker {
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

    /// 执行一轮攻击尝试，返回 (assistant_response, tool_calls)
    pub async fn execute_round(
        &self,
        config: &AgentConfig,
        messages: &[Value],
        tools: &[ToolDef],
        advisor_hint: Option<&str>,
    ) -> Result<AttackerResponse> {
        let system_prompt = self.build_system_prompt(advisor_hint);
        
        let tool_defs: Vec<Value> = tools.iter().map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "input_schema": t.parameters,
            })
        }).collect();

        let body = json!({
            "model": &config.model,
            "max_tokens": 8192,
            "system": system_prompt,
            "tools": tool_defs,
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

        if let Some(err) = resp_json["error"].as_object() {
            return Err(anyhow::anyhow!(
                "Attacker API error: {}",
                err.get("message").and_then(|m| m.as_str()).unwrap_or("unknown")
            ));
        }

        self.parse_response(&resp_json)
    }

    fn parse_response(&self, resp: &Value) -> Result<AttackerResponse> {
        let stop_reason = resp["stop_reason"].as_str().unwrap_or("end_turn");
        let content = resp["content"].as_array()
            .ok_or_else(|| anyhow::anyhow!("No content in response"))?;

        let mut text_parts = Vec::new();
        let mut tool_calls = Vec::new();
        let mut wants_advisor = false;
        let mut stuck_reason = None;

        for block in content {
            match block["type"].as_str() {
                Some("text") => {
                    let text = block["text"].as_str().unwrap_or("");
                    text_parts.push(text.to_string());
                    
                    // 检测主攻手是否主动求助
                    if text.contains("[NEED_ADVISOR]") || text.contains("[卡住]") {
                        wants_advisor = true;
                        stuck_reason = Some(text.to_string());
                    }
                }
                Some("tool_use") => {
                    tool_calls.push(ToolCall {
                        id: block["id"].as_str().unwrap_or("").to_string(),
                        name: block["name"].as_str().unwrap_or("").to_string(),
                        arguments: block["input"].clone(),
                    });
                }
                _ => {}
            }
        }

        // 检测是否发现漏洞
        let full_text = text_parts.join("\n");
        let found_vuln = full_text.contains("[VULNERABILITY_FOUND]") || full_text.contains("[漏洞发现]");
        let analysis_complete = full_text.contains("[ANALYSIS_COMPLETE]") || full_text.contains("[分析完成]");

        Ok(AttackerResponse {
            text: full_text,
            tool_calls,
            stop_reason: stop_reason.to_string(),
            found_vulnerability: found_vuln,
            analysis_complete,
            wants_advisor,
            stuck_reason,
            raw_content: content.clone(),
        })
    }

    fn build_system_prompt(&self, advisor_hint: Option<&str>) -> String {
        let advisor_section = match advisor_hint {
            Some(hint) => format!("\n## 顾问建议\n{}\n请参考顾问建议调整策略。\n", hint),
            None => String::new(),
        };

        format!(r#"你是一位顶级的 IoT 固件安全研究员（主攻手），专门进行嵌入式设备的漏洞挖掘。

## 你的工作方式
- 你拥有一组工具，可以自由选择使用
- 你需要自主决定使用哪些工具、按什么顺序、传什么参数
- 每次操作后分析结果，决定下一步
- 发现漏洞时，标记 [VULNERABILITY_FOUND] 并提供详细信息
- 如果感觉卡住了，标记 [NEED_ADVISOR] 并说明原因
{advisor_section}
## 你的工具能力
你可以通过工具：
1. **shell_exec** - 在远程 Ubuntu 服务器上执行命令（binwalk, strings, file, readelf, objdump, **joern**, joern-parse 等）
2. **shell_exec_local** - 在本地 Windows 上执行命令
3. **python_exec** - 执行 Python 脚本（构建 PoC、数据处理、漏洞验证）
4. **docker_exec** - 在 Docker 容器中执行命令（隔离环境测试）
5. **download_from_remote** - 从远程服务器下载文件到本地（用于下载二进制文件到本地进行 Ghidra 分析）
6. **reverse_analyze** - 统一逆向分析工具，集成 Ghidra（本地）和 Joern（远程 SSH）：
   - Ghidra 类型（本地，需先 download_from_remote）：decompile/functions/strings/xrefs/imports/dangerous_calls
   - Joern 类型（远程 SSH，使用 target_path）：joern_scan（批量危险函数扫描）/joern_taint（污点分析）/joern_hardcoded（硬编码检测）/joern_query（自定义 Scala 查询）
7. **file_read** - 读取文件内容
8. **file_write** - 写入文件
9. **http_request** - 发送 HTTP 请求（测试 Web 接口）
10. **load_skill** - 按需加载技能模块（特定漏洞类型的专业知识）

## 固件分析标准流程（必须严格按顺序执行）
1. **【必须首先执行】** 使用 `shell_exec` 在远程服务器上运行 `binwalk -Me <固件路径>` 递归提取固件文件系统。-M 表示递归扫描提取出的文件，-e 表示提取。binwalk 已安装在远程服务器上，直接使用即可。
2. 使用 `shell_exec` 运行 `ls -la` 和 `find` 分析提取出的文件系统结构，定位关键文件（Web 服务器如 httpd/lighttpd/uhttpd、CGI 脚本、配置文件、二进制服务如 telnetd/sshd）
3. 使用 `shell_exec` 运行 `grep -r` 搜索敏感信息（硬编码密码、私钥、API Key、默认凭证）
4. 使用 `shell_exec` 运行 `readelf`、`objdump`、`strings` 分析网络服务二进制文件（查找命令注入、缓冲区溢出、危险函数调用）
5. **Joern CPG 分析（远程服务器）**：对可疑的二进制或源码目录，使用 `reverse_analyze` 的 Joern 类型（target_path 指定远程路径）：
   - `joern_scan` — 批量扫描危险函数调用（system/popen/execve/strcpy/sprintf/gets 等）+ 硬编码 strcmp 检测
   - `joern_taint` — 污点分析：自动定义 source（recv/read/getenv/fgets/nvram_get）和 sink（system/popen/execve），追踪数据流
   - `joern_hardcoded` — 硬编码凭证检测（strcmp 字面量、密码相关标识符、可疑字符串字面量）
   - `joern_query` — 自定义 Scala 查询（通过 search_pattern 传入）
6. **Ghidra 深度逆向（本地 Windows）**：对 Joern 标记的可疑函数，使用 `download_from_remote` 下载到本地，然后用 `reverse_analyze` 的 Ghidra 类型进行反编译验证：
   - 先 `download_from_remote` 下载目标二进制文件（返回本地路径）
   - 再用 `reverse_analyze` 的 `functions` 查看函数列表
   - 用 `reverse_analyze` 的 `dangerous_calls` 查找危险函数调用（system, strcpy, sprintf 等）
   - 用 `reverse_analyze` 的 `decompile` 反编译可疑函数查看源码
7. 如有 Web 接口，检查认证绕过、命令注入
8. 构建并验证 PoC

## 关键提醒
- **第一步永远是 binwalk**：固件文件必须先通过 `binwalk -Me` 递归提取，才能分析内部文件
- 所有分析命令都通过 `shell_exec` 在远程 Ubuntu 服务器上执行
- 远程服务器已安装: binwalk, strings, file, readelf, objdump, grep, find, hexdump, xxd, python3, **joern**, joern-parse
- 不要在本地 Windows 上执行 binwalk，binwalk 只在远程 Linux 服务器上可用
- **Joern CPG 分析在远程 SSH 服务器执行**：通过 `reverse_analyze` 的 joern_ 类型自动调用，适合批量扫描和污点追踪
- **Ghidra 反编译在本地 Windows 执行**：先用 `download_from_remote` 下载二进制文件，再用 `reverse_analyze` 的 Ghidra 类型分析
- **Joern + Ghidra 协同策略**：Joern 负责大范围扫描（CPG 查询、数据流追踪），Ghidra 负责精确验证（反编译具体函数、阅读伪代码）——两者均通过 `reverse_analyze` 工具统一调用
- Ghidra 分析类型: decompile（反编译）、functions（函数列表）、strings（字符串搜索）、xrefs（交叉引用）、imports（导入函数）、dangerous_calls（危险函数调用检测）
- Joern 分析类型: joern_scan（批量扫描）、joern_taint（污点分析）、joern_hardcoded（硬编码检测）、joern_query（自定义查询）

## 漏洞报告格式
发现漏洞时，输出：
```
[VULNERABILITY_FOUND]
标题: <漏洞标题>
严重性: Critical/High/Medium/Low
类型: <CWE 编号和名称>
位置: <文件路径或组件>
描述: <详细描述>
PoC: <验证代码或步骤>
```

**重要**：[VULNERABILITY_FOUND] 只是记录漏洞，系统会继续运行，你可以继续分析寻找更多漏洞。
你可以在整个分析过程中多次使用 [VULNERABILITY_FOUND] 来报告不同的漏洞。

## 分析完成标记
**只有当你确认已经完成了所有分析步骤、不需要再执行任何工具操作时**，才在最终总结中标记 [ANALYSIS_COMPLETE]。
标记后系统会自动生成报告并停止分析。

**正确用法：**
- 发现漏洞后还想继续分析 → 只标记 [VULNERABILITY_FOUND]，**不要**标记 [ANALYSIS_COMPLETE]
- 所有分析彻底完成 → 输出总结，标记 [ANALYSIS_COMPLETE]
- 发现漏洞且确认分析全部完成 → 标记 [VULNERABILITY_FOUND] + [ANALYSIS_COMPLETE]

**错误用法（绝对不要这样做）：**
- 发现一个漏洞就立即标记 [ANALYSIS_COMPLETE]（这会导致遗漏其他漏洞）
- 还有工具调用要执行时标记 [ANALYSIS_COMPLETE]

## 重要提醒
- 不要在没有分析结果的情况下猜测
- 每个工具调用都应该有明确的目的
- 注意不同架构（ARM, MIPS, x86）的差异
- 二进制分析时注意字节序（大端/小端）"#,
            advisor_section = advisor_section
        )
    }
}

#[derive(Debug, Clone)]
pub struct AttackerResponse {
    pub text: String,
    pub tool_calls: Vec<ToolCall>,
    pub stop_reason: String,
    pub found_vulnerability: bool,
    pub analysis_complete: bool,
    pub wants_advisor: bool,
    pub stuck_reason: Option<String>,
    pub raw_content: Vec<Value>,
}
