use anyhow::Result;
use serde_json::{json, Value};
use std::process::Stdio;

use crate::agent::types::*;
use crate::tools::ssh::SshManager;

/// 工具注册表：管理所有可用工具，执行工具调用
pub struct ToolRegistry {
    ssh: Option<SshManager>,
    ghidra_path: String,
    local_download_path: String,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self { ssh: None, ghidra_path: String::new(), local_download_path: String::new() }
    }

    pub async fn init(&mut self, ssh_config: Option<&SshConfig>, ghidra_path: Option<&str>, local_download_path: Option<&str>) -> Result<()> {
        if let Some(cfg) = ssh_config {
            let mut ssh = SshManager::new(cfg.clone());
            ssh.connect()?;
            self.ssh = Some(ssh);
        }
        if let Some(path) = ghidra_path {
            self.ghidra_path = path.to_string();
        }
        if let Some(path) = local_download_path {
            self.local_download_path = path.to_string();
        }
        Ok(())
    }

    /// 返回所有工具定义（给 Claude API）
    pub fn get_tool_defs(&self) -> Vec<ToolDef> {
        let tools = vec![
            ToolDef {
                name: "shell_exec".into(),
                description: "在远程 Ubuntu 服务器上通过 SSH 执行 shell 命令。可用工具包括：binwalk, strings, file, readelf, objdump, grep, find, hexdump, xxd, arm-linux-gnueabi-objdump 等。适用于固件提取、文件系统分析、二进制检查。".into(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "要在远程 Ubuntu 服务器上执行的 shell 命令"
                        },
                        "working_dir": {
                            "type": "string",
                            "description": "工作目录（可选）"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "超时时间（秒），默认 120"
                        }
                    },
                    "required": ["command"]
                }),
            },
            ToolDef {
                name: "shell_exec_local".into(),
                description: "在本地 Windows 主机上执行 PowerShell 命令。用于本地文件操作、下载固件等。".into(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "要在本地 Windows 上执行的 PowerShell 命令"
                        }
                    },
                    "required": ["command"]
                }),
            },
            ToolDef {
                name: "python_exec".into(),
                description: "在远程服务器上执行 Python 脚本。用于构建 PoC、数据处理、漏洞验证、自动化分析。".into(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "要执行的 Python 代码"
                        },
                        "save_as": {
                            "type": "string",
                            "description": "可选，将代码保存为文件路径再执行"
                        }
                    },
                    "required": ["code"]
                }),
            },
            ToolDef {
                name: "docker_exec".into(),
                description: "在 Docker 容器中执行命令。用于隔离环境测试、模拟目标设备架构（qemu-user-static）。".into(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "image": {
                            "type": "string",
                            "description": "Docker 镜像名称，如 'ubuntu:22.04' 或 'arm32v7/debian'"
                        },
                        "command": {
                            "type": "string",
                            "description": "在容器中执行的命令"
                        },
                        "volumes": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "挂载卷列表，如 ['/tmp/fw:/firmware']"
                        }
                    },
                    "required": ["image", "command"]
                }),
            },
            ToolDef {
                name: "reverse_analyze".into(),
                description: "统一逆向分析工具，集成 Ghidra（本地反编译）和 Joern（远程 CPG 分析）。Ghidra 类型需先用 download_from_remote 下载二进制到本地；Joern 类型直接在远程 SSH 服务器上执行 CPG 分析。".into(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "本地二进制文件路径（Ghidra 类型使用，由 download_from_remote 返回）"
                        },
                        "target_path": {
                            "type": "string",
                            "description": "远程服务器上的目标路径（Joern 类型使用，可以是二进制文件或源码目录）"
                        },
                        "analysis_type": {
                            "type": "string",
                            "enum": ["decompile", "functions", "strings", "xrefs", "imports", "dangerous_calls", "joern_scan", "joern_taint", "joern_hardcoded", "joern_query"],
                            "description": "分析类型。decompile/functions/strings/xrefs/imports/dangerous_calls 为 Ghidra 本地分析；joern_scan/joern_taint/joern_hardcoded/joern_query 为 Joern 远程 CPG 分析"
                        },
                        "function_name": {
                            "type": "string",
                            "description": "指定函数名（用于 decompile 和 xrefs）"
                        },
                        "search_pattern": {
                            "type": "string",
                            "description": "搜索模式（用于 strings）或自定义 Joern Scala 查询表达式（用于 joern_query）"
                        },
                        "language": {
                            "type": "string",
                            "enum": ["c", "ghidra", "java", "python", "javascript"],
                            "description": "Joern 分析时的语言前端。分析 ELF 二进制文件用 ghidra，分析 C 源码目录用 c。若不指定则自动检测（文件→ghidra，目录→c）"
                        }
                    },
                    "required": ["analysis_type"]
                }),
            },
            ToolDef {
                name: "download_from_remote".into(),
                description: "从远程 Ubuntu 服务器下载文件到本地 Windows 机器。用于将需要反编译的二进制文件下载到本地，然后使用 reverse_analyze 的 Ghidra 类型进行分析。".into(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "remote_path": {
                            "type": "string",
                            "description": "远程服务器上的文件路径"
                        },
                        "local_path": {
                            "type": "string",
                            "description": "本地保存路径（可选，默认保存到临时目录）"
                        }
                    },
                    "required": ["remote_path"]
                }),
            },
            ToolDef {
                name: "file_read".into(),
                description: "读取远程服务器上的文件内容。".into(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "文件路径"
                        },
                        "encoding": {
                            "type": "string",
                            "description": "编码，默认 utf-8，可选 hex, base64"
                        },
                        "max_size": {
                            "type": "integer",
                            "description": "最大读取大小（字节），默认 65536"
                        }
                    },
                    "required": ["path"]
                }),
            },
            ToolDef {
                name: "file_write".into(),
                description: "在远程服务器上写入文件。用于保存 PoC 脚本、自定义分析工具等。".into(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "文件路径"
                        },
                        "content": {
                            "type": "string",
                            "description": "文件内容"
                        },
                        "mode": {
                            "type": "string",
                            "description": "文件权限，如 '755'，默认 '644'"
                        }
                    },
                    "required": ["path", "content"]
                }),
            },
            ToolDef {
                name: "http_request".into(),
                description: "发送 HTTP 请求。用于测试目标设备的 Web 接口、API 端点。".into(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "method": {
                            "type": "string",
                            "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                            "description": "HTTP 方法"
                        },
                        "url": {
                            "type": "string",
                            "description": "请求 URL"
                        },
                        "headers": {
                            "type": "object",
                            "description": "请求头"
                        },
                        "body": {
                            "type": "string",
                            "description": "请求体"
                        }
                    },
                    "required": ["method", "url"]
                }),
            },
            ToolDef {
                name: "load_skill".into(),
                description: "按需加载技能模块。可用技能包括（Anthropic Skills 格式）：firmware-extraction（固件提取与分析）, command-injection（命令注入挖掘）, buffer-overflow（缓冲区溢出挖掘）, hardcoded-credentials（硬编码凭证与后门）, reverse-engineering（Ghidra + Joern 逆向分析）, auth-bypass（认证绕过）, crypto-weakness（加密弱点）, iot-network-analysis（网络协议分析）, bootloader-security（Bootloader 安全分析）, firmware-decryption（固件解密与解包）, format-string-exploitation（格式化字符串漏洞利用）, hardware-debug-interfaces（硬件调试接口安全）, privilege-escalation（权限提升）, rtos-analysis（RTOS 实时操作系统分析）, skill-creator（技能自动生成器）, supply-chain-analysis（供应链安全分析）。加载后会获得该领域的专业知识和参考文档。".into(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "skill_id": {
                            "type": "string",
                            "description": "要加载的技能 ID"
                        }
                    },
                    "required": ["skill_id"]
                }),
            },
            ToolDef {
                name: "upload_firmware".into(),
                description: "将固件文件从本地上传到远程 Ubuntu 服务器进行分析。".into(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "local_path": {
                            "type": "string",
                            "description": "本地固件文件路径"
                        },
                        "remote_path": {
                            "type": "string",
                            "description": "远程服务器存放路径，默认 ~/iot_firmware_analysis/"
                        }
                    },
                    "required": ["local_path"]
                }),
            },
        ];

        tools
    }

    /// 执行工具调用
    pub async fn execute(&self, tool_name: &str, args: &Value) -> Result<String> {
        match tool_name {
            "shell_exec" => self.exec_shell_remote(args).await,
            "shell_exec_local" => self.exec_shell_local(args).await,
            "python_exec" => self.exec_python(args).await,
            "docker_exec" => self.exec_docker(args).await,
            "reverse_analyze" => self.exec_reverse_analyze(args).await,
            "download_from_remote" => self.exec_download_from_remote(args).await,
            "file_read" => self.exec_file_read(args).await,
            "file_write" => self.exec_file_write(args).await,
            "http_request" => self.exec_http(args).await,
            "load_skill" => Ok(format!("[LOAD_SKILL:{}]", args["skill_id"].as_str().unwrap_or(""))),
            "upload_firmware" => self.exec_upload(args).await,
            _ => Err(anyhow::anyhow!("Unknown tool: {}", tool_name)),
        }
    }

    // ── 工具执行实现 ──

    async fn exec_shell_remote(&self, args: &Value) -> Result<String> {
        let command = args["command"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'command' parameter"))?;

        if let Some(ref ssh) = self.ssh {
            let working_dir = args["working_dir"].as_str();
            let full_cmd = if let Some(dir) = working_dir {
                format!("cd {} && {}", dir, command)
            } else {
                command.to_string()
            };
            let output = ssh.exec(&full_cmd)?;
            Ok(output.to_string())
        } else {
            // 无 SSH 连接，尝试本地执行（fallback）
            self.exec_shell_local(&json!({"command": command})).await
        }
    }

    async fn exec_shell_local(&self, args: &Value) -> Result<String> {
        let command = args["command"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'command' parameter"))?;

        let output = tokio::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", command])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        let mut result = stdout.to_string();
        if !stderr.is_empty() {
            result.push_str(&format!("\nSTDERR: {}", stderr));
        }
        if !output.status.success() {
            result.push_str(&format!("\n[exit code: {}]", output.status.code().unwrap_or(-1)));
        }
        
        // 截断过长输出
        if result.len() > 50000 {
            result = format!("{}...\n[output truncated, {} total bytes]", &result[..50000], result.len());
        }
        
        Ok(result)
    }

    async fn exec_python(&self, args: &Value) -> Result<String> {
        let code = args["code"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'code' parameter"))?;
        let save_as = args["save_as"].as_str();

        if let Some(ref ssh) = self.ssh {
            let remote_script = save_as.unwrap_or("/tmp/_agent_script.py");
            // 写入脚本
            ssh.exec(&format!("cat > {} << 'PYTHON_EOF'\n{}\nPYTHON_EOF", remote_script, code))?;
            ssh.exec(&format!("chmod +x {}", remote_script))?;
            let output = ssh.exec(&format!("python3 {}", remote_script))?;
            Ok(output.to_string())
        } else {
            // 本地执行
            let temp_file = std::env::temp_dir().join("_agent_script.py");
            tokio::fs::write(&temp_file, code).await?;
            let output = tokio::process::Command::new("python3")
                .arg(&temp_file)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await?;
            let result = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            Ok(result)
        }
    }

    async fn exec_docker(&self, args: &Value) -> Result<String> {
        let image = args["image"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'image' parameter"))?;
        let command = args["command"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'command' parameter"))?;
        let volumes = args["volumes"].as_array();

        let mut docker_cmd = format!("docker run --rm");
        if let Some(vols) = volumes {
            for v in vols {
                if let Some(vol) = v.as_str() {
                    docker_cmd.push_str(&format!(" -v {}", vol));
                }
            }
        }
        docker_cmd.push_str(&format!(" {} sh -c '{}'", image, command.replace("'", "'\\''")));

        if let Some(ref ssh) = self.ssh {
            let output = ssh.exec(&docker_cmd)?;
            Ok(output.to_string())
        } else {
            self.exec_shell_local(&json!({"command": docker_cmd})).await
        }
    }

    async fn exec_ghidra(&self, args: &Value) -> Result<String> {
        let binary_path = args["binary_path"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'binary_path'"))?;
        let analysis_type = args["analysis_type"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'analysis_type'"))?;
        let function_name = args["function_name"].as_str().unwrap_or("");
        let search_pattern = args["search_pattern"].as_str().unwrap_or("");

        if self.ghidra_path.is_empty() {
            return Err(anyhow::anyhow!("Ghidra 路径未配置，请在设置中填写 Ghidra 安装路径"));
        }

        // 查找 analyzeHeadless.bat
        let ghidra_dir = std::path::Path::new(&self.ghidra_path);
        let headless_bat = ghidra_dir.join("support").join("analyzeHeadless.bat");
        if !headless_bat.exists() {
            return Err(anyhow::anyhow!(
                "找不到 analyzeHeadless.bat，路径: {}。请确认 Ghidra 安装路径正确。",
                headless_bat.display()
            ));
        }

        // 检查本地二进制文件是否存在
        if !std::path::Path::new(binary_path).exists() {
            return Err(anyhow::anyhow!(
                "本地文件不存在: {}。请先使用 download_from_remote 从远程服务器下载。",
                binary_path
            ));
        }

        // 构建 Ghidra Jython 脚本
        let ghidra_script = match analysis_type {
            "decompile" => {
                if function_name.is_empty() {
                    r#"
from ghidra.app.decompiler import DecompInterface
decomp = DecompInterface()
decomp.openProgram(currentProgram)
fm = currentProgram.getFunctionManager()
count = 0
for func in fm.getFunctions(True):
    results = decomp.decompileFunction(func, 30, monitor)
    if results.decompileCompleted():
        print("=== " + func.getName() + " @ " + str(func.getEntryPoint()) + " ===")
        print(results.getDecompiledFunction().getC())
    count += 1
    if count > 50:
        print("[truncated: too many functions, use function_name to target specific function]")
        break
"#.to_string()
                } else {
                    format!(r#"
from ghidra.app.decompiler import DecompInterface
decomp = DecompInterface()
decomp.openProgram(currentProgram)
fm = currentProgram.getFunctionManager()
found = False
for func in fm.getFunctions(True):
    if func.getName() == "{}":
        results = decomp.decompileFunction(func, 30, monitor)
        if results.decompileCompleted():
            print(results.getDecompiledFunction().getC())
        found = True
        break
if not found:
    print("Function '{}' not found")
"#, function_name, function_name)
                }
            }
            "functions" => r#"
fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    print(func.getName() + " @ " + str(func.getEntryPoint()))
"#.to_string(),
            "strings" => format!(r#"
from ghidra.program.model.data import StringDataInstance
for s in currentProgram.getListing().getDefinedData(True):
    if s.hasStringValue():
        val = s.getValue()
        if val and "{}" in str(val).lower():
            print(str(s.getAddress()) + ": " + str(val))
"#, search_pattern.to_lowercase()),
            "xrefs" => {
                if !function_name.is_empty() {
                    format!(r#"
fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    if func.getName() == "{}":
        refs = getReferencesTo(func.getEntryPoint())
        for ref in refs:
            caller = fm.getFunctionContaining(ref.getFromAddress())
            if caller:
                print("Called from: " + caller.getName() + " @ " + str(ref.getFromAddress()))
        break
"#, function_name)
                } else {
                    "print('Please specify function_name for xrefs analysis')".to_string()
                }
            }
            "imports" => r#"
fm = currentProgram.getFunctionManager()
for func in fm.getExternalFunctions():
    print("IMPORT: " + func.getName() + " @ " + str(func.getEntryPoint()))
"#.to_string(),
            "dangerous_calls" => r#"
dangerous = ["system", "popen", "execve", "exec", "strcpy", "strcat", "sprintf", "gets", "scanf", "sscanf", "vsprintf", "vsnprintf"]
fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    name = func.getName().lower()
    if any(d in name for d in dangerous):
        print("DANGEROUS: " + func.getName() + " @ " + str(func.getEntryPoint()))
        refs = getReferencesTo(func.getEntryPoint())
        for ref in refs:
            caller = fm.getFunctionContaining(ref.getFromAddress())
            if caller:
                print("  Called from: " + caller.getName() + " @ " + str(ref.getFromAddress()))
"#.to_string(),
            _ => "print('Unknown analysis type')".to_string(),
        };

        // 创建临时脚本文件和项目目录
        let temp_dir = std::env::temp_dir();
        let script_path = temp_dir.join("_ghidra_agent_script.py");
        let project_dir = temp_dir.join("ghidra_agent_proj");
        
        // 确保项目目录存在
        tokio::fs::create_dir_all(&project_dir).await.ok();
        
        // 写入脚本
        tokio::fs::write(&script_path, &ghidra_script).await?;

        // 执行 Ghidra headless (本地 Windows)
        let output = tokio::process::Command::new(&headless_bat)
            .args([
                project_dir.to_str().unwrap_or(""),
                "AgentProject",
                "-import", binary_path,
                "-overwrite",
                "-postScript", script_path.to_str().unwrap_or(""),
                "-deleteProject",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        // Ghidra headless 的脚本 print() 输出格式:
        // 1. 可能直接输出（无前缀）
        // 2. 可能带 INFO 前缀: "INFO  _ghidra_agent_script.py> actual content"
        // 3. 也可能出现在 stderr 中
        // 策略：提取脚本输出行（带 .py> 前缀的提取内容部分），同时保留纯输出行
        let mut result = String::new();
        let script_marker = "_ghidra_agent_script.py>";
        let mut found_script_section = false;
        
        // 合并 stdout 和 stderr 一起处理
        let combined = format!("{}\n{}", stdout, stderr);
        
        for line in combined.lines() {
            // 跳过 Ghidra 引擎自身的日志（不包含脚本标记的 INFO/WARN 行）
            if (line.starts_with("INFO") || line.starts_with("WARN") || line.starts_with("ERROR")) 
                && !line.contains(script_marker) {
                // 检查是否到了脚本执行阶段
                if line.contains("postScript") || line.contains("_ghidra_agent_script") {
                    found_script_section = true;
                }
                continue;
            }
            
            // 提取脚本输出：去掉 "INFO  _ghidra_agent_script.py> " 前缀
            if line.contains(script_marker) {
                found_script_section = true;
                if let Some(pos) = line.find(script_marker) {
                    let content = &line[pos + script_marker.len()..];
                    result.push_str(content.trim_start());
                    result.push('\n');
                }
                continue;
            }
            
            // 跳过 Ghidra 启动相关噪音
            if line.contains("HeadlessAnalyzer") 
                || line.contains("ClassSearcher")
                || line.contains("LoggingInitialization")
                || line.contains("Loading user preferences")
                || line.contains("Searching for classes")
                || line.contains("Ignoring class")
                || line.contains("GhidraProgramUtilities")
                || line.contains("AutoAnalysisManager")
                || line.trim().is_empty() {
                continue;
            }
            
            // 到了脚本执行阶段后，保留所有非噪音行（可能是纯 print 输出）
            if found_script_section {
                result.push_str(line);
                result.push('\n');
            }
        }
        
        // 如果过滤后没内容，返回完整的 stdout + stderr（可能有错误信息）
        if result.trim().is_empty() {
            result = combined;
        }
        
        // 截断过长输出
        if result.len() > 100000 {
            result = format!("{}...\n[output truncated, {} total bytes]", &result[..100000], result.len());
        }

        Ok(result)
    }

    async fn exec_reverse_analyze(&self, args: &Value) -> Result<String> {
        let analysis_type = args["analysis_type"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'analysis_type'"))?;

        // Joern 类型走远程 SSH 执行
        if analysis_type.starts_with("joern_") {
            return self.exec_joern(args).await;
        }

        // Ghidra 类型走本地执行
        self.exec_ghidra(args).await
    }

    async fn exec_joern(&self, args: &Value) -> Result<String> {
        let analysis_type = args["analysis_type"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'analysis_type'"))?;
        let target_path = args["target_path"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Joern 分析需要 'target_path' 参数（远程服务器上的目标路径）"))?;
        let search_pattern = args["search_pattern"].as_str().unwrap_or("");
        let language = args["language"].as_str();

        let ssh = self.ssh.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Joern 分析需要 SSH 连接，请先配置并连接远程服务器"))?;

        // 自动检测语言：文件→ghidra（二进制），目录→c（源码）
        let detected_lang = if let Some(lang) = language {
            lang.to_string()
        } else {
            let is_dir_check = ssh.exec(&format!("test -d {} && echo DIR || echo FILE", target_path))?;
            if is_dir_check.stdout.contains("DIR") {
                "c".to_string()
            } else {
                "ghidra".to_string()
            }
        };

        let cpg_path = "/tmp/_agent_joern.cpg";

        // Step 1: 生成 CPG
        let parse_cmd = format!(
            "rm -rf {} && joern-parse {} --language {} --output {}",
            cpg_path, target_path, detected_lang, cpg_path
        );
        let parse_output = ssh.exec(&parse_cmd)?;

        // 检查 CPG 是否生成成功
        let check = ssh.exec(&format!("test -e {} && echo OK || echo FAIL", cpg_path))?;
        if !check.stdout.contains("OK") {
            return Ok(format!("Joern CPG 生成失败。\njoern-parse 输出:\n{}", parse_output));
        }

        // Step 2: 根据分析类型构建 Joern Scala 脚本
        let script_content = match analysis_type {
            "joern_scan" => format!(r#"
@main def exec(cpgFile: String) = {{
  importCpg(cpgFile)
  val dangerous = List("system", "popen", "execve", "exec", "strcpy", "strcat", "sprintf", "gets", "scanf", "sscanf", "vsprintf", "memcpy", "doSystemCmd")
  dangerous.foreach {{ name =>
    val calls = cpg.call.name(name).l
    if (calls.nonEmpty) {{
      println(s"\n=== $name ($${{calls.size}} calls) ===")
      calls.foreach {{ c =>
        val file = c.file.name.headOption.getOrElse("unknown")
        val line = c.lineNumber.getOrElse(0)
        val method = c.method.fullName
        println(s"  [$name] $file:$line in $method")
        println(s"    code: ${{c.code}}")
      }}
    }}
  }}
  // 硬编码 strcmp 检测
  val hardcoded = cpg.call.name("strcmp", "strncmp").where(_.argument.isLiteral).l
  if (hardcoded.nonEmpty) {{
    println(s"\n=== Hardcoded comparisons (${{hardcoded.size}} found) ===")
    hardcoded.foreach {{ c =>
      val file = c.file.name.headOption.getOrElse("unknown")
      val line = c.lineNumber.getOrElse(0)
      println(s"  [strcmp_hardcoded] $file:$line")
      println(s"    code: ${{c.code}}")
    }}
  }}
}}
"#),
            "joern_taint" => format!(r#"
@main def exec(cpgFile: String) = {{
  importCpg(cpgFile)
  println("=== Taint Analysis: Source -> Sink ===")
  val sources = cpg.call.name("recv", "recvfrom", "read", "fread", "fgets", "getenv", "scanf", "fscanf", "sscanf", "nvram_get", "nvram_safe_get", "acosNvramConfig_get").l
  println(s"Sources found: ${{sources.size}}")
  sources.groupBy(_.name).foreach {{ case (name, calls) =>
    println(s"  $name: ${{calls.size}} calls")
  }}
  val sinks = cpg.call.name("system", "popen", "execve", "exec", "doSystemCmd", "twsystem").l
  println(s"\nSinks found: ${{sinks.size}}")
  sinks.groupBy(_.name).foreach {{ case (name, calls) =>
    println(s"  $name: ${{calls.size}} calls")
  }}
  println("\n=== Data Flow Paths ===")
  val flows = sinks.reachableByFlows(sources).l
  if (flows.isEmpty) {{
    println("No direct taint flows found.")
  }} else {{
    println(s"Found ${{flows.size}} taint flow(s):")
    flows.foreach {{ flow =>
      println(s"\n--- Flow ---")
      flow.elements.foreach {{ elem =>
        val file = elem.file.name.headOption.getOrElse("?")
        val line = elem.lineNumber.getOrElse(0)
        println(s"  $file:$line  ${{elem.code}}")
      }}
    }}
  }}
}}
"#),
            "joern_hardcoded" => format!(r#"
@main def exec(cpgFile: String) = {{
  importCpg(cpgFile)
  println("=== Hardcoded Credential Detection ===")
  // strcmp/strncmp with literal arguments
  val strcmp = cpg.call.name("strcmp", "strncmp").where(_.argument.isLiteral).l
  if (strcmp.nonEmpty) {{
    println(s"\n--- strcmp with literals (${{strcmp.size}}) ---")
    strcmp.foreach {{ c =>
      val file = c.file.name.headOption.getOrElse("?")
      val line = c.lineNumber.getOrElse(0)
      println(s"  $file:$line  ${{c.code}}")
    }}
  }}
  // Password/key/secret related identifiers
  val creds = cpg.identifier.name(".*pass.*|.*pwd.*|.*key.*|.*secret.*|.*token.*|.*admin.*").l
  if (creds.nonEmpty) {{
    println(s"\n--- Credential-related identifiers (${{creds.size}}) ---")
    creds.take(50).foreach {{ id =>
      val file = id.file.name.headOption.getOrElse("?")
      val line = id.lineNumber.getOrElse(0)
      println(s"  $file:$line  ${{id.name}}")
    }}
    if (creds.size > 50) println(s"  ... and ${{creds.size - 50}} more")
  }}
  // Hardcoded string literals in function calls
  val literals = cpg.literal.code(".*password.*|.*passwd.*|.*admin.*|.*root.*|.*default.*").l
  if (literals.nonEmpty) {{
    println(s"\n--- Suspicious string literals (${{literals.size}}) ---")
    literals.take(30).foreach {{ lit =>
      val file = lit.file.name.headOption.getOrElse("?")
      val line = lit.lineNumber.getOrElse(0)
      println(s"  $file:$line  ${{lit.code}}")
    }}
  }}
}}
"#),
            "joern_query" => {
                if search_pattern.is_empty() {
                    return Ok("joern_query 需要 search_pattern 参数来指定 Joern Scala 查询表达式。\n示例: cpg.call.name(\"system\").l".to_string());
                }
                format!(r#"
@main def exec(cpgFile: String) = {{
  importCpg(cpgFile)
  val result = {query}
  println(result)
}}
"#, query = search_pattern)
            }
            _ => return Err(anyhow::anyhow!("Unknown Joern analysis type: {}", analysis_type)),
        };

        // Step 3: 写入脚本并执行
        let script_path = "/tmp/_agent_joern_query.sc";
        let write_cmd = format!(
            "cat > {} << 'JOERN_SCRIPT_EOF'\n{}\nJOERN_SCRIPT_EOF",
            script_path, script_content
        );
        ssh.exec(&write_cmd)?;

        let exec_cmd = format!(
            "joern --script {} --params cpgFile={}",
            script_path, cpg_path
        );
        let output = ssh.exec(&exec_cmd)?;

        let mut result = output.to_string();

        // 截断过长输出
        if result.len() > 100000 {
            result = format!("{}...\n[output truncated, {} total bytes]", &result[..100000], result.len());
        }

        Ok(result)
    }

    async fn exec_download_from_remote(&self, args: &Value) -> Result<String> {
        let remote_path = args["remote_path"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'remote_path'"))?;
        let default_local = {
            let base_dir = if !self.local_download_path.is_empty() {
                std::path::PathBuf::from(&self.local_download_path)
            } else {
                std::env::temp_dir().join("iot_agent_downloads")
            };
            let filename = std::path::Path::new(remote_path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or("downloaded_file".to_string());
            base_dir.join(&filename)
        };
        let local_path = args["local_path"].as_str()
            .map(|p| std::path::PathBuf::from(p))
            .unwrap_or(default_local);

        if let Some(ref ssh) = self.ssh {
            // 确保本地目录存在
            if let Some(parent) = local_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            
            // 解析 ~ 路径
            let resolved_remote = self.resolve_home_path(ssh, remote_path)?;
            
            // 通过 SCP 下载
            ssh.download_file(&resolved_remote, local_path.to_str().unwrap_or(""))?;
            
            Ok(format!("Downloaded {} -> {}", remote_path, local_path.display()))
        } else {
            Err(anyhow::anyhow!("Download requires SSH connection"))
        }
    }

    async fn exec_file_read(&self, args: &Value) -> Result<String> {
        let path = args["path"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'path'"))?;
        let encoding = args["encoding"].as_str().unwrap_or("utf-8");
        let max_size = args["max_size"].as_u64().unwrap_or(65536);

        if let Some(ref ssh) = self.ssh {
            let cmd = match encoding {
                "hex" => format!("xxd {} | head -c {}", path, max_size),
                "base64" => format!("base64 {} | head -c {}", path, max_size),
                _ => format!("head -c {} {}", max_size, path),
            };
            let output = ssh.exec(&cmd)?;
            Ok(output.to_string())
        } else {
            let content = tokio::fs::read_to_string(path).await?;
            Ok(content.chars().take(max_size as usize).collect())
        }
    }

    async fn exec_file_write(&self, args: &Value) -> Result<String> {
        let path = args["path"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'path'"))?;
        let content = args["content"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'content'"))?;
        let mode = args["mode"].as_str().unwrap_or("644");

        if let Some(ref ssh) = self.ssh {
            let cmd = format!("cat > {} << 'WRITE_EOF'\n{}\nWRITE_EOF\nchmod {} {}", path, content, mode, path);
            let output = ssh.exec(&cmd)?;
            Ok(format!("File written: {} (mode {})\n{}", path, mode, output))
        } else {
            tokio::fs::write(path, content).await?;
            Ok(format!("File written: {}", path))
        }
    }

    async fn exec_http(&self, args: &Value) -> Result<String> {
        let method = args["method"].as_str().unwrap_or("GET");
        let url = args["url"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'url'"))?;

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let mut req = match method {
            "GET" => client.get(url),
            "POST" => client.post(url),
            "PUT" => client.put(url),
            "DELETE" => client.delete(url),
            "PATCH" => client.patch(url),
            _ => return Err(anyhow::anyhow!("Unsupported method: {}", method)),
        };

        if let Some(headers) = args["headers"].as_object() {
            for (k, v) in headers {
                if let Some(val) = v.as_str() {
                    req = req.header(k, val);
                }
            }
        }

        if let Some(body) = args["body"].as_str() {
            req = req.body(body.to_string());
        }

        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let headers: Vec<String> = resp.headers().iter()
            .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
            .collect();
        let body = resp.text().await?;

        let mut result = format!("HTTP {} {}\n", status, url);
        result.push_str("--- Headers ---\n");
        for h in &headers {
            result.push_str(&format!("{}\n", h));
        }
        result.push_str("--- Body ---\n");
        if body.len() > 20000 {
            result.push_str(&format!("{}...\n[truncated, {} bytes total]", &body[..20000], body.len()));
        } else {
            result.push_str(&body);
        }

        Ok(result)
    }

    async fn exec_upload(&self, args: &Value) -> Result<String> {
        let local_path = args["local_path"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'local_path'"))?;
        let remote_path = args["remote_path"].as_str()
            .unwrap_or("~/iot_firmware_analysis/");

        if let Some(ref ssh) = self.ssh {
            // 解析 ~ 为实际 home 路径（SCP 协议不支持 ~ 展开）
            let resolved_path = self.resolve_home_path(ssh, remote_path)?;

            // 确保目录存在
            ssh.exec(&format!("mkdir -p {}", resolved_path))?;
            let filename = std::path::Path::new(local_path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or("firmware.bin".to_string());
            let full_remote = format!("{}/{}", resolved_path.trim_end_matches('/'), filename);
            ssh.upload_file(local_path, &full_remote)?;
            Ok(format!("Uploaded {} -> {}", local_path, full_remote))
        } else {
            Err(anyhow::anyhow!("Upload requires SSH connection"))
        }
    }

    /// 解析路径中的 ~ 为实际 home 目录
    fn resolve_home_path(&self, ssh: &SshManager, path: &str) -> Result<String> {
        if path.starts_with('~') {
            let output = ssh.exec("echo $HOME")?;
            let home = output.stdout.trim().to_string();
            if home.is_empty() {
                return Err(anyhow::anyhow!("Failed to resolve home directory"));
            }
            Ok(path.replacen('~', &home, 1))
        } else {
            Ok(path.to_string())
        }
    }
}
