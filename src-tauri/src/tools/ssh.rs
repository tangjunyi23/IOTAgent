use anyhow::Result;
use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::agent::types::{SshConfig, SshAuth};

/// 对命令进行 shell 转义，用单引号包裹并处理内部的单引号
fn shell_escape(cmd: &str) -> String {
    format!("'{}'", cmd.replace("'", "'\\''"))
}

/// SSH 远程连接管理器
/// 连接到 Ubuntu 服务器执行逆向工具命令
pub struct SshManager {
    config: SshConfig,
    session: Option<Arc<Mutex<Session>>>,
}

impl SshManager {
    pub fn new(config: SshConfig) -> Self {
        Self {
            config,
            session: None,
        }
    }

    /// 建立 SSH 连接
    pub fn connect(&mut self) -> Result<()> {
        let tcp = TcpStream::connect(format!("{}:{}", self.config.host, self.config.port))?;
        let mut sess = Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;

        match &self.config.auth {
            SshAuth::Password { password } => {
                sess.userauth_password(&self.config.username, password)?;
            }
            SshAuth::Key { private_key_path, passphrase } => {
                sess.userauth_pubkey_file(
                    &self.config.username,
                    None,
                    Path::new(private_key_path),
                    passphrase.as_deref(),
                )?;
            }
        }

        if !sess.authenticated() {
            return Err(anyhow::anyhow!("SSH authentication failed"));
        }

        self.session = Some(Arc::new(Mutex::new(sess)));
        Ok(())
    }

    /// 执行远程命令
    pub fn exec(&self, command: &str) -> Result<SshOutput> {
        let session = self.session.as_ref()
            .ok_or_else(|| anyhow::anyhow!("SSH not connected"))?;
        
        let sess = session.lock().map_err(|e| anyhow::anyhow!("Lock error: {}", e))?;
        let mut channel = sess.channel_session()?;

        // SSH channel.exec() 创建非交互式 shell，不会加载用户的 profile 文件
        // 且 Ubuntu 默认 .bashrc 开头有 `case $- in *i*) ;; *) return;; esac` 守卫
        // 非交互式 shell 中即使 source ~/.bashrc 也会被跳过
        // 因此使用 bash -i（交互模式）+ -c 来执行命令，绕过守卫，加载完整 PATH
        let wrapped = format!(
            "bash -i -c {}",
            shell_escape(command)
        );
        channel.exec(&wrapped)?;

        let mut stdout = String::new();
        channel.read_to_string(&mut stdout)?;

        let mut stderr = String::new();
        channel.stderr().read_to_string(&mut stderr)?;

        // bash -i 在无 TTY 的 SSH channel 上会产生无害警告，过滤掉以免误导 AI agent
        let stderr = stderr
            .lines()
            .filter(|line| {
                !line.contains("cannot set terminal process group")
                    && !line.contains("no job control in this shell")
            })
            .collect::<Vec<_>>()
            .join("\n");

        channel.wait_close()?;
        let exit_code = channel.exit_status()?;

        Ok(SshOutput {
            stdout,
            stderr,
            exit_code,
        })
    }

    /// 上传文件到远程服务器
    pub fn upload_file(&self, local_path: &str, remote_path: &str) -> Result<()> {
        let session = self.session.as_ref()
            .ok_or_else(|| anyhow::anyhow!("SSH not connected"))?;
        
        let sess = session.lock().map_err(|e| anyhow::anyhow!("Lock error: {}", e))?;
        let content = std::fs::read(local_path)?;
        let mut remote_file = sess.scp_send(
            Path::new(remote_path),
            0o644,
            content.len() as u64,
            None,
        )?;
        
        use std::io::Write;
        remote_file.write_all(&content)?;
        remote_file.send_eof()?;
        remote_file.wait_eof()?;
        remote_file.close()?;
        remote_file.wait_close()?;

        Ok(())
    }

    /// 下载远程文件
    pub fn download_file(&self, remote_path: &str, local_path: &str) -> Result<()> {
        let session = self.session.as_ref()
            .ok_or_else(|| anyhow::anyhow!("SSH not connected"))?;
        
        let sess = session.lock().map_err(|e| anyhow::anyhow!("Lock error: {}", e))?;
        let (mut remote_file, _stat) = sess.scp_recv(Path::new(remote_path))?;
        
        let mut content = Vec::new();
        remote_file.read_to_end(&mut content)?;
        std::fs::write(local_path, &content)?;

        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.session.is_some()
    }

    pub fn disconnect(&mut self) {
        self.session = None;
    }
}

#[derive(Debug, Clone)]
pub struct SshOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl std::fmt::Display for SshOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.stdout.is_empty() {
            write!(f, "{}", self.stdout)?;
        }
        if !self.stderr.is_empty() {
            if !self.stdout.is_empty() {
                write!(f, "\n")?;
            }
            write!(f, "STDERR: {}", self.stderr)?;
        }
        if self.exit_code != 0 {
            write!(f, "\n[exit code: {}]", self.exit_code)?;
        }
        Ok(())
    }
}
