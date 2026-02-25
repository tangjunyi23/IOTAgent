use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use anyhow::Result;

/// 知识库系统 - 存储分析结果供后续学习
#[derive(Debug, Clone, Serialize, Deserialize)]
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

pub struct KnowledgeBase {
    db_path: PathBuf,
    entries: Vec<KnowledgeEntry>,
}

impl KnowledgeBase {
    pub fn new(db_path: PathBuf) -> Self {
        Self {
            db_path,
            entries: Vec::new(),
        }
    }

    pub async fn init(&mut self) -> Result<()> {
        tokio::fs::create_dir_all(self.db_path.parent().unwrap_or(&self.db_path)).await?;
        if self.db_path.exists() {
            let content = tokio::fs::read_to_string(&self.db_path).await?;
            self.entries = serde_json::from_str(&content).unwrap_or_default();
        }
        Ok(())
    }

    pub async fn save_entry(&mut self, entry: KnowledgeEntry) -> Result<()> {
        self.entries.push(entry);
        let json = serde_json::to_string_pretty(&self.entries)?;
        tokio::fs::write(&self.db_path, json).await?;
        Ok(())
    }

    /// 删除知识条目
    pub async fn delete_entry(&mut self, id: &str) -> Result<bool> {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        if self.entries.len() < before {
            let json = serde_json::to_string_pretty(&self.entries)?;
            tokio::fs::write(&self.db_path, json).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// 搜索相关知识
    pub fn search(&self, query: &str) -> Vec<&KnowledgeEntry> {
        let q = query.to_lowercase();
        self.entries.iter().filter(|e| {
            e.title.to_lowercase().contains(&q) ||
            e.device_type.to_lowercase().contains(&q) ||
            e.techniques_used.iter().any(|t| t.to_lowercase().contains(&q))
        }).collect()
    }

    pub fn get_all(&self) -> &[KnowledgeEntry] {
        &self.entries
    }
}
