use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use anyhow::Result;
use chrono::Utc;

/// Skills 知识库系统
/// 兼容 Anthropic Skills 规范（文件夹 + SKILL.md）和旧版扁平 .md 格式
/// 支持双源扫描：项目 skills/ 目录 + 应用数据目录

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skill {
    pub id: String,
    pub name: String,
    pub category: SkillCategory,
    pub description: String,
    /// SKILL.md 主体内容
    pub content: String,
    /// references/ 目录下的参考文档（按文件名索引）
    pub references: HashMap<String, String>,
    /// scripts/ 目录下的脚本路径列表（不加载到上下文，可按需执行）
    pub script_paths: Vec<String>,
    pub tags: Vec<String>,
    pub source_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SkillCategory {
    VulnType,
    ToolUsage,
    Architecture,
    Protocol,
    DeviceSpecific,
    Methodology,
    PostAnalysis,
}

impl SkillCategory {
    fn from_str_loose(s: &str) -> Self {
        let lower = s.to_lowercase();
        if lower.contains("vuln") { SkillCategory::VulnType }
        else if lower.contains("tool") { SkillCategory::ToolUsage }
        else if lower.contains("arch") { SkillCategory::Architecture }
        else if lower.contains("proto") || lower.contains("network") { SkillCategory::Protocol }
        else if lower.contains("device") { SkillCategory::DeviceSpecific }
        else if lower.contains("method") { SkillCategory::Methodology }
        else if lower.contains("post") || lower.contains("analysis") { SkillCategory::PostAnalysis }
        else { SkillCategory::Methodology }
    }
}

pub struct SkillManager {
    /// 应用数据目录下的 skills 路径（可写，存后续自动生成的技能）
    data_skills_dir: PathBuf,
    /// 项目根目录下的 skills 路径（只读，包含 Anthropic 格式技能包）
    project_skills_dir: Option<PathBuf>,
    loaded_skills: HashMap<String, Skill>,
    index: Vec<SkillIndex>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillIndex {
    pub id: String,
    pub name: String,
    pub category: SkillCategory,
    pub description: String,
    pub tags: Vec<String>,
    /// 标记来源："project" 或 "data"
    pub source: String,
}

impl SkillManager {
    pub fn new(data_skills_dir: PathBuf) -> Self {
        Self {
            data_skills_dir,
            project_skills_dir: None,
            loaded_skills: HashMap::new(),
            index: Vec::new(),
        }
    }

    /// 设置项目 skills 目录（Anthropic 格式技能包所在目录）
    pub fn set_project_skills_dir(&mut self, dir: PathBuf) {
        self.project_skills_dir = Some(dir);
    }

    /// 初始化：扫描所有技能源，构建索引
    pub async fn init(&mut self) -> Result<()> {
        // 确保数据目录存在
        tokio::fs::create_dir_all(&self.data_skills_dir).await?;
        tokio::fs::create_dir_all(self.data_skills_dir.join("post_analysis")).await?;

        // 扫描并索引所有技能源
        self.rebuild_index().await?;

        Ok(())
    }

    /// 按需加载技能（包含 SKILL.md 正文 + references 内容）
    pub async fn load_skill(&mut self, skill_id: &str) -> Result<&Skill> {
        if !self.loaded_skills.contains_key(skill_id) {
            let skill = self.read_skill_full(skill_id).await?;
            self.loaded_skills.insert(skill_id.to_string(), skill);
        }
        Ok(self.loaded_skills.get(skill_id).unwrap())
    }

    /// 获取所有已加载技能的名称
    pub fn loaded_skill_names(&self) -> Vec<String> {
        self.loaded_skills.keys().cloned().collect()
    }

    /// 搜索相关技能
    pub fn search_skills(&self, query: &str) -> Vec<&SkillIndex> {
        let query_lower = query.to_lowercase();
        self.index.iter().filter(|s| {
            s.name.to_lowercase().contains(&query_lower) ||
            s.description.to_lowercase().contains(&query_lower) ||
            s.tags.iter().any(|t| t.to_lowercase().contains(&query_lower))
        }).collect()
    }

    /// 获取已加载技能的摘要（注入到 prompt 中）
    pub fn get_loaded_context(&self) -> String {
        if self.loaded_skills.is_empty() {
            return String::new();
        }
        let mut ctx = String::from("\n## 已激活的技能知识\n");
        for (id, skill) in &self.loaded_skills {
            ctx.push_str(&format!("\n### {} ({})\n{}\n", skill.name, id, skill.content));
            // 附加已加载的 references
            for (ref_name, ref_content) in &skill.references {
                ctx.push_str(&format!("\n#### 参考: {}\n{}\n", ref_name, ref_content));
            }
        }
        ctx
    }

    /// 列出技能可用的脚本（供工具调用执行）
    pub fn get_skill_scripts(&self, skill_id: &str) -> Vec<String> {
        self.loaded_skills.get(skill_id)
            .map(|s| s.script_paths.clone())
            .unwrap_or_default()
    }

    /// 保存分析总结为新技能（Anthropic SKILL.md 格式）
    pub async fn save_analysis_skill(&mut self, name: &str, content: &str, tags: Vec<String>) -> Result<String> {
        let id = format!("analysis_{}", Utc::now().format("%Y%m%d_%H%M%S"));
        let skill_dir = self.data_skills_dir.join("post_analysis").join(&id);
        tokio::fs::create_dir_all(&skill_dir).await?;

        let file_content = format!(
            "---\nname: {}\ndescription: Auto-generated analysis: {}\n---\n\n{}",
            name, name, content
        );
        tokio::fs::write(skill_dir.join("SKILL.md"), &file_content).await?;

        let skill = Skill {
            id: id.clone(),
            name: name.to_string(),
            category: SkillCategory::PostAnalysis,
            description: format!("Auto-generated analysis: {}", name),
            content: content.to_string(),
            references: HashMap::new(),
            script_paths: Vec::new(),
            tags: tags.clone(),
            source_path: skill_dir.to_string_lossy().to_string(),
        };

        self.index.push(SkillIndex {
            id: skill.id.clone(),
            name: skill.name.clone(),
            category: skill.category.clone(),
            description: skill.description.clone(),
            tags: skill.tags.clone(),
            source: "data".into(),
        });

        self.loaded_skills.insert(id.clone(), skill);
        Ok(id)
    }

    /// 获取完整索引
    pub fn get_index(&self) -> &[SkillIndex] {
        &self.index
    }

    /// 删除技能（从磁盘和索引中移除）
    pub async fn delete_skill(&mut self, skill_id: &str) -> Result<bool> {
        // 先加载技能获取 source_path
        let source_path = match self.read_skill_full(skill_id).await {
            Ok(skill) => PathBuf::from(&skill.source_path),
            Err(_) => return Ok(false),
        };

        // 删除磁盘上的文件/文件夹
        if source_path.is_dir() {
            tokio::fs::remove_dir_all(&source_path).await?;
        } else if source_path.is_file() {
            tokio::fs::remove_file(&source_path).await?;
        } else {
            return Ok(false);
        }

        // 从索引中移除
        self.index.retain(|s| s.id != skill_id);
        // 从已加载缓存中移除
        self.loaded_skills.remove(skill_id);

        Ok(true)
    }

    // ── 内部：读取完整技能（正文 + references） ──

    async fn read_skill_full(&self, skill_id: &str) -> Result<Skill> {
        // 1. 优先查找 Anthropic 格式（文件夹 + SKILL.md）
        //    先查项目 skills 目录，再查 data 目录
        let search_dirs: Vec<&PathBuf> = {
            let mut dirs = Vec::new();
            if let Some(ref proj) = self.project_skills_dir {
                dirs.push(proj);
            }
            dirs.push(&self.data_skills_dir);
            dirs
        };

        for base_dir in &search_dirs {
            // 直接子文件夹匹配 skill_id
            let skill_dir = base_dir.join(skill_id);
            let skill_md = skill_dir.join("SKILL.md");
            if skill_md.exists() {
                return self.load_anthropic_skill(skill_id, &skill_dir).await;
            }

            // 递归一层子目录（如 post_analysis/analysis_xxx/）
            if let Ok(mut entries) = tokio::fs::read_dir(base_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let sub = entry.path();
                    if sub.is_dir() {
                        let nested = sub.join(skill_id);
                        let nested_md = nested.join("SKILL.md");
                        if nested_md.exists() {
                            return self.load_anthropic_skill(skill_id, &nested).await;
                        }
                    }
                }
            }

            // 兼容旧格式：扁平 .md 文件
            let flat_subdirs = ["vuln_types", "tools", "architectures", "protocols", "devices", "methodology", "post_analysis"];
            for subdir in &flat_subdirs {
                let path = base_dir.join(subdir).join(format!("{}.md", skill_id));
                if path.exists() {
                    let content = tokio::fs::read_to_string(&path).await?;
                    return self.parse_flat_skill_file(skill_id, &content, &path);
                }
            }
        }

        Err(anyhow::anyhow!("Skill not found: {}", skill_id))
    }

    /// 加载 Anthropic 格式技能包（SKILL.md + references/ + scripts/）
    async fn load_anthropic_skill(&self, id: &str, skill_dir: &PathBuf) -> Result<Skill> {
        let skill_md_path = skill_dir.join("SKILL.md");
        let raw = tokio::fs::read_to_string(&skill_md_path).await?;

        let (name, description, body, tags) = Self::parse_frontmatter(&raw, id);

        // 加载 references/
        let mut references = HashMap::new();
        let refs_dir = skill_dir.join("references");
        if refs_dir.exists() {
            if let Ok(mut entries) = tokio::fs::read_dir(&refs_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    if path.extension().map(|e| e == "md").unwrap_or(false) {
                        let ref_name = path.file_stem().unwrap().to_string_lossy().to_string();
                        if let Ok(content) = tokio::fs::read_to_string(&path).await {
                            references.insert(ref_name, content);
                        }
                    }
                }
            }
        }

        // 收集 scripts/ 路径
        let mut script_paths = Vec::new();
        let scripts_dir = skill_dir.join("scripts");
        if scripts_dir.exists() {
            if let Ok(mut entries) = tokio::fs::read_dir(&scripts_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    if path.is_file() {
                        script_paths.push(path.to_string_lossy().to_string());
                    }
                }
            }
        }

        // 从描述推断 category
        let category = SkillCategory::from_str_loose(&format!("{} {} {}", &name, &description, &id));

        Ok(Skill {
            id: id.to_string(),
            name,
            category,
            description,
            content: body,
            references,
            script_paths,
            tags,
            source_path: skill_dir.to_string_lossy().to_string(),
        })
    }

    /// 解析 YAML frontmatter（兼容 Anthropic 和旧格式）
    fn parse_frontmatter(content: &str, fallback_id: &str) -> (String, String, String, Vec<String>) {
        if content.starts_with("---") {
            let parts: Vec<&str> = content.splitn(3, "---").collect();
            if parts.len() >= 3 {
                let meta = parts[1];
                let body = parts[2].trim().to_string();

                let name = Self::extract_field(meta, "name")
                    .unwrap_or_else(|| fallback_id.to_string());
                let description = Self::extract_field(meta, "description")
                    .unwrap_or_default();
                let tags_str = Self::extract_field(meta, "tags").unwrap_or_default();
                let tags: Vec<String> = tags_str
                    .trim_matches(|c| c == '[' || c == ']')
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();

                return (name, description, body, tags);
            }
        }
        (fallback_id.to_string(), String::new(), content.to_string(), Vec::new())
    }

    /// 解析旧格式扁平 .md 文件
    fn parse_flat_skill_file(&self, id: &str, content: &str, path: &PathBuf) -> Result<Skill> {
        let (name, description, body, tags) = Self::parse_frontmatter(content, id);
        let category = SkillCategory::from_str_loose(&format!("{} {}", &name, &description));

        Ok(Skill {
            id: id.to_string(),
            name,
            category,
            description,
            content: body,
            references: HashMap::new(),
            script_paths: Vec::new(),
            tags,
            source_path: path.to_string_lossy().to_string(),
        })
    }

    fn extract_field(text: &str, field: &str) -> Option<String> {
        for line in text.lines() {
            let trimmed = line.trim();
            let prefix = format!("{}:", field);
            if trimmed.starts_with(&prefix) {
                return Some(trimmed[prefix.len()..].trim().to_string());
            }
        }
        None
    }

    /// 重建索引：扫描项目 skills 目录 + 数据 skills 目录
    async fn rebuild_index(&mut self) -> Result<()> {
        self.index.clear();

        // 克隆路径以避免借用冲突
        let proj_dir = self.project_skills_dir.clone();
        let data_dir = self.data_skills_dir.clone();

        // 扫描项目 skills 目录（Anthropic 格式优先）
        if let Some(ref dir) = proj_dir {
            if dir.exists() {
                self.scan_directory(dir, "project").await?;
            }
        }

        // 扫描数据目录（内置 + 自动生成的 post_analysis 技能）
        if data_dir.exists() {
            self.scan_directory(&data_dir, "data").await?;
        }

        Ok(())
    }

    /// 扫描一个目录，识别 Anthropic 格式和旧格式技能
    async fn scan_directory(&mut self, dir: &PathBuf, source: &str) -> Result<()> {
        let mut entries = tokio::fs::read_dir(dir).await?;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();

            if path.is_dir() {
                let dir_name = path.file_name().unwrap().to_string_lossy().to_string();
                // 跳过 skill-creator（元技能）和隐藏目录
                if dir_name.starts_with('.') || dir_name == "skill-creator" || dir_name == "node_modules" {
                    continue;
                }

                // 检查是否是 Anthropic 格式技能包（有 SKILL.md）
                let skill_md = path.join("SKILL.md");
                if skill_md.exists() {
                    if let Ok(raw) = tokio::fs::read_to_string(&skill_md).await {
                        let (name, description, _body, tags) = Self::parse_frontmatter(&raw, &dir_name);
                        let category = SkillCategory::from_str_loose(&format!("{} {} {}", &name, &description, &dir_name));

                        // 避免重复
                        if !self.index.iter().any(|i| i.id == dir_name) {
                            self.index.push(SkillIndex {
                                id: dir_name.clone(),
                                name,
                                category,
                                description,
                                tags,
                                source: source.into(),
                            });
                        }
                    }
                } else {
                    // 可能是旧格式子目录（vuln_types/, tools/ 等），递归扫描一层
                    self.scan_flat_subdir(&path, source).await?;
                }
            }
        }
        Ok(())
    }

    /// 扫描旧格式子目录中的扁平 .md 文件
    async fn scan_flat_subdir(&mut self, dir: &PathBuf, source: &str) -> Result<()> {
        if let Ok(mut entries) = tokio::fs::read_dir(dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();

                // Anthropic 格式子技能包
                if path.is_dir() {
                    let skill_md = path.join("SKILL.md");
                    if skill_md.exists() {
                        let dir_name = path.file_name().unwrap().to_string_lossy().to_string();
                        if let Ok(raw) = tokio::fs::read_to_string(&skill_md).await {
                            let (name, description, _body, tags) = Self::parse_frontmatter(&raw, &dir_name);
                            let category = SkillCategory::from_str_loose(&format!("{} {} {}", &name, &description, &dir_name));
                            if !self.index.iter().any(|i| i.id == dir_name) {
                                self.index.push(SkillIndex {
                                    id: dir_name,
                                    name,
                                    category,
                                    description,
                                    tags,
                                    source: source.into(),
                                });
                            }
                        }
                    }
                    continue;
                }

                // 旧格式扁平 .md
                if path.extension().map(|e| e == "md").unwrap_or(false) {
                    let id = path.file_stem().unwrap().to_string_lossy().to_string();
                    if self.index.iter().any(|i| i.id == id) {
                        continue; // 项目技能优先，跳过重复
                    }
                    if let Ok(content) = tokio::fs::read_to_string(&path).await {
                        let (name, description, _body, tags) = Self::parse_frontmatter(&content, &id);
                        let category = SkillCategory::from_str_loose(&format!("{} {} {}", &name, &description, &id));
                        self.index.push(SkillIndex {
                            id,
                            name,
                            category,
                            description,
                            tags,
                            source: source.into(),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}
