<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { invoke } from '@tauri-apps/api/core'

interface SkillIndex {
  id: string
  name: string
  category: string
  description: string
  tags: string[]
}

interface SkillDetail {
  id: string
  name: string
  category: string
  description: string
  content: string
  references: Record<string, string>
  script_paths: string[]
  tags: string[]
  source_path: string
}

const skills = ref<SkillIndex[]>([])
const loading = ref(true)
const activeCategory = ref('all')
const searchQuery = ref('')
const selectedSkill = ref<SkillDetail | null>(null)
const loadingSkillId = ref('')
const deletingSkillId = ref('')

const categories = [
  { key: 'all', label: '全部' },
  { key: 'VulnType', label: '漏洞类型' },
  { key: 'ToolUsage', label: '工具技巧' },
  { key: 'Architecture', label: '架构知识' },
  { key: 'Protocol', label: '协议分析' },
  { key: 'DeviceSpecific', label: '设备特定' },
  { key: 'Methodology', label: '方法论' },
  { key: 'PostAnalysis', label: '分析总结' },
]

const filteredSkills = computed(() => {
  let result = skills.value
  if (activeCategory.value !== 'all') {
    result = result.filter(s => s.category === activeCategory.value)
  }
  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase()
    result = result.filter(s =>
      s.name.toLowerCase().includes(q) ||
      s.description.toLowerCase().includes(q) ||
      s.tags.some(t => t.toLowerCase().includes(q))
    )
  }
  return result
})

async function viewSkill(skillId: string) {
  if (selectedSkill.value?.id === skillId) {
    selectedSkill.value = null
    return
  }
  loadingSkillId.value = skillId
  try {
    const raw = await invoke<string>('get_skill_content', { skillId })
    selectedSkill.value = JSON.parse(raw) as SkillDetail
  } catch (e) {
    console.warn('Failed to load skill:', e)
  } finally {
    loadingSkillId.value = ''
  }
}

function closeDetail() {
  selectedSkill.value = null
}

async function deleteSkill(skillId: string, event: Event) {
  event.stopPropagation()
  if (!confirm('确定要删除该技能吗？此操作将从磁盘中移除技能文件，不可恢复。')) return
  deletingSkillId.value = skillId
  try {
    await invoke<string>('delete_skill', { skillId })
    skills.value = skills.value.filter(s => s.id !== skillId)
    if (selectedSkill.value?.id === skillId) {
      selectedSkill.value = null
    }
  } catch (e) {
    console.warn('Failed to delete skill:', e)
  } finally {
    deletingSkillId.value = ''
  }
}

onMounted(async () => {
  try {
    const raw = await invoke<string>('get_skills')
    skills.value = JSON.parse(raw)
  } catch (e) {
    console.warn('Failed to load skills:', e)
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="skills-page">
    <div class="page-header animate__animated animate__fadeInDown">
      <h1 class="page-title">
        技能库
      </h1>
      <p class="page-subtitle">按需加载的专业知识模块 · 持续积累的分析经验</p>
    </div>

    <!-- Category Tabs -->
    <div class="category-tabs animate__animated animate__fadeInUp">
      <button
        v-for="cat in categories"
        :key="cat.key"
        :class="['cat-btn', { active: activeCategory === cat.key }]"
        @click="activeCategory = cat.key"
      >
        <span>{{ cat.label }}</span>
      </button>
    </div>

    <!-- Search -->
    <div class="search-bar glass-card animate__animated animate__fadeInUp" style="animation-delay: 0.1s">
      <input v-model="searchQuery" class="input" placeholder="搜索技能..." />
    </div>

    <!-- Skills Grid -->
    <div v-if="loading" class="loading-state">
      <div class="spinner-lg"></div>
      <p>加载技能库...</p>
    </div>

    <div v-else-if="filteredSkills.length === 0" class="empty-state animate__animated animate__fadeIn">
      <span class="empty-icon">—</span>
      <h3>暂无技能</h3>
      <p>此分类下尚无技能模块</p>
    </div>

    <div v-else class="skills-grid">
      <div
        v-for="(skill, i) in filteredSkills"
        :key="skill.id"
        class="skill-card glass-card animate__animated animate__fadeInUp"
        :class="{ 'is-loading': loadingSkillId === skill.id }"
        :style="{ animationDelay: Math.min(i * 0.05, 0.5) + 's' }"
        @click="viewSkill(skill.id)"
      >
        <div class="skill-info">
          <h3>{{ skill.name }}</h3>
          <p>{{ skill.description }}</p>
          <div class="skill-tags">
            <span v-for="tag in skill.tags" :key="tag" class="skill-tag">{{ tag }}</span>
          </div>
        </div>
        <div class="skill-meta">
          <button
            class="btn-delete-skill"
            :disabled="deletingSkillId === skill.id"
            @click="deleteSkill(skill.id, $event)"
            title="删除技能"
          >×</button>
          <span class="skill-id">{{ skill.id }}</span>
          <span class="skill-view-hint">点击查看</span>
        </div>
      </div>
    </div>

    <!-- Skill Detail Modal -->
    <Teleport to="body">
      <div v-if="selectedSkill" class="modal-overlay" @click.self="closeDetail">
        <div class="modal-content">
          <div class="modal-header">
            <div>
              <h2>{{ selectedSkill.name }}</h2>
              <p class="modal-desc">{{ selectedSkill.description }}</p>
            </div>
            <button class="modal-close" @click="closeDetail">×</button>
          </div>
          <div class="modal-body">
            <div class="modal-section">
              <h4>技能内容</h4>
              <pre class="skill-content-text">{{ selectedSkill.content }}</pre>
            </div>
            <div v-if="Object.keys(selectedSkill.references).length > 0" class="modal-section">
              <h4>参考文档</h4>
              <div v-for="(content, name) in selectedSkill.references" :key="name" class="ref-block">
                <h5>{{ name }}</h5>
                <pre class="skill-content-text ref-text">{{ content }}</pre>
              </div>
            </div>
            <div v-if="selectedSkill.script_paths.length > 0" class="modal-section">
              <h4>关联脚本</h4>
              <div v-for="sp in selectedSkill.script_paths" :key="sp" class="script-path">{{ sp }}</div>
            </div>
            <div class="modal-section modal-meta-row">
              <span class="modal-meta-tag" v-for="tag in selectedSkill.tags" :key="tag">{{ tag }}</span>
              <span class="modal-meta-path">{{ selectedSkill.source_path }}</span>
            </div>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- Info Card -->
    <div class="info-card glass-card animate__animated animate__fadeInUp" style="animation-delay: 0.3s">
      <h3>关于技能系统</h3>
      <div class="info-content">
        <div class="info-item">
          <span class="info-icon">·</span>
          <div>
            <strong>按需加载</strong>
            <p>主攻手 AI 可根据分析需要动态加载技能，不会一次性占用上下文</p>
          </div>
        </div>
        <div class="info-item">
          <span class="info-icon">--</span>
          <div>
            <strong>自动积累</strong>
            <p>每次分析完成后，AI 会自动总结经验，生成新的技能模块</p>
          </div>
        </div>
        <div class="info-item">
          <span class="info-icon">--</span>
          <div>
            <strong>可扩展</strong>
            <p>你可以在技能目录中手动添加 Markdown 格式的技能文件</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.skills-page {
  display: flex;
  flex-direction: column;
  gap: 20px;
  max-width: 1000px;
  margin: 0 auto;
}

.page-header { text-align: center; padding: 10px 0; }
.page-title {
  font-size: 24px;
  font-weight: 700;
  background: linear-gradient(135deg, var(--primary-light), var(--accent-cyan));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
}
.title-icon { font-size: 28px; -webkit-text-fill-color: initial; }
.page-subtitle { font-size: 13px; color: var(--text-muted); margin-top: 4px; }

/* Category Tabs */
.category-tabs {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  padding: 6px;
  background: var(--bg-card);
  border-radius: var(--radius);
  border: 1px solid var(--border);
}

.cat-btn {
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 7px 14px;
  border: none;
  background: transparent;
  color: var(--text-secondary);
  border-radius: var(--radius-sm);
  cursor: pointer;
  font-family: var(--font-sans);
  font-size: 12px;
  transition: all 0.25s ease;
}

.cat-btn:hover { background: var(--primary-glow); }
.cat-btn.active {
  background: var(--primary-glow);
  color: var(--primary);
}

.search-bar { padding: 12px; }

.loading-state {
  text-align: center;
  padding: 60px;
  color: var(--text-muted);
}

.spinner-lg {
  width: 32px;
  height: 32px;
  border: 3px solid var(--border);
  border-top-color: var(--primary);
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto 12px;
}

.empty-state {
  text-align: center;
  padding: 60px 20px;
}
.empty-icon { font-size: 40px; display: block; margin-bottom: 12px; }
.empty-state h3 { font-size: 16px; margin-bottom: 6px; }
.empty-state p { color: var(--text-muted); font-size: 13px; }

/* Skills Grid */
.skills-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 14px;
}

.skill-card {
  display: flex;
  gap: 14px;
  align-items: flex-start;
  position: relative;
  cursor: pointer;
  transition: all 0.25s ease;
}

.skill-card:hover {
  border-color: var(--border-active);
}

.skill-card.is-loading {
  opacity: 0.6;
  pointer-events: none;
}

.skill-info {
  flex: 1;
  min-width: 0;
}

.skill-info h3 {
  font-size: 14px;
  margin-bottom: 4px;
  color: var(--text-primary);
}

.skill-info p {
  font-size: 12px;
  color: var(--text-muted);
  line-height: 1.5;
  margin-bottom: 8px;
}

.skill-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.skill-tag {
  padding: 2px 8px;
  background: var(--primary-glow);
  border: 1px solid var(--border);
  border-radius: 10px;
  font-size: 10px;
  color: var(--text-muted);
}

.skill-meta {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 4px;
  flex-shrink: 0;
}

.btn-delete-skill {
  width: 22px;
  height: 22px;
  border: none;
  background: transparent;
  color: var(--text-muted);
  border-radius: 4px;
  font-size: 16px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  opacity: 0;
  transition: all 0.2s ease;
}

.skill-card:hover .btn-delete-skill {
  opacity: 0.6;
}

.btn-delete-skill:hover {
  opacity: 1 !important;
  background: rgba(251, 113, 133, 0.15);
  color: var(--accent-red);
}

.btn-delete-skill:disabled {
  opacity: 0.3;
  cursor: not-allowed;
}

.skill-id {
  font-size: 9px;
  color: var(--text-muted);
  font-family: var(--font-mono);
  opacity: 0.5;
}

.skill-view-hint {
  font-size: 10px;
  color: var(--primary-light);
  opacity: 0;
  transition: opacity 0.2s ease;
}

.skill-card:hover .skill-view-hint {
  opacity: 1;
}

/* Modal */
.modal-overlay {
  position: fixed;
  inset: 0;
  z-index: 100;
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(4px);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 40px;
}

.modal-content {
  background: var(--bg-dark);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  width: 100%;
  max-width: 800px;
  max-height: 80vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding: 24px 24px 16px;
  border-bottom: 1px solid var(--border);
}

.modal-header h2 {
  font-size: 18px;
  color: var(--text-primary);
}

.modal-desc {
  font-size: 12px;
  color: var(--text-muted);
  margin-top: 4px;
}

.modal-close {
  width: 32px;
  height: 32px;
  border: none;
  background: rgba(255, 255, 255, 0.05);
  color: var(--text-muted);
  border-radius: 8px;
  font-size: 20px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s ease;
  flex-shrink: 0;
}

.modal-close:hover {
  background: rgba(255, 255, 255, 0.1);
  color: var(--text-primary);
}

.modal-body {
  padding: 20px 24px 24px;
  overflow-y: auto;
  flex: 1;
}

.modal-section {
  margin-bottom: 20px;
}

.modal-section:last-child {
  margin-bottom: 0;
}

.modal-section h4 {
  font-size: 13px;
  color: var(--primary-light);
  margin-bottom: 10px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.skill-content-text {
  font-size: 13px;
  color: var(--text-secondary);
  line-height: 1.7;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: var(--font-sans);
  background: var(--bg-input);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 16px;
  max-height: 400px;
  overflow-y: auto;
}

.ref-block {
  margin-bottom: 12px;
}

.ref-block h5 {
  font-size: 12px;
  color: var(--accent-cyan);
  margin-bottom: 6px;
}

.ref-text {
  max-height: 200px;
}

.script-path {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--text-muted);
  padding: 6px 10px;
  background: var(--bg-input);
  border-radius: var(--radius-sm);
  margin-bottom: 4px;
  word-break: break-all;
}

.modal-meta-row {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
  padding-top: 12px;
  border-top: 1px solid var(--border);
}

.modal-meta-tag {
  padding: 2px 10px;
  background: var(--primary-glow);
  border: 1px solid var(--border);
  border-radius: 10px;
  font-size: 11px;
  color: var(--text-muted);
}

.modal-meta-path {
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--text-muted);
  opacity: 0.5;
  margin-left: auto;
  word-break: break-all;
}

/* Info Card */
.info-card {
  padding: 24px;
}

.info-card h3 {
  font-size: 15px;
  margin-bottom: 16px;
}

.info-content {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
}

.info-item {
  display: flex;
  gap: 10px;
}

.info-icon {
  font-size: 24px;
  flex-shrink: 0;
}

.info-item strong {
  display: block;
  font-size: 13px;
  margin-bottom: 4px;
}

.info-item p {
  font-size: 12px;
  color: var(--text-muted);
  line-height: 1.5;
}

@keyframes spin { to { transform: rotate(360deg); } }

@media (max-width: 700px) {
  .info-content { grid-template-columns: 1fr; }
}
</style>
