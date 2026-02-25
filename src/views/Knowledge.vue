<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { invoke } from '@tauri-apps/api/core'

interface KnowledgeEntry {
  id: string
  title: string
  device_type: string
  firmware_info: string
  vulnerabilities_found: string[]
  techniques_used: string[]
  lessons_learned: string
  created_at: string
}

const entries = ref<KnowledgeEntry[]>([])
const loading = ref(true)
const selectedEntry = ref<KnowledgeEntry | null>(null)
const searchQuery = ref('')
const deletingId = ref('')

onMounted(async () => {
  try {
    const raw = await invoke<string>('get_knowledge')
    entries.value = JSON.parse(raw)
  } catch (e) {
    console.warn('Failed to load knowledge base:', e)
  } finally {
    loading.value = false
  }
})

function selectEntry(entry: KnowledgeEntry) {
  selectedEntry.value = selectedEntry.value?.id === entry.id ? null : entry
}

async function deleteEntry(id: string) {
  if (!confirm('确定要删除这条知识？删除后不可恢复。')) return
  deletingId.value = id
  try {
    await invoke<string>('delete_knowledge', { id })
    entries.value = entries.value.filter(e => e.id !== id)
    if (selectedEntry.value?.id === id) {
      selectedEntry.value = null
    }
  } catch (e) {
    console.warn('Failed to delete knowledge entry:', e)
  } finally {
    deletingId.value = ''
  }
}

const filteredEntries = () => {
  const q = searchQuery.value.toLowerCase()
  if (!q) return entries.value
  return entries.value.filter(e =>
    e.title.toLowerCase().includes(q) ||
    e.device_type.toLowerCase().includes(q) ||
    e.techniques_used.some(t => t.toLowerCase().includes(q))
  )
}
</script>

<template>
  <div class="knowledge-page">
    <div class="page-header animate__animated animate__fadeInDown">
      <h1 class="page-title">
        知识库
      </h1>
      <p class="page-subtitle">自动积累的分析经验和漏洞知识</p>
    </div>

    <div class="search-bar glass-card animate__animated animate__fadeInUp">
      <input v-model="searchQuery" class="input" placeholder="搜索知识条目..." />
    </div>

    <div class="content-area">
      <div v-if="loading" class="loading-state">
        <div class="spinner-lg"></div>
        <p>加载知识库...</p>
      </div>

      <div v-else-if="filteredEntries().length === 0" class="empty-state animate__animated animate__fadeIn">
        <span class="empty-icon">—</span>
        <h3>知识库为空</h3>
        <p>完成固件分析后，分析结果会自动保存到知识库中</p>
        <p class="empty-hint">每次分析完成后，AI 会总结经验并存储，供后续分析参考</p>
      </div>

      <div v-else class="entries-grid">
        <div
          v-for="entry in filteredEntries()"
          :key="entry.id"
          :class="['entry-card', 'glass-card', { expanded: selectedEntry?.id === entry.id }]"
          @click="selectEntry(entry)"
        >
          <div class="entry-header">
            <h3>{{ entry.title }}</h3>
            <div class="entry-actions">
              <span class="entry-date">{{ new Date(entry.created_at).toLocaleDateString() }}</span>
              <button
                class="btn-delete"
                @click.stop="deleteEntry(entry.id)"
                :disabled="deletingId === entry.id"
                title="删除此条目"
              >{{ deletingId === entry.id ? '...' : '×' }}</button>
            </div>
          </div>
          <div class="entry-meta">
            <span class="meta-tag">{{ entry.device_type }}</span>
            <span class="meta-tag" v-for="v in entry.vulnerabilities_found" :key="v">{{ v }}</span>
          </div>
          <div class="entry-techniques">
            <span v-for="t in entry.techniques_used" :key="t" class="tech-tag">{{ t }}</span>
          </div>

          <div v-if="selectedEntry?.id === entry.id" class="entry-detail">
            <h4>固件信息</h4>
            <pre class="code-block">{{ entry.firmware_info }}</pre>
            <h4>经验总结</h4>
            <pre class="lessons-text">{{ entry.lessons_learned }}</pre>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.knowledge-page {
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
  padding: 80px 20px;
}
.empty-icon { font-size: 48px; display: block; margin-bottom: 16px; }
.empty-state h3 { font-size: 18px; margin-bottom: 8px; }
.empty-state p { color: var(--text-muted); font-size: 14px; }
.empty-hint { font-size: 12px; opacity: 0.6; margin-top: 8px; }

.entries-grid {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.entry-card {
  cursor: pointer;
  transition: all 0.3s ease;
}

.entry-card.expanded {
  border-color: var(--primary);
}

.entry-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
}

.entry-header h3 { font-size: 15px; flex: 1; min-width: 0; }

.entry-actions {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-shrink: 0;
}

.entry-date { font-size: 11px; color: var(--text-muted); }

.btn-delete {
  width: 24px;
  height: 24px;
  border: none;
  background: rgba(239, 68, 68, 0.1);
  color: rgba(239, 68, 68, 0.6);
  border-radius: 6px;
  cursor: pointer;
  font-size: 14px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s ease;
  opacity: 0;
}

.entry-card:hover .btn-delete {
  opacity: 1;
}

.btn-delete:hover {
  background: rgba(239, 68, 68, 0.2);
  color: #ef4444;
}

.btn-delete:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.entry-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 8px;
}

.meta-tag {
  font-size: 12px;
  color: var(--text-secondary);
}

.entry-techniques {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.tech-tag {
  padding: 2px 10px;
  background: rgba(129, 140, 248, 0.1);
  border: 1px solid rgba(129, 140, 248, 0.2);
  border-radius: 12px;
  font-size: 11px;
  color: var(--accent-blue);
}

.entry-detail {
  margin-top: 16px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
  animation: slide-up 0.3s ease;
}

.entry-detail h4 {
  font-size: 13px;
  color: var(--primary-light);
  margin-bottom: 8px;
  margin-top: 12px;
}

.entry-detail h4:first-child { margin-top: 0; }

.lessons-text {
  font-size: 13px;
  color: var(--text-secondary);
  line-height: 1.7;
  white-space: pre-wrap;
  font-family: var(--font-sans);
}

@keyframes spin { to { transform: rotate(360deg); } }
</style>
