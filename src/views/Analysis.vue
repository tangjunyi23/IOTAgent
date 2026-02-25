<script setup lang="ts">
import { ref, computed, nextTick, watch } from 'vue'
import { useAgentStore } from '../stores/agent'
import { open } from '@tauri-apps/plugin-dialog'

const store = useAgentStore()
const logContainer = ref<HTMLDivElement>()
const activeTab = ref<'logs' | 'advisor' | 'findings'>('logs')
const isDragOver = ref(false)
const isExporting = ref(false)
const exportResult = ref<{ path: string; filename: string } | null>(null)

// Auto-scroll logs
watch(() => store.logs.length, async () => {
  await nextTick()
  if (logContainer.value) {
    logContainer.value.scrollTop = logContainer.value.scrollHeight
  }
})

async function handleStart() {
  try {
    if (!store.isInitialized) {
      await store.initAgent()
    }
    await store.startAnalysis()
  } catch (e: any) {
    store.addLog({
      timestamp: new Date().toISOString(),
      level: 'error',
      message: `启动失败: ${e.message || e}`,
      type: 'error'
    })
  }
}

async function selectFirmware() {
  const selected = await open({
    multiple: false,
    title: '选择固件文件',
    filters: [
      { name: '固件文件', extensions: ['bin', 'img', 'fw', 'hex', 'trx', 'chk', 'dlf', 'rbi'] },
      { name: '所有文件', extensions: ['*'] }
    ]
  })
  if (selected) {
    store.firmwarePath = selected as string
  }
}

function onDragOver(e: DragEvent) {
  e.preventDefault()
  isDragOver.value = true
}

function onDragLeave() {
  isDragOver.value = false
}

function onDrop(e: DragEvent) {
  e.preventDefault()
  isDragOver.value = false
  if (e.dataTransfer?.files?.length) {
    // Tauri 中拖放文件会给出完整路径
    const file = e.dataTransfer.files[0]
    // 在 Tauri 中，file.path 包含完整路径；如果没有则用 name
    const filePath = (file as any).path || file.name
    store.firmwarePath = filePath
  }
}

async function handleExportReport() {
  isExporting.value = true
  exportResult.value = null
  try {
    let exportPath = store.config.report_export_path
    // 如果未配置导出路径，弹出文件夹选择对话框
    if (!exportPath) {
      const selected = await open({
        directory: true,
        multiple: false,
        title: '选择报告导出目录',
      })
      if (!selected) {
        isExporting.value = false
        return
      }
      exportPath = selected as string
    }
    const result = await store.exportReport(exportPath)
    exportResult.value = { path: result.path, filename: result.filename }
    store.addLog({
      timestamp: new Date().toISOString(),
      level: 'info',
      message: `报告已导出: ${result.path}`,
      type: 'log'
    })
    setTimeout(() => exportResult.value = null, 8000)
  } catch (e: any) {
    store.addLog({
      timestamp: new Date().toISOString(),
      level: 'error',
      message: `导出报告失败: ${e.message || e}`,
      type: 'error'
    })
  } finally {
    isExporting.value = false
  }
}

function getLogIcon(type: string) {
  switch (type) {
    case 'tool_call': return '▶'
    case 'tool_result': return '◀'
    case 'advisor': return '◆'
    case 'finding': return '●'
    case 'state': return '○'
    case 'complete': return '✓'
    default: return '·'
  }
}

function getSeverityClass(severity: string) {
  return 'badge-' + severity.toLowerCase()
}

const filteredLogs = computed(() => {
  return store.logs
})
</script>

<template>
  <div class="analysis-page">
    <!-- Header -->
    <div class="page-header animate__animated animate__fadeInDown">
      <h1 class="page-title">
        固件漏洞分析
      </h1>
    </div>

    <!-- Config Panel -->
    <div class="config-panel glass-card animate__animated animate__fadeInUp">
      <!-- Firmware Drop Zone -->
      <div
        class="firmware-drop-zone"
        :class="{ 'drag-over': isDragOver, 'has-file': store.firmwarePath }"
        @dragover="onDragOver"
        @dragleave="onDragLeave"
        @drop="onDrop"
        @click="!store.isRunning && selectFirmware()"
        v-if="!store.isRunning || !store.firmwarePath"
      >
        <div v-if="!store.firmwarePath" class="drop-placeholder">
          <span class="drop-icon"></span>
          <p class="drop-text">拖入固件文件 或 <span class="drop-link">点击选择</span></p>
          <p class="drop-hint">支持 .bin .img .fw .hex .trx 等格式</p>
        </div>
        <div v-else class="drop-selected">
          <span class="file-icon"></span>
          <span class="file-path">{{ store.firmwarePath }}</span>
          <button class="btn-clear" @click.stop="store.firmwarePath = ''" title="清除" v-if="!store.isRunning">✕</button>
        </div>
      </div>
      <div v-else class="firmware-info">
        <span class="file-icon"></span>
        <span class="file-path">{{ store.firmwarePath }}</span>
      </div>

      <div class="config-row">
        <div class="config-field">
          <label>目标描述</label>
          <input
            v-model="store.targetDescription"
            class="input"
            placeholder="例如: TP-Link TL-WR841N 路由器固件"
            :disabled="store.isRunning"
          />
        </div>
        <div class="config-action">
          <button
            v-if="!store.isRunning"
            class="btn btn-primary start-btn"
            @click="handleStart"
            :disabled="!store.isConfigured || !store.firmwarePath"
          >
            <span></span>
            开始分析
          </button>
          <button
            v-else
            class="btn btn-danger stop-btn"
            @click="store.stopAnalysis()"
          >
            <span></span>
            停止分析
          </button>
        </div>
      </div>
    </div>

    <!-- Progress Bar -->
    <div class="progress-section glass-card" v-if="store.isRunning || store.progress.attempt > 0">
      <div class="progress-info">
        <span>尝试 {{ store.progress.attempt }} / {{ store.progress.maxAttempts }}</span>
        <span v-if="store.progress.consecutiveFailures > 0" class="failure-count">
          连续失败: {{ store.progress.consecutiveFailures }}
        </span>
        <span class="state-badge">{{ store.sessionState }}</span>
      </div>
      <div class="progress-bar">
        <div
          class="progress-fill"
          :style="{ width: store.progressPercent + '%' }"
          :class="{ 'progress-danger': store.progress.consecutiveFailures >= 3 }"
        ></div>
      </div>
    </div>

    <!-- Tab Controls -->
    <div class="tab-controls">
      <button
        :class="['tab-btn', { active: activeTab === 'logs' }]"
        @click="activeTab = 'logs'"
      >
        运行日志
        <span class="tab-count" v-if="store.logs.length">{{ store.logs.length }}</span>
      </button>
      <button
        :class="['tab-btn', { active: activeTab === 'advisor' }]"
        @click="activeTab = 'advisor'"
      >
        顾问建议
        <span class="tab-count" v-if="store.advisorMessages.length">{{ store.advisorMessages.length }}</span>
      </button>
      <button
        :class="['tab-btn', { active: activeTab === 'findings' }]"
        @click="activeTab = 'findings'"
      >
        漏洞发现
        <span class="tab-count" v-if="store.findings.length">{{ store.findings.length }}</span>
      </button>
      <button
        v-if="(store.logs.length > 0 || store.findings.length > 0) && !store.isRunning"
        class="tab-btn export-tab-btn"
        @click="handleExportReport"
        :disabled="isExporting"
      >
        <span v-if="isExporting" class="spinner"></span>
        {{ isExporting ? '导出中...' : '导出报告' }}
      </button>
    </div>

    <!-- Export Result Toast -->
    <div v-if="exportResult" class="export-toast animate__animated animate__fadeInDown">
      <span class="export-toast-icon">✓</span>
      <span class="export-toast-text">报告已导出: {{ exportResult.filename }}</span>
      <span class="export-toast-path">{{ exportResult.path }}</span>
    </div>

    <!-- Tab Content -->
    <div class="tab-content glass-card">
      <!-- Logs Tab -->
      <div v-if="activeTab === 'logs'" ref="logContainer" class="log-scroll">
        <div v-if="filteredLogs.length === 0" class="empty-state">
          <span class="empty-icon">—</span>
          <p>等待分析启动...</p>
        </div>
        <div v-for="(log, i) in filteredLogs" :key="i" class="log-entry" :class="'log-level-' + log.level">
          <div class="log-header">
            <span class="log-icon">{{ getLogIcon(log.type) }}</span>
            <span class="log-time">{{ new Date(log.timestamp).toLocaleTimeString() }}</span>
            <span class="log-badge" :class="'badge-' + log.level">{{ log.level }}</span>
          </div>
          <div class="log-body">{{ log.message }}</div>
          <div v-if="log.details" class="log-details">
            <pre class="code-block">{{ typeof log.details === 'string' ? log.details : JSON.stringify(log.details, null, 2) }}</pre>
          </div>
        </div>
      </div>

      <!-- Advisor Tab -->
      <div v-if="activeTab === 'advisor'" class="advisor-scroll">
        <div v-if="store.advisorMessages.length === 0" class="empty-state">
          <span class="empty-icon">—</span>
          <p>顾问尚未介入</p>
        </div>
        <div v-for="(msg, i) in store.advisorMessages" :key="i" class="advisor-card">
          <div class="advisor-header">
            <span class="advisor-icon">◆</span>
            <span class="advisor-trigger">{{ msg.trigger }}</span>
          </div>
          <div class="advisor-body">
            <pre class="advisor-text">{{ msg.message }}</pre>
          </div>
        </div>
      </div>

      <!-- Findings Tab -->
      <div v-if="activeTab === 'findings'" class="findings-scroll">
        <div v-if="store.findings.length === 0" class="empty-state">
          <span class="empty-icon">—</span>
          <p>尚未发现漏洞</p>
        </div>
        <div v-for="f in store.findings" :key="f.id" class="finding-card">
          <div class="finding-header">
            <span class="badge" :class="getSeverityClass(f.severity)">{{ f.severity }}</span>
            <h3>{{ f.title }}</h3>
            <span v-if="f.cwe" class="cwe-tag">{{ f.cwe }}</span>
          </div>
          <div class="finding-location" v-if="f.location">{{ f.location }}</div>
          <div class="finding-desc">{{ f.description }}</div>
          <div v-if="f.poc" class="finding-poc">
            <h4>PoC</h4>
            <pre class="code-block">{{ f.poc }}</pre>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.analysis-page {
  display: flex;
  flex-direction: column;
  gap: 16px;
  max-width: 1100px;
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
.title-icon {
  display: none;
}

/* Firmware Drop Zone */
.firmware-drop-zone {
  border: 2px dashed rgba(99, 102, 241, 0.35);
  border-radius: 12px;
  padding: 28px 20px;
  text-align: center;
  cursor: pointer;
  transition: all 0.25s ease;
  margin-bottom: 16px;
  background: rgba(99, 102, 241, 0.04);
}
.firmware-drop-zone:hover {
  border-color: rgba(99, 102, 241, 0.6);
  background: rgba(99, 102, 241, 0.08);
}
.firmware-drop-zone.drag-over {
  border-color: var(--primary);
  background: rgba(99, 102, 241, 0.14);
  box-shadow: 0 0 20px rgba(99, 102, 241, 0.15);
  transform: scale(1.01);
}
.firmware-drop-zone.has-file {
  padding: 14px 20px;
}
.drop-placeholder .drop-icon {
  font-size: 36px;
  display: block;
  margin-bottom: 8px;
}
.drop-placeholder .drop-text {
  color: var(--text-secondary);
  font-size: 14px;
  margin: 0 0 4px;
}
.drop-placeholder .drop-link {
  color: var(--primary);
  text-decoration: underline;
  cursor: pointer;
}
.drop-placeholder .drop-hint {
  color: var(--text-muted);
  font-size: 12px;
  margin: 0;
}
.drop-selected, .firmware-info {
  display: flex;
  align-items: center;
  gap: 10px;
}
.drop-selected .file-icon, .firmware-info .file-icon {
  font-size: 22px;
  flex-shrink: 0;
}
.drop-selected .file-path, .firmware-info .file-path {
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px;
  color: var(--text-primary);
  word-break: break-all;
  text-align: left;
  flex: 1;
}
.btn-clear {
  background: rgba(239, 68, 68, 0.15);
  border: none;
  color: #ef4444;
  width: 26px;
  height: 26px;
  border-radius: 50%;
  cursor: pointer;
  font-size: 14px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: background 0.2s;
  flex-shrink: 0;
}
.btn-clear:hover {
  background: rgba(239, 68, 68, 0.3);
}
.firmware-info {
  padding: 14px 20px;
  margin-bottom: 16px;
  background: rgba(99, 102, 241, 0.06);
  border-radius: 10px;
  border: 1px solid rgba(99, 102, 241, 0.15);
}

/* Config Panel */
.config-row {
  display: flex;
  gap: 16px;
  align-items: flex-end;
}

.config-field {
  flex: 1;
}

.config-field label {
  display: block;
  font-size: 12px;
  color: var(--text-muted);
  margin-bottom: 6px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.config-action {
  flex-shrink: 0;
}

.start-btn {
  height: 42px;
  padding: 0 28px;
  font-size: 14px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.stop-btn {
  height: 42px;
  padding: 0 28px;
  font-size: 14px;
  display: flex;
  align-items: center;
  gap: 8px;
  background: linear-gradient(135deg, #ef4444, #dc2626) !important;
  border-color: #ef4444 !important;
}
.stop-btn:hover {
  background: linear-gradient(135deg, #dc2626, #b91c1c) !important;
}

.spinner {
  width: 16px;
  height: 16px;
  border: 2px solid rgba(255,255,255,0.3);
  border-top-color: white;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

/* Progress */
.progress-section { padding: 14px 20px; }
.progress-info {
  display: flex;
  align-items: center;
  gap: 16px;
  font-size: 12px;
  color: var(--text-secondary);
  margin-bottom: 8px;
}

.failure-count {
  color: var(--accent-red);
  font-weight: 600;
}

.state-badge {
  margin-left: auto;
  padding: 2px 10px;
  background: var(--primary-glow);
  border-radius: 12px;
  font-size: 11px;
  color: var(--primary);
}

.progress-bar {
  height: 6px;
  background: var(--bg-input);
  border-radius: 3px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--primary), var(--accent-cyan));
  border-radius: 3px;
  transition: width 0.5s ease;
}

.progress-danger {
  background: linear-gradient(90deg, var(--accent-red), var(--accent-amber)) !important;
}

/* Tabs */
.tab-controls {
  display: flex;
  gap: 4px;
  background: var(--bg-card);
  border-radius: var(--radius);
  padding: 4px;
  border: 1px solid var(--border);
}

.tab-btn {
  flex: 1;
  padding: 10px 16px;
  border: none;
  background: transparent;
  color: var(--text-secondary);
  border-radius: var(--radius-sm);
  cursor: pointer;
  font-family: var(--font-sans);
  font-size: 13px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  transition: all 0.25s ease;
}

.tab-btn:hover { background: var(--primary-glow); }
.tab-btn.active {
  background: var(--primary-glow);
  color: var(--primary);
}

.tab-count {
  background: var(--primary-dark);
  color: white;
  padding: 1px 7px;
  border-radius: 10px;
  font-size: 10px;
  font-weight: 600;
}

/* Tab Content */
.tab-content {
  min-height: 400px;
  max-height: 60vh;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.log-scroll, .advisor-scroll, .findings-scroll {
  overflow-y: auto;
  flex: 1;
  padding: 4px;
}

/* Log Entries */
.log-entry {
  padding: 10px 14px;
  margin-bottom: 6px;
  background: var(--bg-input);
  border-radius: var(--radius-sm);
  border-left: 3px solid var(--border);
  animation: slide-up 0.3s ease-out;
}

.log-entry.log-level-error { border-left-color: var(--accent-red); }
.log-entry.log-level-warn { border-left-color: var(--accent-amber); }
.log-entry.log-level-info { border-left-color: var(--accent-cyan); }

.log-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 4px;
}

.log-icon { font-size: 14px; }
.log-time { font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); }
.log-badge {
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 9px;
  font-weight: 600;
  text-transform: uppercase;
}
.badge-info { background: rgba(59, 130, 246, 0.2); color: #93c5fd; }
.badge-warn { background: rgba(234, 179, 8, 0.2); color: #fde047; }
.badge-error { background: rgba(239, 68, 68, 0.2); color: #fca5a5; }

.log-body {
  font-size: 13px;
  color: var(--text-primary);
  line-height: 1.5;
}

.log-details {
  margin-top: 8px;
}

.log-details .code-block {
  font-size: 11px;
  max-height: 200px;
  overflow-y: auto;
}

/* Advisor Cards */
.advisor-card {
  background: var(--bg-input);
  border: 1px solid rgba(251, 191, 36, 0.2);
  border-radius: var(--radius);
  padding: 16px;
  margin-bottom: 12px;
}

.advisor-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}

.advisor-icon { font-size: 20px; }
.advisor-trigger {
  font-size: 12px;
  color: var(--accent-amber);
  font-weight: 600;
  padding: 2px 10px;
  background: rgba(251, 191, 36, 0.1);
  border-radius: 12px;
}

.advisor-text {
  font-size: 13px;
  color: var(--text-secondary);
  line-height: 1.7;
  white-space: pre-wrap;
  font-family: var(--font-sans);
}

/* Finding Cards */
.finding-card {
  background: var(--bg-input);
  border: 1px solid var(--border-active);
  border-radius: var(--radius);
  padding: 18px;
  margin-bottom: 12px;
}

.finding-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 10px;
}

.finding-header h3 {
  font-size: 16px;
  flex: 1;
}

.cwe-tag {
  font-size: 11px;
  color: var(--accent-blue);
  padding: 2px 8px;
  background: rgba(129, 140, 248, 0.1);
  border-radius: 8px;
}

.finding-location {
  font-size: 12px;
  color: var(--text-muted);
  margin-bottom: 8px;
  font-family: var(--font-mono);
}

.finding-desc {
  font-size: 13px;
  color: var(--text-secondary);
  line-height: 1.6;
  margin-bottom: 12px;
}

.finding-poc h4 {
  font-size: 13px;
  color: var(--accent-green);
  margin-bottom: 8px;
}

/* Empty State */
.empty-state {
  text-align: center;
  padding: 60px 20px;
  color: var(--text-muted);
}
.empty-icon { font-size: 40px; display: block; margin-bottom: 12px; }
.empty-hint { font-size: 12px; margin-top: 6px; opacity: 0.6; }

/* Export Button */
.export-tab-btn {
  background: rgba(34, 197, 94, 0.1) !important;
  border: 1px solid rgba(34, 197, 94, 0.3) !important;
  color: #22c55e !important;
  flex: 0 0 auto !important;
  padding: 8px 16px !important;
  font-weight: 600;
  transition: all 0.25s ease;
}
.export-tab-btn:hover:not(:disabled) {
  background: rgba(34, 197, 94, 0.2) !important;
  border-color: rgba(34, 197, 94, 0.5) !important;
}
.export-tab-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

/* Export Toast */
.export-toast {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 18px;
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid rgba(34, 197, 94, 0.3);
  border-radius: var(--radius);
  flex-wrap: wrap;
}
.export-toast-icon { font-size: 18px; }
.export-toast-text {
  font-size: 13px;
  color: #22c55e;
  font-weight: 600;
}
.export-toast-path {
  font-size: 11px;
  color: var(--text-muted);
  font-family: var(--font-mono);
  word-break: break-all;
  width: 100%;
  padding-left: 28px;
}
</style>
