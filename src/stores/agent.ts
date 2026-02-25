import { defineStore } from 'pinia'
import { ref, reactive, computed } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'

export interface AgentConfig {
  api_key: string
  api_base_url: string
  model: string
  max_retries: number
  advisor_model: string
  ssh_config: SshConfig | null
  ghidra_path: string
  local_download_path: string
  report_export_path: string
  background_image: string
  background_opacity: number
  api_timeout_secs: number
  summarize_threshold: number
  advisor_check_interval: number
}

export interface SshConfig {
  host: string
  port: number
  username: string
  auth: { type: 'Password'; password: string } | { type: 'Key'; private_key_path: string; passphrase: string | null }
}

export interface Finding {
  id: string
  severity: string
  title: string
  description: string
  location: string
  poc: string | null
  cwe: string | null
  discovered_at: string
}

export interface AgentEvent {
  type: string
  [key: string]: any
}

export interface LogEntry {
  timestamp: string
  level: string
  message: string
  type: string
  details?: any
}

export const useAgentStore = defineStore('agent', () => {
  // ── 状态 ──
  const config = reactive<AgentConfig>({
    api_key: '',
    api_base_url: 'https://api.siliconflow.cn/v1',
    model: '',
    max_retries: 15,
    advisor_model: '',
    ssh_config: null,
    ghidra_path: '',
    local_download_path: '',
    report_export_path: '',
    background_image: '',
    background_opacity: 0.3,
    api_timeout_secs: 120,
    summarize_threshold: 16,
    advisor_check_interval: 5,
  })

  const isInitialized = ref(false)
  const isRunning = ref(false)
  const sessionState = ref('idle')
  const logs = ref<LogEntry[]>([])
  const findings = ref<Finding[]>([])
  const progress = reactive({ attempt: 0, maxAttempts: 15, consecutiveFailures: 0 })
  const advisorMessages = ref<{ trigger: string; message: string }[]>([])
  const firmwarePath = ref('')
  const targetDescription = ref('')
  const backgroundDataUrl = ref('')
  const theme = ref<'dark' | 'light'>((localStorage.getItem('theme') as 'dark' | 'light') || 'dark')

  // Apply theme on init
  document.documentElement.setAttribute('data-theme', theme.value)

  function toggleTheme() {
    theme.value = theme.value === 'dark' ? 'light' : 'dark'
    document.documentElement.setAttribute('data-theme', theme.value)
    localStorage.setItem('theme', theme.value)
  }

  // ── 计算属性 ──
  const isConfigured = computed(() => config.api_key.length > 0)
  const progressPercent = computed(() =>
    progress.maxAttempts > 0 ? (progress.attempt / progress.maxAttempts) * 100 : 0
  )

  // ── 操作 ──
  async function loadConfig() {
    try {
      const raw = await invoke<string>('load_config')
      const loaded = JSON.parse(raw) as AgentConfig
      Object.assign(config, loaded)
      // 加载背景图
      if (config.background_image) {
        await loadBackgroundImage(config.background_image)
      }
    } catch (e) {
      console.warn('Failed to load config:', e)
    }
  }

  async function saveConfig() {
    await invoke('save_config', { config: { ...config } })
  }

  async function initAgent() {
    await invoke<string>('init_agent', { config: { ...config } })
    isInitialized.value = true
  }

  async function startAnalysis() {
    if (!firmwarePath.value) throw new Error('请指定固件路径')
    isRunning.value = true
    logs.value = []
    findings.value = []
    advisorMessages.value = []
    progress.attempt = 0
    progress.consecutiveFailures = 0

    try {
      const result = await invoke<string>('start_analysis', {
        config: { ...config },
        firmwarePath: firmwarePath.value,
        targetDescription: targetDescription.value || '嵌入式设备固件',
      })
      const founds = JSON.parse(result) as Finding[]
      findings.value = founds
    } finally {
      isRunning.value = false
    }
  }

  async function stopAnalysis() {
    try {
      await invoke<string>('stop_analysis')
      addLog({
        timestamp: new Date().toISOString(),
        level: 'warn',
        message: '正在停止分析...',
        type: 'log'
      })
    } catch (e: any) {
      console.warn('Stop failed:', e)
    }
  }

  async function exportReport(exportPath: string) {
    const result = await invoke<string>('export_report', {
      exportPath,
      firmwarePath: firmwarePath.value,
      targetDescription: targetDescription.value || '嵌入式设备固件',
      findings: findings.value.map(f => ({ ...f })),
      logs: logs.value.map(l => ({ ...l })),
      advisorMessages: advisorMessages.value.map(m => ({ ...m })),
    })
    return JSON.parse(result)
  }

  async function testSsh() {
    if (!config.ssh_config) throw new Error('未配置 SSH')
    const result = await invoke<string>('test_ssh', { config: config.ssh_config })
    return JSON.parse(result)
  }

  async function testModelApi(apiKey: string, apiBaseUrl: string, model: string) {
    const result = await invoke<string>('test_model_api', { apiKey, apiBaseUrl, model })
    return JSON.parse(result)
  }

  async function loadBackgroundImage(path: string) {
    if (!path) {
      backgroundDataUrl.value = ''
      return
    }
    try {
      const dataUrl = await invoke<string>('read_image_base64', { path })
      backgroundDataUrl.value = dataUrl
    } catch (e) {
      console.warn('Failed to load background image:', e)
      backgroundDataUrl.value = ''
    }
  }

  function addLog(entry: LogEntry) {
    logs.value.push(entry)
    // 保持最近 500 条
    if (logs.value.length > 500) {
      logs.value = logs.value.slice(-500)
    }
  }

  // ── 事件监听 ──
  async function setupEventListener() {
    await listen<AgentEvent>('agent-event', (event) => {
      const ev = event.payload
      const timestamp = new Date().toISOString()

      switch (ev.type) {
        case 'log':
          addLog({ timestamp: ev.timestamp || timestamp, level: ev.level, message: ev.message, type: 'log' })
          break
        case 'state_change':
          sessionState.value = typeof ev.state === 'string' ? ev.state : JSON.stringify(ev.state)
          addLog({ timestamp, level: 'info', message: `状态变更: ${sessionState.value}`, type: 'state' })
          break
        case 'tool_call':
          addLog({ timestamp, level: 'info', message: `调用工具: ${ev.tool}`, type: 'tool_call', details: ev.args_preview })
          break
        case 'tool_result':
          addLog({
            timestamp, level: ev.is_error ? 'error' : 'info',
            message: `${ev.is_error ? '[ERR]' : '[OK]'} ${ev.tool} 结果`, type: 'tool_result',
            details: ev.result_preview
          })
          break
        case 'advisor_message':
          advisorMessages.value.push({ trigger: ev.trigger, message: ev.message })
          addLog({ timestamp, level: 'info', message: `顾问建议 (${ev.trigger})`, type: 'advisor', details: ev.message })
          break
        case 'finding':
          findings.value.push(ev.finding)
          addLog({ timestamp, level: 'info', message: `发现漏洞: ${ev.finding.title}`, type: 'finding' })
          break
        case 'progress':
          progress.attempt = ev.attempt
          progress.maxAttempts = ev.max_attempts
          progress.consecutiveFailures = ev.consecutive_failures
          break
        case 'complete':
          isRunning.value = false
          addLog({ timestamp, level: ev.success ? 'info' : 'warn', message: ev.message, type: 'complete' })
          break
        case 'heartbeat':
          sessionState.value = `${ev.phase} (${ev.elapsed_secs}s)`
          break
      }
    })
  }

  return {
    config, isInitialized, isRunning, sessionState,
    logs, findings, progress, advisorMessages,
    firmwarePath, targetDescription, backgroundDataUrl,
    theme,
    isConfigured, progressPercent,
    loadConfig, saveConfig, initAgent, startAnalysis, stopAnalysis, exportReport,
    testSsh, testModelApi, loadBackgroundImage, setupEventListener, addLog, toggleTheme,
  }
})
