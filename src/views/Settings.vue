<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useAgentStore } from '../stores/agent'
import { open } from '@tauri-apps/plugin-dialog'

const store = useAgentStore()
const sshTestResult = ref<{ connected: boolean; system_info: string } | null>(null)
const sshTesting = ref(false)
const saveStatus = ref('')
const apiTesting = ref(false)
const apiTestResult = ref<{ success: boolean; message: string } | null>(null)

// Local form state
const form = reactive({
  api_key: '',
  api_base_url: 'https://api.siliconflow.cn/v1',
  model: '',
  max_retries: 15,
  advisor_model: '',
  ssh_enabled: false,
  ssh_host: '',
  ssh_port: 22,
  ssh_username: 'root',
  ssh_auth_type: 'password' as 'password' | 'key',
  ssh_password: '',
  ssh_key_path: '',
  ssh_passphrase: '',
  ghidra_path: '',
  local_download_path: '',
  report_export_path: '',
  background_image: '',
  background_opacity: 0.3,
  api_timeout_secs: 120,
  summarize_threshold: 16,
  advisor_check_interval: 5,
})

onMounted(() => {
  // Load from store
  form.api_key = store.config.api_key
  form.api_base_url = store.config.api_base_url
  form.model = store.config.model
  form.max_retries = store.config.max_retries
  form.advisor_model = store.config.advisor_model
  form.ghidra_path = store.config.ghidra_path || ''
  form.local_download_path = store.config.local_download_path || ''
  form.report_export_path = store.config.report_export_path || ''
  form.background_image = store.config.background_image || ''
  form.background_opacity = store.config.background_opacity ?? 0.3
  form.api_timeout_secs = store.config.api_timeout_secs ?? 120
  form.summarize_threshold = store.config.summarize_threshold ?? 16
  form.advisor_check_interval = store.config.advisor_check_interval ?? 5
  if (store.config.ssh_config) {
    form.ssh_enabled = true
    form.ssh_host = store.config.ssh_config.host
    form.ssh_port = store.config.ssh_config.port
    form.ssh_username = store.config.ssh_config.username
    if (store.config.ssh_config.auth.type === 'Password') {
      form.ssh_auth_type = 'password'
      form.ssh_password = store.config.ssh_config.auth.password
    } else {
      form.ssh_auth_type = 'key'
      form.ssh_key_path = store.config.ssh_config.auth.private_key_path
      form.ssh_passphrase = store.config.ssh_config.auth.passphrase || ''
    }
  }
})

async function saveSettings() {
  store.config.api_key = form.api_key
  store.config.api_base_url = form.api_base_url
  store.config.model = form.model
  store.config.max_retries = form.max_retries
  store.config.advisor_model = form.advisor_model
  store.config.ghidra_path = form.ghidra_path
  store.config.local_download_path = form.local_download_path
  store.config.report_export_path = form.report_export_path
  store.config.background_image = form.background_image
  store.config.background_opacity = form.background_opacity
  store.config.api_timeout_secs = form.api_timeout_secs
  store.config.summarize_threshold = form.summarize_threshold
  store.config.advisor_check_interval = form.advisor_check_interval

  if (form.ssh_enabled) {
    store.config.ssh_config = {
      host: form.ssh_host,
      port: form.ssh_port,
      username: form.ssh_username,
      auth: form.ssh_auth_type === 'password'
        ? { type: 'Password', password: form.ssh_password }
        : { type: 'Key', private_key_path: form.ssh_key_path, passphrase: form.ssh_passphrase || null }
    }
  } else {
    store.config.ssh_config = null
  }

  await store.saveConfig()
  // Reload background if changed
  if (form.background_image) {
    await store.loadBackgroundImage(form.background_image)
  }
  saveStatus.value = '配置已保存'
  setTimeout(() => saveStatus.value = '', 3000)
}

async function browseReportExportPath() {
  const selected = await open({
    directory: true,
    multiple: false,
    title: '选择分析报告导出目录',
  })
  if (selected) {
    form.report_export_path = selected as string
  }
}

async function browseDownloadPath() {
  const selected = await open({
    directory: true,
    multiple: false,
    title: '选择文件下载保存目录',
  })
  if (selected) {
    form.local_download_path = selected as string
  }
}

async function browseGhidraPath() {
  const selected = await open({
    directory: true,
    multiple: false,
    title: '选择 Ghidra 安装目录',
  })
  if (selected) {
    form.ghidra_path = selected as string
  }
}

async function browseBackgroundImage() {
  const selected = await open({
    multiple: false,
    title: '选择背景图片',
    filters: [{ name: '图片文件', extensions: ['png', 'jpg', 'jpeg', 'webp', 'gif', 'bmp'] }],
  })
  if (selected) {
    form.background_image = selected as string
    // Preview immediately
    await store.loadBackgroundImage(form.background_image)
  }
}

function clearBackgroundImage() {
  form.background_image = ''
  store.backgroundDataUrl = ''
}

async function testSshConnection() {
  sshTesting.value = true
  sshTestResult.value = null
  try {
    const result = await store.testSsh()
    sshTestResult.value = result
  } catch (e: any) {
    sshTestResult.value = { connected: false, system_info: e.message || String(e) }
  } finally {
    sshTesting.value = false
  }
}

async function testApiConnection() {
  if (!form.api_key || !form.api_base_url || !form.model) {
    apiTestResult.value = { success: false, message: '请先填写 API Key、Base URL 和模型名称' }
    return
  }
  apiTesting.value = true
  apiTestResult.value = null
  try {
    const result = await store.testModelApi(form.api_key, form.api_base_url, form.model)
    apiTestResult.value = {
      success: true,
      message: `✅ 连接成功\n模型: ${result.model}\n回复: ${result.reply}\nTokens: ${result.input_tokens} in / ${result.output_tokens} out`
    }
  } catch (e: any) {
    apiTestResult.value = { success: false, message: `❌ ${e.message || String(e)}` }
  } finally {
    apiTesting.value = false
  }
}


</script>

<template>
  <div class="settings-page">
    <div class="page-header animate__animated animate__fadeInDown">
      <h1 class="page-title">
        系统设置
      </h1>
    </div>

    <!-- API Settings -->
    <div class="settings-section glass-card animate__animated animate__fadeInUp">
      <h2 class="section-title">API 配置</h2>
      <div class="form-grid">
        <div class="form-field">
          <label>API Key</label>
          <input v-model="form.api_key" type="password" class="input input-mono" placeholder="sk-ant-..." />
        </div>
        <div class="form-field">
          <label>API Base URL</label>
          <input v-model="form.api_base_url" class="input input-mono" placeholder="https://api.siliconflow.cn/v1" />
        </div>
        <div class="form-field">
          <label>主攻手模型</label>
          <input v-model="form.model" class="input input-mono" placeholder="请输入模型名称，如 deepseek-ai/DeepSeek-V3" />
        </div>
        <div class="form-field">
          <label>顾问模型</label>
          <input v-model="form.advisor_model" class="input input-mono" placeholder="请输入模型名称，如 deepseek-ai/DeepSeek-V3" />
        </div>
        <div class="form-field">
          <label>最大尝试次数</label>
          <input v-model.number="form.max_retries" type="number" class="input" min="1" max="50" />
        </div>
        <div class="form-field full">
          <button class="btn btn-secondary" @click="testApiConnection" :disabled="apiTesting">
            <span v-if="apiTesting" class="spinner"></span>
            {{ apiTesting ? '测试中...' : '测试 API 连接' }}
          </button>
          <div v-if="apiTestResult" class="ssh-result" :class="{ success: apiTestResult.success }">
            <pre>{{ apiTestResult.message }}</pre>
          </div>
        </div>
      </div>
    </div>

    <!-- SSH Settings -->
    <div class="settings-section glass-card animate__animated animate__fadeInUp" style="animation-delay: 0.1s">
      <div class="section-header">
        <h2 class="section-title">SSH 远程服务器</h2>
        <label class="toggle-label">
          <input type="checkbox" v-model="form.ssh_enabled" class="toggle-input" />
          <span class="toggle-switch"></span>
          <span>{{ form.ssh_enabled ? '已启用' : '已禁用' }}</span>
        </label>
      </div>
      <p class="section-desc">连接到 Ubuntu 服务器使用 binwalk、Ghidra、objdump 等逆向工具</p>

      <div v-if="form.ssh_enabled" class="form-grid">
        <div class="form-field">
          <label>服务器地址</label>
          <input v-model="form.ssh_host" class="input input-mono" placeholder="192.168.1.100" />
        </div>
        <div class="form-field">
          <label>端口</label>
          <input v-model.number="form.ssh_port" type="number" class="input" />
        </div>
        <div class="form-field">
          <label>用户名</label>
          <input v-model="form.ssh_username" class="input" placeholder="root" />
        </div>
        <div class="form-field full">
          <label>认证方式</label>
          <div class="auth-toggle">
            <button
              :class="['auth-btn', { active: form.ssh_auth_type === 'password' }]"
              @click="form.ssh_auth_type = 'password'"
            >密码</button>
            <button
              :class="['auth-btn', { active: form.ssh_auth_type === 'key' }]"
              @click="form.ssh_auth_type = 'key'"
            >SSH Key</button>
          </div>
        </div>
        <div v-if="form.ssh_auth_type === 'password'" class="form-field full">
          <label>密码</label>
          <input v-model="form.ssh_password" type="password" class="input" />
        </div>
        <div v-else class="form-field full">
          <label>私钥路径</label>
          <input v-model="form.ssh_key_path" class="input input-mono" placeholder="C:\Users\.ssh\id_rsa" />
          <label style="margin-top: 8px">密钥密码（可选）</label>
          <input v-model="form.ssh_passphrase" type="password" class="input" placeholder="如有" />
        </div>

        <div class="form-field full">
          <button class="btn btn-secondary" @click="testSshConnection" :disabled="sshTesting">
            <span v-if="sshTesting" class="spinner"></span>
            {{ sshTesting ? '测试中...' : '测试连接' }}
          </button>
          <div v-if="sshTestResult" class="ssh-result" :class="{ success: sshTestResult.connected }">
            <pre>{{ sshTestResult.system_info }}</pre>
          </div>
        </div>
      </div>
    </div>

    <!-- Ghidra Settings -->
    <div class="settings-section glass-card animate__animated animate__fadeInUp" style="animation-delay: 0.15s">
      <h2 class="section-title">Ghidra 反编译工具</h2>
      <p class="section-desc">配置本地 Ghidra 无头模式路径，用于二进制文件反编译分析。主攻手会自动从远程服务器下载二进制文件到本地，然后调用 Ghidra 进行分析。</p>
      <div class="form-grid">
        <div class="form-field full">
          <label>Ghidra 安装路径</label>
          <div class="input-with-browse">
            <input v-model="form.ghidra_path" class="input input-mono" placeholder="C:\Users\22522\Desktop\ghidra_11.1.2_PUBLIC" />
            <button class="btn btn-browse" @click="browseGhidraPath" title="浏览...">...</button>
          </div>
          <span class="field-hint">指向 Ghidra 根目录，程序会自动查找 support/analyzeHeadless.bat</span>
        </div>
        <div class="form-field full">
          <label>本地下载路径</label>
          <div class="input-with-browse">
            <input v-model="form.local_download_path" class="input input-mono" placeholder="C:\Users\22522\Desktop\firmware_downloads" />
            <button class="btn btn-browse" @click="browseDownloadPath" title="浏览...">...</button>
          </div>
          <span class="field-hint">从远程服务器下载文件的保存目录（如 Ghidra 分析用的二进制文件），留空则使用系统临时目录</span>
        </div>
      </div>
    </div>

    <!-- Report Export Settings -->
    <div class="settings-section glass-card animate__animated animate__fadeInUp" style="animation-delay: 0.2s">
      <h2 class="section-title">分析报告导出</h2>
      <p class="section-desc">配置分析报告的本地导出路径。分析完成后会自动将报告以 Markdown 格式导出到指定目录，您也可以在分析页面手动导出。</p>
      <div class="form-grid">
        <div class="form-field full">
          <label>报告导出路径</label>
          <div class="input-with-browse">
            <input v-model="form.report_export_path" class="input input-mono" placeholder="C:\Users\22522\Desktop\analysis_reports" />
            <button class="btn btn-browse" @click="browseReportExportPath" title="浏览选择目录">...</button>
          </div>
          <span class="field-hint">分析完成后自动导出报告到此目录，留空则不自动导出（仍可在分析页面手动导出）</span>
        </div>
      </div>
    </div>

    <!-- Agent Advanced Settings -->
    <div class="settings-section glass-card animate__animated animate__fadeInUp" style="animation-delay: 0.22s">
      <h2 class="section-title">Agent 高级配置</h2>
      <p class="section-desc">调整 AI 分析代理的运行参数，包括 API 请求超时和消息历史摘要触发阈值。</p>
      <div class="form-grid">
        <div class="form-field">
          <label>API 请求超时（秒）</label>
          <input v-model.number="form.api_timeout_secs" type="number" class="input" min="30" max="600" step="10" />
          <span class="field-hint">单次 API 调用的最大等待时间，超时后会自动重试。默认 120 秒，建议 60–300。</span>
        </div>
        <div class="form-field">
          <label>消息摘要阈值（条）</label>
          <input v-model.number="form.summarize_threshold" type="number" class="input" min="8" max="100" step="2" />
          <span class="field-hint">当对话消息超过此数量时，顾问会自动摘要压缩历史消息。默认 16，值越小摘要越频繁。</span>
        </div>
        <div class="form-field">
          <label>顾问介入间隔（轮）</label>
          <input v-model.number="form.advisor_check_interval" type="number" class="input" min="1" max="50" step="1" />
          <span class="field-hint">每隔多少轮尝试顾问自动介入一次（也用于连续失败触发间隔）。默认 5，值越小顾问介入越频繁。</span>
        </div>
      </div>
    </div>

    <!-- Background Settings -->
    <div class="settings-section glass-card animate__animated animate__fadeInUp" style="animation-delay: 0.25s">
      <h2 class="section-title">背景自定义</h2>
      <p class="section-desc">设置自定义背景图片和透明度，打造个性化工作界面。</p>
      <div class="form-grid">
        <div class="form-field full">
          <label>背景图片</label>
          <div class="input-with-browse">
            <input v-model="form.background_image" class="input input-mono" placeholder="选择一张本地图片" readonly />
            <button class="btn btn-browse" @click="browseBackgroundImage" title="选择图片">...</button>
          </div>
          <span class="field-hint">支持 PNG、JPG、WEBP、GIF 等常见图片格式</span>
        </div>
        <div v-if="form.background_image" class="form-field full">
          <label>透明度: {{ Math.round(form.background_opacity * 100) }}%</label>
          <div class="opacity-control">
            <input
              type="range"
              v-model.number="form.background_opacity"
              min="0.05"
              max="1"
              step="0.05"
              class="slider"
              @input="store.config.background_opacity = form.background_opacity"
            />
            <span class="opacity-value">{{ Math.round(form.background_opacity * 100) }}%</span>
          </div>
        </div>
        <div v-if="form.background_image" class="form-field full">
          <button class="btn btn-secondary" @click="clearBackgroundImage">清除背景图片</button>
        </div>
      </div>
    </div>

    <!-- Save Button -->
    <div class="save-bar animate__animated animate__fadeInUp" style="animation-delay: 0.25s">
      <button class="btn btn-primary" @click="saveSettings">保存配置</button>
      <span v-if="saveStatus" class="save-status">{{ saveStatus }}</span>
    </div>
  </div>
</template>

<style scoped>
.settings-page {
  display: flex;
  flex-direction: column;
  gap: 20px;
  max-width: 800px;
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
.title-icon { display: none; }

.settings-section { padding: 24px; }
.section-title { font-size: 16px; margin-bottom: 8px; }
.section-desc { font-size: 12px; color: var(--text-muted); margin-bottom: 16px; }

.section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.form-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.form-field.full { grid-column: 1 / -1; }

.form-field label {
  font-size: 12px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.field-hint {
  font-size: 11px;
  color: var(--text-muted);
  opacity: 0.7;
  margin-top: 2px;
}

/* Input with Browse Button */
.input-with-browse {
  display: flex;
  gap: 6px;
  align-items: stretch;
}
.input-with-browse .input {
  flex: 1;
}
.btn-browse {
  padding: 0 12px;
  font-size: 16px;
  border: 1px solid var(--border);
  background: var(--bg-input);
  color: var(--text-secondary);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all 0.2s ease;
  display: flex;
  align-items: center;
  justify-content: center;
  min-width: 40px;
}
.btn-browse:hover {
  border-color: var(--primary);
  background: rgba(99, 102, 241, 0.1);
  color: var(--primary-light);
}

/* Toggle */
.toggle-label {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  font-size: 13px;
  color: var(--text-secondary);
}

.toggle-input { display: none; }

.toggle-switch {
  width: 36px;
  height: 20px;
  background: var(--bg-input);
  border-radius: 10px;
  position: relative;
  transition: all 0.3s ease;
  border: 1px solid var(--border);
}

.toggle-switch::after {
  content: '';
  position: absolute;
  width: 14px;
  height: 14px;
  border-radius: 50%;
  background: var(--text-muted);
  top: 2px;
  left: 2px;
  transition: all 0.3s ease;
}

.toggle-input:checked + .toggle-switch {
  background: var(--primary-dark);
  border-color: var(--primary);
}

.toggle-input:checked + .toggle-switch::after {
  transform: translateX(16px);
  background: var(--primary-light);
}

/* Auth Toggle */
.auth-toggle {
  display: flex;
  gap: 4px;
  background: var(--bg-input);
  border-radius: var(--radius-sm);
  padding: 3px;
}

.auth-btn {
  flex: 1;
  padding: 6px 16px;
  border: none;
  background: transparent;
  color: var(--text-secondary);
  border-radius: 6px;
  cursor: pointer;
  font-family: var(--font-sans);
  font-size: 13px;
  transition: all 0.25s ease;
}

.auth-btn.active {
  background: var(--primary-dark);
  color: white;
}

/* SSH Result */
.ssh-result {
  margin-top: 10px;
  padding: 10px;
  border-radius: var(--radius-sm);
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.2);
}

.ssh-result.success {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.2);
}

.ssh-result pre {
  font-size: 12px;
  font-family: var(--font-mono);
  color: var(--text-secondary);
  white-space: pre-wrap;
}

/* Spinner */
.spinner {
  width: 14px;
  height: 14px;
  border: 2px solid rgba(255,255,255,0.3);
  border-top-color: white;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
  display: inline-block;
}

@keyframes spin { to { transform: rotate(360deg); } }

/* Save */
.save-bar {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 16px 0;
}

.save-status {
  font-size: 13px;
  color: var(--accent-green);
  animation: fade-in 0.3s ease;
}

select.input {
  appearance: none;
  background-image: url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 20 20'%3e%3cpath stroke='%239ca3af' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.5' d='M6 8l4 4 4-4'/%3e%3c/svg%3e");
  background-position: right 10px center;
  background-repeat: no-repeat;
  background-size: 16px;
  padding-right: 36px;
}

/* Opacity slider */
.opacity-control {
  display: flex;
  align-items: center;
  gap: 12px;
}

.slider {
  flex: 1;
  -webkit-appearance: none;
  appearance: none;
  height: 4px;
  background: var(--bg-input);
  border-radius: 2px;
  outline: none;
  cursor: pointer;
}

.slider::-webkit-slider-thumb {
  -webkit-appearance: none;
  appearance: none;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  background: var(--primary);
  cursor: pointer;
  border: 2px solid var(--bg-dark);
  transition: transform 0.15s ease;
}

.slider::-webkit-slider-thumb:hover {
  transform: scale(1.2);
}

.opacity-value {
  font-size: 13px;
  font-family: var(--font-mono);
  color: var(--text-secondary);
  min-width: 40px;
  text-align: right;
}
</style>
