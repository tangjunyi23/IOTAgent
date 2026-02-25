<script setup lang="ts">
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { useAgentStore } from '../stores/agent'

const router = useRouter()
const store = useAgentStore()

const stats = computed(() => [
  { label: '漏洞发现', value: store.findings.length, color: 'var(--accent-red)' },
  { label: '分析次数', value: store.progress.attempt, color: 'var(--accent-cyan)' },
  { label: '顾问介入', value: store.advisorMessages.length, color: 'var(--accent-amber)' },
  { label: '系统状态', value: store.isRunning ? '运行中' : '待命', color: 'var(--accent-green)' },
])

const recentLogs = computed(() => store.logs.slice(-8).reverse())

function goToAnalysis() {
  router.push('/analysis')
}
</script>

<template>
  <div class="dashboard">
    <!-- Header -->
    <div class="page-header animate__animated animate__fadeInDown">
      <h1 class="page-title">
        IoT Firmware Hunter
      </h1>
    </div>

    <!-- Stats Grid -->
    <div class="stats-grid">
      <div
        v-for="(stat, i) in stats"
        :key="stat.label"
        class="stat-card glass-card animate__animated animate__fadeInUp"
        :style="{ animationDelay: i * 0.1 + 's' }"
      >
        <div class="stat-info">
          <div class="stat-value">{{ stat.value }}</div>
          <div class="stat-label">{{ stat.label }}</div>
        </div>
        <div class="stat-glow" :style="{ background: stat.color }"></div>
      </div>
    </div>

    <!-- Main Action -->
    <div class="action-section glass-card animate__animated animate__fadeInUp" style="animation-delay: 0.4s">
      <div class="action-content">
        <div class="action-art">
          <div class="hex-grid">
            <div v-for="i in 7" :key="i" class="hex" :style="{ animationDelay: i * 0.2 + 's' }"></div>
          </div>
        </div>
        <div class="action-info">
          <h2>开始漏洞挖掘</h2>
          <p>上传固件文件，AI Agent 将自动分析文件系统、逆向二进制文件、搜索安全漏洞</p>
          <div class="action-features">
            <span class="feature-tag">binwalk 提取</span>
            <span class="feature-tag">Ghidra 逆向</span>
            <span class="feature-tag">PoC 生成</span>
            <span class="feature-tag">Docker 隔离</span>
          </div>
          <button class="btn btn-primary action-btn" @click="goToAnalysis">
            启动分析
          </button>
        </div>
      </div>
    </div>

    <!-- Recent Activity & Findings -->
    <div class="bottom-grid">
      <!-- Recent Activity -->
      <div class="glass-card animate__animated animate__fadeInLeft" style="animation-delay: 0.5s">
        <h3 class="section-title">最近活动</h3>
        <div class="log-list" v-if="recentLogs.length">
          <div v-for="log in recentLogs" :key="log.timestamp" class="log-item">
            <span class="log-level" :class="'log-' + log.level">{{ log.level }}</span>
            <span class="log-message">{{ log.message }}</span>
            <span class="log-time">{{ new Date(log.timestamp).toLocaleTimeString() }}</span>
          </div>
        </div>
        <div class="empty-state" v-else>
          <span class="empty-icon">—</span>
          <p>暂无活动记录</p>
        </div>
      </div>

      <!-- Findings -->
      <div class="glass-card animate__animated animate__fadeInRight" style="animation-delay: 0.6s">
        <h3 class="section-title">漏洞发现</h3>
        <div class="findings-list" v-if="store.findings.length">
          <div v-for="f in store.findings" :key="f.id" class="finding-item">
            <span class="badge" :class="'badge-' + f.severity.toLowerCase()">{{ f.severity }}</span>
            <span class="finding-title">{{ f.title }}</span>
          </div>
        </div>
        <div class="empty-state" v-else>
          <span class="empty-icon">—</span>
          <p>尚未发现漏洞</p>
          <p class="empty-hint">开始分析后，发现的漏洞将显示在这里</p>
        </div>
      </div>
    </div>


  </div>
</template>

<style scoped>
.dashboard {
  display: flex;
  flex-direction: column;
  gap: 20px;
  max-width: 1200px;
  margin: 0 auto;
}

.page-header {
  text-align: center;
  padding: 20px 0 10px;
}

.page-title {
  font-size: 28px;
  font-weight: 700;
  background: linear-gradient(135deg, var(--primary-light), var(--accent-cyan), var(--primary));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
}

.page-subtitle {
  color: var(--text-muted);
  font-size: 14px;
  margin-top: 6px;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
}

.stat-card {
  position: relative;
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 18px;
  overflow: hidden;
}

.stat-value {
  font-size: 22px;
  font-weight: 700;
  font-family: var(--font-mono);
}

.stat-label {
  font-size: 12px;
  color: var(--text-muted);
}

.stat-glow {
  position: absolute;
  top: -20px;
  right: -20px;
  width: 60px;
  height: 60px;
  border-radius: 50%;
  opacity: 0.08;
  filter: blur(20px);
}

/* Action Section */
.action-section {
  padding: 0;
  overflow: hidden;
}

.action-content {
  display: flex;
  align-items: stretch;
}

.action-art {
  width: 200px;
  min-height: 200px;
  background: linear-gradient(135deg, var(--primary-glow), var(--bg-input));
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
  overflow: hidden;
}

.hex-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  padding: 20px;
  justify-content: center;
}

.hex {
  width: 30px;
  height: 30px;
  background: var(--primary-glow);
  clip-path: polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%);
  animation: pulse-glow 3s infinite;
}

.action-info {
  flex: 1;
  padding: 28px;
}

.action-info h2 {
  font-size: 22px;
  margin-bottom: 8px;
  background: linear-gradient(135deg, var(--primary-light), var(--accent-cyan));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

.action-info p {
  color: var(--text-secondary);
  font-size: 14px;
  line-height: 1.6;
  margin-bottom: 16px;
}

.action-features {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 20px;
}

.feature-tag {
  padding: 4px 12px;
  background: var(--bg-input);
  border: 1px solid var(--border);
  border-radius: 20px;
  font-size: 12px;
  color: var(--text-secondary);
}

.action-btn {
  font-size: 15px;
  padding: 12px 28px;
}

/* Bottom Grid */
.bottom-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.section-title {
  font-size: 15px;
  margin-bottom: 16px;
  color: var(--text-primary);
}

.log-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.log-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px;
  background: var(--bg-input);
  border-radius: var(--radius-sm);
  font-size: 12px;
}

.log-level {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  min-width: 44px;
  text-align: center;
}

.log-info { background: rgba(59, 130, 246, 0.2); color: #93c5fd; }
.log-warn { background: rgba(234, 179, 8, 0.2); color: #fde047; }
.log-error { background: rgba(239, 68, 68, 0.2); color: #fca5a5; }

.log-message {
  flex: 1;
  color: var(--text-secondary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.log-time {
  color: var(--text-muted);
  font-family: var(--font-mono);
  font-size: 10px;
}

.findings-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.finding-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px;
  background: var(--bg-input);
  border-radius: var(--radius-sm);
}

.finding-title {
  font-size: 13px;
  color: var(--text-primary);
}

.empty-state {
  text-align: center;
  padding: 30px 20px;
  color: var(--text-muted);
}

.empty-icon {
  font-size: 36px;
  display: block;
  margin-bottom: 8px;
}

.empty-hint {
  font-size: 12px;
  margin-top: 4px;
  opacity: 0.6;
}



@media (max-width: 900px) {
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
  .bottom-grid { grid-template-columns: 1fr; }
  .action-art { display: none; }
}
</style>
