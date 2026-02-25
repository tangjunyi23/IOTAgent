<script setup lang="ts">
import { computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAgentStore } from '../stores/agent'

const router = useRouter()
const route = useRoute()
const store = useAgentStore()

const navItems = [
  { path: '/', label: '仪表盘', shortLabel: 'Home' },
  { path: '/analysis', label: '漏洞分析', shortLabel: 'Scan' },
  { path: '/skills', label: '技能库', shortLabel: 'Skills' },
  { path: '/knowledge', label: '知识库', shortLabel: 'KB' },
  { path: '/settings', label: '设置', shortLabel: 'Config' },
]

function navigate(path: string) {
  router.push(path)
}

const statusColor = computed(() => {
  if (store.isRunning) return 'var(--accent-green)'
  if (store.findings.length > 0) return 'var(--accent-amber)'
  return 'var(--text-muted)'
})
</script>

<template>
  <nav class="sidebar">
    <!-- Logo Area -->
    <div class="sidebar-logo">
      <div class="logo-icon">
        <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
          <circle cx="16" cy="16" r="14" stroke="var(--primary)" stroke-width="2" fill="none"/>
          <path d="M10 16 L16 10 L22 16 L16 22 Z" fill="var(--primary)" opacity="0.6"/>
          <circle cx="16" cy="16" r="4" fill="var(--primary)"/>
        </svg>
      </div>
      <div class="logo-text">
        <span class="logo-title">IoT Hunter</span>
      </div>
    </div>

    <!-- Theme Toggle -->
    <button class="theme-toggle" @click="store.toggleTheme()">
      <svg v-if="store.theme === 'dark'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="5"/>
        <line x1="12" y1="1" x2="12" y2="3"/>
        <line x1="12" y1="21" x2="12" y2="23"/>
        <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
        <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
        <line x1="1" y1="12" x2="3" y2="12"/>
        <line x1="21" y1="12" x2="23" y2="12"/>
        <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
        <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
      </svg>
      <svg v-else width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
      </svg>
      <span>{{ store.theme === 'dark' ? '日间模式' : '夜间模式' }}</span>
    </button>

    <!-- Status indicator -->
    <div class="status-bar">
      <div class="status-dot" :style="{ background: statusColor }"></div>
      <span class="status-text">
        {{ store.isRunning ? '分析中...' : store.findings.length > 0 ? '发现漏洞' : '待命' }}
      </span>
    </div>

    <!-- Navigation -->
    <div class="nav-items">
      <button
        v-for="item in navItems"
        :key="item.path"
        :class="['nav-item', { active: route.path === item.path }]"
        @click="navigate(item.path)"
      >
        <span class="nav-label">{{ item.label }}</span>
        <div class="nav-indicator" v-if="route.path === item.path"></div>
      </button>
    </div>

    <!-- Bottom info -->
    <div class="sidebar-footer">
      <div class="progress-mini" v-if="store.isRunning">
        <div class="progress-mini-bar">
          <div class="progress-mini-fill" :style="{ width: store.progressPercent + '%' }"></div>
        </div>
        <span class="progress-mini-text">{{ store.progress.attempt }}/{{ store.progress.maxAttempts }}</span>
      </div>
      <div class="version-info">v0.1.0</div>
    </div>
  </nav>
</template>

<style scoped>
.sidebar {
  width: 220px;
  min-width: 220px;
  height: 100%;
  background: var(--sidebar-bg);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  padding: 16px 12px;
  backdrop-filter: blur(24px);
}

.sidebar-logo {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px;
  margin-bottom: 8px;
}

.logo-icon {
  animation: float 4s ease-in-out infinite;
}

.logo-text {
  display: flex;
  flex-direction: column;
}

.logo-title {
  font-size: 16px;
  font-weight: 700;
  color: var(--text-primary);
}

/* Theme Toggle */
.theme-toggle {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text-secondary);
  border-radius: var(--radius-sm);
  cursor: pointer;
  font-family: var(--font-sans);
  font-size: 12px;
  transition: all 0.25s ease;
  margin-bottom: 12px;
}

.theme-toggle:hover {
  background: var(--primary-glow);
  color: var(--text-primary);
  border-color: var(--border-active);
}

.status-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  background: var(--bg-input);
  border-radius: var(--radius-sm);
  margin-bottom: 20px;
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  animation: pulse-glow 2s infinite;
}

.status-text {
  font-size: 12px;
  color: var(--text-secondary);
}

.nav-items {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.nav-item {
  position: relative;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  border: none;
  background: transparent;
  color: var(--text-secondary);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all 0.25s ease;
  font-family: var(--font-sans);
  font-size: 13px;
  text-align: left;
  width: 100%;
}

.nav-item:hover {
  background: var(--primary-glow);
  color: var(--text-primary);
}

.nav-item.active {
  background: var(--primary-glow);
  color: var(--primary);
}

.nav-indicator {
  position: absolute;
  left: 0;
  top: 50%;
  transform: translateY(-50%);
  width: 3px;
  height: 20px;
  background: var(--primary);
  border-radius: 0 3px 3px 0;
  box-shadow: 0 0 8px var(--primary-glow);
}

.sidebar-footer {
  padding-top: 16px;
  border-top: 1px solid var(--border);
}

.progress-mini {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.progress-mini-bar {
  flex: 1;
  height: 4px;
  background: var(--bg-input);
  border-radius: 2px;
  overflow: hidden;
}

.progress-mini-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--primary), var(--accent-cyan));
  border-radius: 2px;
  transition: width 0.5s ease;
}

.progress-mini-text {
  font-size: 10px;
  color: var(--text-muted);
  font-family: var(--font-mono);
}

.version-info {
  font-size: 10px;
  color: var(--text-muted);
  text-align: center;
}
</style>
