<script setup lang="ts">
import { onMounted } from 'vue'
import { useAgentStore } from './stores/agent'
import Sidebar from './components/Sidebar.vue'
import BackgroundEffect from './components/BackgroundEffect.vue'

const store = useAgentStore()

onMounted(async () => {
  await store.loadConfig()
  await store.setupEventListener()
})
</script>

<template>
  <div class="app-root">
    <BackgroundEffect />
    <div class="app-layout">
      <Sidebar />
      <main class="main-content">
        <router-view v-slot="{ Component }">
          <transition name="page" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </main>
    </div>
  </div>
</template>

<style scoped>
.app-root {
  width: 100vw;
  height: 100vh;
  position: relative;
  overflow: hidden;
}

.app-layout {
  position: relative;
  z-index: 1;
  display: flex;
  width: 100%;
  height: 100%;
}

.main-content {
  flex: 1;
  overflow-y: auto;
  padding: 24px;
  position: relative;
}
</style>
