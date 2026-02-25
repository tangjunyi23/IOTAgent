<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed } from 'vue'
import { useAgentStore } from '../stores/agent'

const store = useAgentStore()

interface Particle {
  x: number; y: number; size: number; speed: number; opacity: number; hue: number
}

const canvas = ref<HTMLCanvasElement>()
let animId = 0
let particles: Particle[] = []

const hasCustomBg = computed(() => !!store.backgroundDataUrl)
const bgOpacity = computed(() => store.config.background_opacity ?? 0.3)
const isDark = computed(() => store.theme === 'dark')

function initParticles(w: number, h: number) {
  particles = Array.from({ length: 40 }, () => ({
    x: Math.random() * w,
    y: Math.random() * h,
    size: Math.random() * 2 + 0.5,
    speed: Math.random() * 0.3 + 0.05,
    opacity: Math.random() * 0.2 + 0.03,
    hue: 0,
  }))
}

function draw() {
  const c = canvas.value
  if (!c) return
  const ctx = c.getContext('2d')!
  const w = c.width = c.offsetWidth
  const h = c.height = c.offsetHeight

  if (particles.length === 0) initParticles(w, h)

  ctx.clearRect(0, 0, w, h)

  const dark = isDark.value
  for (const p of particles) {
    p.y -= p.speed
    if (p.y < -10) { p.y = h + 10; p.x = Math.random() * w }

    ctx.beginPath()
    ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2)
    ctx.fillStyle = dark
      ? `rgba(255, 255, 255, ${p.opacity})`
      : `rgba(0, 0, 0, ${p.opacity * 0.5})`
    ctx.fill()
  }

  animId = requestAnimationFrame(draw)
}

onMounted(() => { draw() })
onUnmounted(() => { cancelAnimationFrame(animId) })
</script>

<template>
  <div class="bg-effect">
    <!-- Custom background image -->
    <div
      v-if="hasCustomBg"
      class="custom-bg"
      :style="{
        backgroundImage: `url(${store.backgroundDataUrl})`,
        opacity: bgOpacity,
      }"
    ></div>
    <!-- Gradient background (semi-transparent when custom bg exists) -->
    <div class="gradient-bg" :class="{ 'has-custom': hasCustomBg }"></div>
    <!-- Particle canvas -->
    <canvas ref="canvas" class="particle-canvas"></canvas>
  </div>
</template>

<style scoped>
.bg-effect {
  position: fixed;
  inset: 0;
  z-index: 0;
  pointer-events: none;
}

.custom-bg {
  position: absolute;
  inset: 0;
  background-size: cover;
  background-position: center;
  background-repeat: no-repeat;
  z-index: 0;
}

.gradient-bg {
  position: absolute;
  inset: 0;
  z-index: 1;
  background: var(--bg-deep);
}

.gradient-bg.has-custom {
  background: var(--bg-deep);
  opacity: 0.55;
}

.particle-canvas {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  z-index: 2;
}
</style>
