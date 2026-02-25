import { createApp } from "vue";
import { createPinia } from "pinia";
import { createRouter, createWebHistory } from "vue-router";
import App from "./App.vue";
import "animate.css";
import "./styles/global.css";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/", component: () => import("./views/Dashboard.vue") },
    { path: "/analysis", component: () => import("./views/Analysis.vue") },
    { path: "/settings", component: () => import("./views/Settings.vue") },
    { path: "/knowledge", component: () => import("./views/Knowledge.vue") },
    { path: "/skills", component: () => import("./views/Skills.vue") },
  ],
});

const app = createApp(App);
app.use(createPinia());
app.use(router);
app.mount("#app");
