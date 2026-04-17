<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRoute } from 'vue-router';
import { api, type Dashboard as DashboardData, type Settings } from '../api';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { logout } from '../router';

const route = useRoute();

/** 仪表盘统计数据 */
const dashboard = ref<DashboardData | null>(null);
const quarantineOn429 = ref(true);
const warmupEnabled = ref(false);
const warmupBaseUtcHour = ref(23);
const warmupJitterMinutes = ref(30);
const warmupMaxRetries = ref(2);
const warmupRetryBackoffSecs = ref(300);
const warmupAccountGapSecs = ref(45);
const warmupPollIntervalSecs = ref(60);
const settingsLoading = ref(false);

/** 加载仪表盘数据 */
async function loadDashboard() {
  try {
    dashboard.value = await api.getDashboard();
  } catch {
    // 忽略瞬态错误
  }
}

async function loadSettings() {
  try {
    const settings = await api.getSettings();
    applySettings(settings);
  } catch {
    // 忽略瞬态错误
  }
}

function applySettings(settings: Settings) {
  quarantineOn429.value = settings.quarantine_on_429;
  warmupEnabled.value = settings.warmup_enabled;
  warmupBaseUtcHour.value = settings.warmup_base_utc_hour;
  warmupJitterMinutes.value = settings.warmup_jitter_minutes;
  warmupMaxRetries.value = settings.warmup_max_retries;
  warmupRetryBackoffSecs.value = settings.warmup_retry_backoff_secs;
  warmupAccountGapSecs.value = settings.warmup_account_gap_secs;
  warmupPollIntervalSecs.value = settings.warmup_poll_interval_secs;
}

async function toggleQuarantine() {
  settingsLoading.value = true;
  try {
    applySettings(await api.updateSettings({
      quarantine_on_429: !quarantineOn429.value,
    }));
  } catch {
    // 忽略瞬态错误
  } finally {
    settingsLoading.value = false;
  }
}

async function toggleWarmup() {
  settingsLoading.value = true;
  try {
    applySettings(await api.updateSettings({
      warmup_enabled: !warmupEnabled.value,
    }));
  } catch {
    // 忽略瞬态错误
  } finally {
    settingsLoading.value = false;
  }
}

async function saveWarmupSettings() {
  settingsLoading.value = true;
  try {
    applySettings(await api.updateSettings({
      warmup_base_utc_hour: warmupBaseUtcHour.value,
      warmup_jitter_minutes: warmupJitterMinutes.value,
      warmup_max_retries: warmupMaxRetries.value,
      warmup_retry_backoff_secs: warmupRetryBackoffSecs.value,
      warmup_account_gap_secs: warmupAccountGapSecs.value,
      warmup_poll_interval_secs: warmupPollIntervalSecs.value,
    }));
  } catch {
    // 忽略瞬态错误
  } finally {
    settingsLoading.value = false;
  }
}

/** 格式化大数字为千分位 */
function formatNum(n: number): string {
  return n.toLocaleString();
}

function formatUtcHour(hour: number): string {
  return `UTC ${String(hour).padStart(2, '0')}:00`;
}

onMounted(() => {
  loadDashboard();
  loadSettings();
});
</script>

<template>
  <div class="min-h-screen">
    <!-- 顶部导航栏 -->
    <header class="sticky top-0 z-40 bg-white/80 backdrop-blur-md border-b border-[#e8e2d9]/60 px-6 py-3">
      <div class="max-w-7xl mx-auto flex items-center justify-between">
        <div class="flex items-center gap-6">
          <div class="flex items-center gap-2">
            <img src="/favicon.svg" alt="Logo" class="w-6 h-6" />
            <h1 class="text-lg font-semibold text-[#29261e] tracking-tight">Claude Code Gateway</h1>
          </div>
          <nav class="flex items-center gap-1">
            <router-link
              :to="{ name: 'accounts' }"
              class="px-3 py-1.5 text-sm rounded-lg transition-colors"
              :class="route.name === 'accounts' || route.name === 'dashboard'
                ? 'bg-[#c4704f]/10 text-[#c4704f] font-medium'
                : 'text-[#8c8475] hover:text-[#29261e] hover:bg-[#f0ebe4]'"
            >
              账号
            </router-link>
            <router-link
              :to="{ name: 'tokens' }"
              class="px-3 py-1.5 text-sm rounded-lg transition-colors"
              :class="route.name === 'tokens'
                ? 'bg-[#c4704f]/10 text-[#c4704f] font-medium'
                : 'text-[#8c8475] hover:text-[#29261e] hover:bg-[#f0ebe4]'"
            >
              令牌
            </router-link>
          </nav>
        </div>
        <div class="flex items-center gap-3">
          <div class="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#f0ebe4]">
            <span class="text-xs text-[#8c8475]">429 暂停账号</span>
            <button
              :disabled="settingsLoading"
              @click="toggleQuarantine"
              class="relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none disabled:opacity-50"
              :class="quarantineOn429 ? 'bg-[#c4704f]' : 'bg-[#d6d0c8]'"
              :aria-checked="quarantineOn429"
              role="switch"
            >
              <span
                class="pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow-sm transition-transform duration-200"
                :class="quarantineOn429 ? 'translate-x-4' : 'translate-x-0'"
              />
            </button>
          </div>
          <div class="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#f6efe6]">
            <span class="text-xs text-[#8c8475]">预热调度</span>
            <button
              :disabled="settingsLoading"
              @click="toggleWarmup"
              class="relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none disabled:opacity-50"
              :class="warmupEnabled ? 'bg-[#c4704f]' : 'bg-[#d6d0c8]'"
              :aria-checked="warmupEnabled"
              role="switch"
            >
              <span
                class="pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow-sm transition-transform duration-200"
                :class="warmupEnabled ? 'translate-x-4' : 'translate-x-0'"
              />
            </button>
          </div>
          <Button
            variant="ghost"
            size="sm"
            @click="logout"
            class="text-[#8c8475] hover:text-[#29261e] hover:bg-[#f0ebe4]"
          >
            退出
          </Button>
        </div>
      </div>
    </header>

    <main class="max-w-7xl mx-auto px-6 py-6 space-y-6">
      <!-- 统计卡片 -->
      <div v-if="dashboard" class="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card class="bg-white border-[#e8e2d9] rounded-xl hover:shadow-md transition-all duration-200 !py-0 !gap-0">
          <CardContent class="py-3 px-4">
            <p class="text-[#8c8475] text-xs mb-1">总账号</p>
            <p class="text-2xl font-bold text-[#29261e]">{{ formatNum(dashboard.accounts.total) }}</p>
          </CardContent>
        </Card>
        <Card class="bg-white border-[#e8e2d9] rounded-xl hover:shadow-md transition-all duration-200 !py-0 !gap-0">
          <CardContent class="py-3 px-4">
            <p class="text-[#8c8475] text-xs mb-1">活跃</p>
            <p class="text-2xl font-bold text-emerald-600">{{ formatNum(dashboard.accounts.active) }}</p>
          </CardContent>
        </Card>
        <Card class="bg-white border-[#e8e2d9] rounded-xl hover:shadow-md transition-all duration-200 !py-0 !gap-0">
          <CardContent class="py-3 px-4">
            <p class="text-[#8c8475] text-xs mb-1">异常</p>
            <p class="text-2xl font-bold text-red-500">{{ formatNum(dashboard.accounts.error) }}</p>
          </CardContent>
        </Card>
        <Card class="bg-white border-[#e8e2d9] rounded-xl hover:shadow-md transition-all duration-200 !py-0 !gap-0">
          <CardContent class="py-3 px-4">
            <p class="text-[#8c8475] text-xs mb-1">停用</p>
            <p class="text-2xl font-bold text-[#b5b0a6]">{{ formatNum(dashboard.accounts.disabled) }}</p>
          </CardContent>
        </Card>
        <Card class="bg-white border-[#e8e2d9] rounded-xl hover:shadow-md transition-all duration-200 !py-0 !gap-0">
          <CardContent class="py-3 px-4">
            <p class="text-[#8c8475] text-xs mb-1">令牌</p>
            <p class="text-2xl font-bold text-[#29261e]">{{ formatNum(dashboard.tokens) }}</p>
          </CardContent>
        </Card>
      </div>

      <Card class="bg-[linear-gradient(135deg,#fbf5ed_0%,#fffaf5_100%)] border-[#e8e2d9] rounded-2xl !py-0 !gap-0">
        <CardContent class="py-5 px-5 space-y-4">
          <div class="flex items-start justify-between gap-4">
            <div>
              <p class="text-sm font-semibold text-[#29261e]">预热计划</p>
              <p class="text-xs text-[#8c8475] mt-1">
                围绕 {{ formatUtcHour(warmupBaseUtcHour) }} 在 ±{{ warmupJitterMinutes }} 分钟内随机触发，每天时间不同。
              </p>
            </div>
            <Badge
              class="border text-xs font-medium"
              :class="warmupEnabled ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-gray-100 text-gray-500 border-gray-200'"
            >
              {{ warmupEnabled ? '已启用' : '已关闭' }}
            </Badge>
          </div>

          <div class="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
            <div class="space-y-1">
              <label class="text-[10px] text-[#b5b0a6] uppercase tracking-wider">基准时刻</label>
              <input
                v-model.number="warmupBaseUtcHour"
                type="number"
                min="0"
                max="23"
                class="w-full h-10 rounded-xl border border-[#e8e2d9] bg-white px-3 text-sm text-[#29261e] focus:outline-none focus:border-[#c4704f]"
              />
            </div>
            <div class="space-y-1">
              <label class="text-[10px] text-[#b5b0a6] uppercase tracking-wider">随机分钟</label>
              <input
                v-model.number="warmupJitterMinutes"
                type="number"
                min="0"
                max="720"
                class="w-full h-10 rounded-xl border border-[#e8e2d9] bg-white px-3 text-sm text-[#29261e] focus:outline-none focus:border-[#c4704f]"
              />
            </div>
            <div class="space-y-1">
              <label class="text-[10px] text-[#b5b0a6] uppercase tracking-wider">最大重试</label>
              <input
                v-model.number="warmupMaxRetries"
                type="number"
                min="0"
                max="10"
                class="w-full h-10 rounded-xl border border-[#e8e2d9] bg-white px-3 text-sm text-[#29261e] focus:outline-none focus:border-[#c4704f]"
              />
            </div>
            <div class="space-y-1">
              <label class="text-[10px] text-[#b5b0a6] uppercase tracking-wider">重试秒数</label>
              <input
                v-model.number="warmupRetryBackoffSecs"
                type="number"
                min="30"
                class="w-full h-10 rounded-xl border border-[#e8e2d9] bg-white px-3 text-sm text-[#29261e] focus:outline-none focus:border-[#c4704f]"
              />
            </div>
            <div class="space-y-1">
              <label class="text-[10px] text-[#b5b0a6] uppercase tracking-wider">账号间隔</label>
              <input
                v-model.number="warmupAccountGapSecs"
                type="number"
                min="1"
                class="w-full h-10 rounded-xl border border-[#e8e2d9] bg-white px-3 text-sm text-[#29261e] focus:outline-none focus:border-[#c4704f]"
              />
            </div>
            <div class="space-y-1">
              <label class="text-[10px] text-[#b5b0a6] uppercase tracking-wider">轮询间隔</label>
              <input
                v-model.number="warmupPollIntervalSecs"
                type="number"
                min="15"
                class="w-full h-10 rounded-xl border border-[#e8e2d9] bg-white px-3 text-sm text-[#29261e] focus:outline-none focus:border-[#c4704f]"
              />
            </div>
          </div>

          <div class="flex items-center justify-between gap-3">
            <p class="text-xs text-[#8c8475]">
              账号页里单独开启的账号才会参与预热，消息内容会随机短寒暄，不固定为 `hi`。
            </p>
            <Button
              :disabled="settingsLoading"
              @click="saveWarmupSettings"
              class="bg-[#c4704f] hover:bg-[#b5623f] text-white rounded-xl"
            >
              {{ settingsLoading ? '保存中...' : '保存预热设置' }}
            </Button>
          </div>
        </CardContent>
      </Card>

      <!-- 子路由内容 -->
      <router-view @refresh="loadDashboard" />
    </main>
  </div>
</template>
