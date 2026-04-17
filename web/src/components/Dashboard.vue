<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRoute } from 'vue-router';
import { api, type Dashboard as DashboardData } from '../api';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { logout } from '../router';

const route = useRoute();

/** 仪表盘统计数据 */
const dashboard = ref<DashboardData | null>(null);

/** 加载仪表盘数据 */
async function loadDashboard() {
  try {
    dashboard.value = await api.getDashboard();
  } catch {
    // 忽略瞬态错误
  }
}

/** 格式化大数字为千分位 */
function formatNum(n: number): string {
  return n.toLocaleString();
}

onMounted(loadDashboard);
</script>

<template>
  <div class="min-h-screen">
    <!-- 顶部导航栏 -->
    <header class="sticky top-0 z-40 bg-white/80 backdrop-blur-md border-b border-[#e8e2d9]/60 px-6 py-3">
      <div class="max-w-7xl mx-auto flex items-center justify-between">
        <div class="flex items-center gap-6">
          <div class="flex items-center gap-2">
            <img src="/favicon.svg" alt="Logo" class="w-6 h-6" />
            <h1 class="text-lg font-semibold text-[#29261e] tracking-tight">cc-bridge</h1>
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
        <Button
          variant="ghost"
          size="sm"
          @click="logout"
          class="text-[#8c8475] hover:text-[#29261e] hover:bg-[#f0ebe4]"
        >
          退出
        </Button>
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

      <!-- 子路由内容 -->
      <router-view @refresh="loadDashboard" />
    </main>
  </div>
</template>
