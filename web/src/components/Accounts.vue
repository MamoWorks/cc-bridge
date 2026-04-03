<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { api, type Account } from '../api';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter,
} from '@/components/ui/dialog';
import { useToast } from '../composables/useToast';

const emit = defineEmits<{ refresh: [] }>();
const { show: toast } = useToast();

/** 账号列表 */
const accounts = ref<Account[]>([]);
/** 分页状态 */
const currentPage = ref(1);
const totalPages = ref(1);
const totalCount = ref(0);
const pageSize = 12;
/** 表单弹窗是否可见 */
const showForm = ref(false);
/** 删除确认弹窗是否可见 */
const showDeleteConfirm = ref(false);
/** 待删除账号 ID */
const deleteTargetId = ref<number | null>(null);
/** 当前编辑的账号（null 表示新建） */
const editing = ref<Account | null>(null);
/** 表单数据 */
const form = ref({ name: '', email: '', token: '', proxy_url: '', billing_mode: 'strip', concurrency: 3, priority: 50 });
/** 正在测试的账号 ID */
const testing = ref<number | null>(null);
/** 测试结果 */
const testResult = ref<{ status: string; message?: string } | null>(null);
/** 正在刷新用量的账号 ID */
const refreshingUsage = ref<number | null>(null);

/** 加载账号列表 */
async function load() {
  try {
    const res = await api.listAccounts(currentPage.value, pageSize);
    accounts.value = res.data ?? [];
    totalPages.value = res.total_pages;
    totalCount.value = res.total;
  } catch {
    accounts.value = [];
  }
}

/** 翻页 */
function goToPage(page: number) {
  if (page < 1 || page > totalPages.value) return;
  currentPage.value = page;
  load();
}

/** 可见的页码列表 */
const visiblePages = computed(() => {
  const pages: number[] = [];
  const total = totalPages.value;
  const current = currentPage.value;
  let start = Math.max(1, current - 2);
  let end = Math.min(total, start + 4);
  start = Math.max(1, end - 4);
  for (let i = start; i <= end; i++) pages.push(i);
  return pages;
});

onMounted(load);

/** 打开新建账号弹窗 */
function openCreate() {
  editing.value = null;
  form.value = { name: '', email: '', token: '', proxy_url: '', billing_mode: 'strip', concurrency: 3, priority: 50 };
  showForm.value = true;
}

/**
 * 打开编辑账号弹窗
 * @param a 要编辑的账号对象
 */
function openEdit(a: Account) {
  editing.value = a;
  form.value = {
    name: a.name,
    email: a.email,
    token: '',
    proxy_url: a.proxy_url,
    billing_mode: a.billing_mode || 'strip',
    concurrency: a.concurrency,
    priority: a.priority,
  };
  showForm.value = true;
}

/** 保存账号（新建或更新） */
async function save() {
  try {
    if (editing.value) {
      const updates: Record<string, unknown> = {};
      if (form.value.name) updates.name = form.value.name;
      if (form.value.email) updates.email = form.value.email;
      if (form.value.token) updates.token = form.value.token;
      updates.proxy_url = form.value.proxy_url;
      updates.billing_mode = form.value.billing_mode;
      updates.concurrency = form.value.concurrency;
      updates.priority = form.value.priority;
      await api.updateAccount(editing.value.id, updates);
    } else {
      await api.createAccount(form.value);
    }
    showForm.value = false;
    await load();
    emit('refresh');
  } catch (e: unknown) {
    toast((e as Error).message || '保存失败');
  }
}

/**
 * 确认删除账号
 * @param id 账号 ID
 */
function confirmDelete(id: number) {
  deleteTargetId.value = id;
  showDeleteConfirm.value = true;
}

/** 执行删除账号 */
async function executeDelete() {
  if (deleteTargetId.value === null) return;
  try {
    await api.deleteAccount(deleteTargetId.value);
    showDeleteConfirm.value = false;
    deleteTargetId.value = null;
    await load();
    emit('refresh');
  } catch (e: unknown) {
    toast((e as Error).message || '删除失败');
  }
}

/**
 * 测试账号连接
 * @param id 账号 ID
 */
async function test(id: number) {
  testing.value = id;
  testResult.value = null;
  try {
    testResult.value = await api.testAccount(id);
    if (testResult.value.status === 'error') {
      toast(testResult.value.message || '测试失败');
    }
  } catch (e: unknown) {
    toast((e as Error).message || '测试请求失败');
  }
  setTimeout(() => { testing.value = null; testResult.value = null; }, 3000);
}

/**
 * 刷新账号用量数据
 * @param id 账号 ID
 */
async function refreshUsage(id: number) {
  refreshingUsage.value = id;
  try {
    const res = await api.refreshUsage(id);
    if (res.status === 'ok' && res.usage) {
      const acc = accounts.value.find(a => a.id === id);
      if (acc) {
        acc.usage_data = res.usage;
        acc.usage_fetched_at = new Date().toISOString();
      }
    } else if (res.status === 'error') {
      toast(res.message || '刷新用量失败');
    }
  } catch (e: unknown) {
    toast((e as Error).message || '刷新用量失败');
  }
  refreshingUsage.value = null;
}

/**
 * 格式化剩余时间
 * @param resetsAt ISO 时间字符串
 */
function formatTimeLeft(resetsAt: string): string {
  const diff = new Date(resetsAt).getTime() - Date.now();
  if (diff <= 0) return '已重置';
  const hours = Math.floor(diff / 3600000);
  const minutes = Math.floor((diff % 3600000) / 60000);
  if (hours > 0) return `${hours}h${minutes}m`;
  return `${minutes}m`;
}

/**
 * 获取用量进度条颜色
 * @param pct 使用百分比 (0-100)
 */
function usageBarColor(pct: number): string {
  if (pct >= 80) return 'bg-red-400';
  if (pct >= 50) return 'bg-amber-400';
  return 'bg-emerald-400';
}

/**
 * 获取状态徽章样式
 * @param status 账号状态
 */
function statusStyle(status: string): { class: string; label: string } {
  if (status === 'active') return { class: 'bg-emerald-50 text-emerald-700 border-emerald-200', label: '活跃' };
  if (status === 'error') return { class: 'bg-red-50 text-red-600 border-red-200', label: '异常' };
  return { class: 'bg-gray-100 text-gray-500 border-gray-200', label: '停用' };
}

/**
 * 遮蔽 Token 显示
 * @param t Token 原始值
 */
function maskToken(t: string): string {
  if (t.length <= 20) return t;
  return t.slice(0, 20) + '...';
}
</script>

<template>
  <div class="space-y-4">
    <!-- 标题栏 -->
    <div class="flex justify-between items-center">
      <h2 class="text-lg font-semibold text-[#29261e]">账号管理</h2>
      <Button
        @click="openCreate"
        class="bg-[#c4704f] hover:bg-[#b5623f] text-white font-medium rounded-xl transition-all duration-200 hover:shadow-md"
      >
        添加账号
      </Button>
    </div>

    <!-- 账号卡片列表 -->
    <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
      <Card
        v-for="a in accounts"
        :key="a.id"
        class="bg-white border-[#e8e2d9] rounded-xl hover:shadow-md transition-all duration-200 overflow-hidden"
      >
        <div class="p-5 space-y-3">
          <!-- 头部：名称 + 状态 -->
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2 min-w-0">
              <div class="w-8 h-8 rounded-lg bg-[#c4704f]/10 flex items-center justify-center flex-shrink-0">
                <span class="text-[#c4704f] text-sm font-semibold">{{ (a.name || a.email)[0].toUpperCase() }}</span>
              </div>
              <div class="min-w-0">
                <p class="text-sm font-medium text-[#29261e] truncate">{{ a.name || a.email }}</p>
                <p v-if="a.name" class="text-xs text-[#8c8475] truncate">{{ a.email }}</p>
              </div>
            </div>
            <Badge :class="statusStyle(a.status).class" class="border text-xs font-medium flex-shrink-0">
              {{ statusStyle(a.status).label }}
            </Badge>
          </div>

          <!-- 信息 -->
          <div class="pt-2 border-t border-[#f0ebe4] space-y-2">
            <div class="grid grid-cols-3 gap-3">
              <div class="text-center">
                <p class="text-[10px] text-[#b5b0a6] uppercase tracking-wider">并发</p>
                <p class="text-sm font-medium text-[#29261e]">{{ a.concurrency }}</p>
              </div>
              <div class="text-center">
                <p class="text-[10px] text-[#b5b0a6] uppercase tracking-wider">优先级</p>
                <p class="text-sm font-medium text-[#29261e]">{{ a.priority }}</p>
              </div>
              <div class="text-center">
                <p class="text-[10px] text-[#b5b0a6] uppercase tracking-wider">Billing</p>
                <p class="text-sm font-medium" :class="a.billing_mode === 'rewrite' ? 'text-amber-600' : 'text-[#29261e]'">
                  {{ a.billing_mode === 'rewrite' ? '重写' : '清除' }}
                </p>
              </div>
            </div>
            <div class="space-y-3">
              <div>
                <p class="text-[10px] text-[#b5b0a6] uppercase tracking-wider mb-0.5">代理</p>
                <p class="text-sm text-[#8c8475] truncate">{{ a.proxy_url || '直连' }}</p>
              </div>
              <div>
                <p class="text-[10px] text-[#b5b0a6] uppercase tracking-wider mb-0.5">Setup Token</p>
                <p class="font-mono text-[11px] text-[#8c8475] truncate">{{ maskToken(a.token) }}</p>
              </div>
            </div>
          </div>

          <!-- 用量窗口 -->
          <div class="pt-2 border-t border-[#f0ebe4] space-y-2">
            <div class="flex items-center justify-between">
              <p class="text-[10px] text-[#b5b0a6] uppercase tracking-wider">用量</p>
              <p v-if="a.usage_fetched_at" class="text-[10px] text-[#b5b0a6]">
                {{ new Date(a.usage_fetched_at).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) }}
              </p>
              <p v-else class="text-[10px] text-[#b5b0a6]">未刷新</p>
            </div>
            <!-- 5 小时 -->
            <div class="space-y-0.5">
              <div class="flex justify-between text-[11px]">
                <span class="text-[#8c8475]">5 小时</span>
                <span class="text-[#5c5647] font-medium">{{ a.usage_data?.five_hour ? (a.usage_data.five_hour.utilization * 100).toFixed(0) : '0' }}%
                  <span v-if="a.usage_data?.five_hour" class="text-[#b5b0a6] font-normal">· {{ formatTimeLeft(a.usage_data.five_hour.resets_at) }}</span>
                </span>
              </div>
              <div class="h-1.5 bg-[#f0ebe4] rounded-full overflow-hidden">
                <div :class="usageBarColor(a.usage_data?.five_hour ? a.usage_data.five_hour.utilization * 100 : 0)"
                  class="h-full rounded-full transition-all duration-300"
                  :style="{ width: (a.usage_data?.five_hour ? Math.min(a.usage_data.five_hour.utilization * 100, 100) : 0) + '%' }" />
              </div>
            </div>
            <!-- 7 天 -->
            <div class="space-y-0.5">
              <div class="flex justify-between text-[11px]">
                <span class="text-[#8c8475]">7 天</span>
                <span class="text-[#5c5647] font-medium">{{ a.usage_data?.seven_day ? (a.usage_data.seven_day.utilization * 100).toFixed(0) : '0' }}%
                  <span v-if="a.usage_data?.seven_day" class="text-[#b5b0a6] font-normal">· {{ formatTimeLeft(a.usage_data.seven_day.resets_at) }}</span>
                </span>
              </div>
              <div class="h-1.5 bg-[#f0ebe4] rounded-full overflow-hidden">
                <div :class="usageBarColor(a.usage_data?.seven_day ? a.usage_data.seven_day.utilization * 100 : 0)"
                  class="h-full rounded-full transition-all duration-300"
                  :style="{ width: (a.usage_data?.seven_day ? Math.min(a.usage_data.seven_day.utilization * 100, 100) : 0) + '%' }" />
              </div>
            </div>
            <!-- 7 天 Sonnet -->
            <div class="space-y-0.5">
              <div class="flex justify-between text-[11px]">
                <span class="text-[#8c8475]">7 天 Sonnet</span>
                <span class="text-[#5c5647] font-medium">{{ a.usage_data?.seven_day_sonnet ? (a.usage_data.seven_day_sonnet.utilization * 100).toFixed(0) : '0' }}%
                  <span v-if="a.usage_data?.seven_day_sonnet" class="text-[#b5b0a6] font-normal">· {{ formatTimeLeft(a.usage_data.seven_day_sonnet.resets_at) }}</span>
                </span>
              </div>
              <div class="h-1.5 bg-[#f0ebe4] rounded-full overflow-hidden">
                <div :class="usageBarColor(a.usage_data?.seven_day_sonnet ? a.usage_data.seven_day_sonnet.utilization * 100 : 0)"
                  class="h-full rounded-full transition-all duration-300"
                  :style="{ width: (a.usage_data?.seven_day_sonnet ? Math.min(a.usage_data.seven_day_sonnet.utilization * 100, 100) : 0) + '%' }" />
              </div>
            </div>
          </div>

          <!-- 测试结果 -->
          <div
            v-if="testing === a.id && testResult"
            class="text-xs font-medium px-2 py-1 rounded-lg text-center"
            :class="testResult.status === 'ok' ? 'bg-emerald-50 text-emerald-600' : 'bg-red-50 text-red-500'"
          >
            {{ testResult.status === 'ok' ? '连接正常' : testResult.message }}
          </div>

          <!-- 操作按钮 -->
          <div class="flex items-center gap-2 pt-2 border-t border-[#f0ebe4]">
            <Button
              variant="ghost"
              size="sm"
              @click="openEdit(a)"
              class="text-[#8c8475] hover:text-[#29261e] hover:bg-[#f0ebe4] h-8 px-3 text-xs flex-1"
            >
              编辑
            </Button>
            <Button
              variant="ghost"
              size="sm"
              @click="refreshUsage(a.id)"
              :disabled="refreshingUsage === a.id"
              class="text-[#c4704f] hover:text-[#b5623f] hover:bg-[#c4704f]/5 h-8 px-3 text-xs flex-1"
            >
              {{ refreshingUsage === a.id ? '刷新中...' : '用量' }}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              @click="test(a.id)"
              :disabled="testing === a.id"
              class="text-[#c4704f] hover:text-[#b5623f] hover:bg-[#c4704f]/5 h-8 px-3 text-xs flex-1"
            >
              {{ testing === a.id ? '测试中...' : '测试' }}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              @click="confirmDelete(a.id)"
              class="text-red-400 hover:text-red-500 hover:bg-red-50 h-8 px-3 text-xs flex-1"
            >
              删除
            </Button>
          </div>
        </div>
      </Card>

      <!-- 空状态 -->
      <div
        v-if="accounts.length === 0"
        class="col-span-full flex flex-col items-center justify-center py-16 text-[#b5b0a6]"
      >
        <div class="w-12 h-12 rounded-xl bg-[#f0ebe4] flex items-center justify-center mb-3">
          <svg class="w-6 h-6 text-[#c4704f]/50" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M18 7.5v3m0 0v3m0-3h3m-3 0h-3m-2.25-4.125a3.375 3.375 0 1 1-6.75 0 3.375 3.375 0 0 1 6.75 0ZM3 19.235v-.11a6.375 6.375 0 0 1 12.75 0v.109A12.318 12.318 0 0 1 9.374 21c-2.331 0-4.512-.645-6.374-1.766Z" />
          </svg>
        </div>
        <p class="text-sm">暂无账号，点击"添加账号"开始</p>
      </div>
    </div>

    <!-- 分页 -->
    <div v-if="totalPages > 1" class="flex items-center justify-between pt-2">
      <p class="text-sm text-[#8c8475]">共 {{ totalCount }} 个账号</p>
      <div class="flex items-center gap-1">
        <Button
          variant="ghost"
          size="sm"
          :disabled="currentPage <= 1"
          @click="goToPage(currentPage - 1)"
          class="h-8 px-2 text-[#8c8475] hover:text-[#29261e] hover:bg-[#f0ebe4] disabled:opacity-40"
        >
          上一页
        </Button>
        <Button
          v-for="p in visiblePages"
          :key="p"
          variant="ghost"
          size="sm"
          @click="goToPage(p)"
          class="h-8 w-8 p-0 text-sm"
          :class="p === currentPage
            ? 'bg-[#c4704f] text-white hover:bg-[#b5623f]'
            : 'text-[#8c8475] hover:text-[#29261e] hover:bg-[#f0ebe4]'"
        >
          {{ p }}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          :disabled="currentPage >= totalPages"
          @click="goToPage(currentPage + 1)"
          class="h-8 px-2 text-[#8c8475] hover:text-[#29261e] hover:bg-[#f0ebe4] disabled:opacity-40"
        >
          下一页
        </Button>
      </div>
    </div>

    <!-- 新建/编辑账号弹窗 -->
    <Dialog v-model:open="showForm">
      <DialogContent class="bg-white border-[#e8e2d9] rounded-2xl text-[#29261e] sm:max-w-md">
        <DialogHeader>
          <DialogTitle class="text-[#29261e] text-lg">{{ editing ? '编辑账号' : '添加账号' }}</DialogTitle>
          <DialogDescription class="text-[#8c8475]">
            {{ editing ? '修改账号信息，Token 留空表示不更改' : '填写新账号信息' }}
          </DialogDescription>
        </DialogHeader>

        <form @submit.prevent="save" class="space-y-4 mt-2">
          <div class="space-y-2">
            <Label class="text-[#5c5647] text-sm">备注名（选填）</Label>
            <Input
              v-model="form.name"
              class="bg-[#f9f6f1] border-[#e8e2d9] text-[#29261e] placeholder-[#b5b0a6] focus:border-[#c4704f] focus:ring-[#c4704f]/20"
            />
          </div>
          <div class="space-y-2">
            <Label class="text-[#5c5647] text-sm">邮箱 <span class="text-red-500">*</span></Label>
            <Input
              v-model="form.email"
              required
              class="bg-[#f9f6f1] border-[#e8e2d9] text-[#29261e] placeholder-[#b5b0a6] focus:border-[#c4704f] focus:ring-[#c4704f]/20"
            />
          </div>
          <div class="space-y-2">
            <Label class="text-[#5c5647] text-sm">
              Setup Token (sk-ant-oat01-...) <span v-if="!editing" class="text-red-500">*</span>
            </Label>
            <Textarea
              v-model="form.token"
              :required="!editing"
              :rows="3"
              :placeholder="editing ? '留空保持不变' : ''"
              class="bg-[#f9f6f1] border-[#e8e2d9] text-[#29261e] placeholder-[#b5b0a6] focus:border-[#c4704f] focus:ring-[#c4704f]/20 font-mono text-sm"
            />
          </div>
          <div class="space-y-2">
            <Label class="text-[#5c5647] text-sm">代理地址（选填）</Label>
            <Input
              v-model="form.proxy_url"
              placeholder="http:// 或 socks5://"
              class="bg-[#f9f6f1] border-[#e8e2d9] text-[#29261e] placeholder-[#b5b0a6] focus:border-[#c4704f] focus:ring-[#c4704f]/20"
            />
          </div>
          <div class="space-y-2">
            <Label class="text-[#5c5647] text-sm">Billing 模式</Label>
            <div class="flex gap-2">
              <button
                type="button"
                @click="form.billing_mode = 'strip'"
                class="flex-1 px-3 py-2 rounded-lg text-sm font-medium border transition-all duration-200"
                :class="form.billing_mode === 'strip'
                  ? 'bg-[#c4704f]/10 border-[#c4704f] text-[#c4704f]'
                  : 'bg-[#f9f6f1] border-[#e8e2d9] text-[#8c8475] hover:border-[#c4704f]/40'"
              >
                清除 (Strip)
              </button>
              <button
                type="button"
                @click="form.billing_mode = 'rewrite'"
                class="flex-1 px-3 py-2 rounded-lg text-sm font-medium border transition-all duration-200"
                :class="form.billing_mode === 'rewrite'
                  ? 'bg-amber-50 border-amber-400 text-amber-600'
                  : 'bg-[#f9f6f1] border-[#e8e2d9] text-[#8c8475] hover:border-amber-300'"
              >
                重写 (Rewrite)
              </button>
            </div>
          </div>
          <div class="flex gap-4">
            <div class="flex-1 space-y-2">
              <Label class="text-[#5c5647] text-sm">并发数</Label>
              <Input
                v-model.number="form.concurrency"
                type="number"
                min="1"
                class="bg-[#f9f6f1] border-[#e8e2d9] text-[#29261e] focus:border-[#c4704f] focus:ring-[#c4704f]/20"
              />
            </div>
            <div class="flex-1 space-y-2">
              <Label class="text-[#5c5647] text-sm">优先级</Label>
              <Input
                v-model.number="form.priority"
                type="number"
                min="1"
                class="bg-[#f9f6f1] border-[#e8e2d9] text-[#29261e] focus:border-[#c4704f] focus:ring-[#c4704f]/20"
              />
            </div>
          </div>

          <DialogFooter class="gap-2 pt-2">
            <Button
              type="button"
              variant="ghost"
              @click="showForm = false"
              class="text-[#8c8475] hover:text-[#29261e] hover:bg-[#f0ebe4]"
            >
              取消
            </Button>
            <Button
              type="submit"
              class="bg-[#c4704f] hover:bg-[#b5623f] text-white font-medium rounded-xl transition-all duration-200"
            >
              保存
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <!-- 删除确认弹窗 -->
    <Dialog v-model:open="showDeleteConfirm">
      <DialogContent class="bg-white border-[#e8e2d9] rounded-2xl text-[#29261e] sm:max-w-sm">
        <DialogHeader>
          <DialogTitle class="text-[#29261e]">确认删除</DialogTitle>
          <DialogDescription class="text-[#8c8475]">
            此操作不可撤销，确认要删除此账号吗？
          </DialogDescription>
        </DialogHeader>
        <DialogFooter class="gap-2 pt-4">
          <Button
            variant="ghost"
            @click="showDeleteConfirm = false"
            class="text-[#8c8475] hover:text-[#29261e] hover:bg-[#f0ebe4]"
          >
            取消
          </Button>
          <Button
            @click="executeDelete"
            class="bg-red-500 hover:bg-red-600 text-white font-medium rounded-xl transition-all duration-200"
          >
            删除
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
