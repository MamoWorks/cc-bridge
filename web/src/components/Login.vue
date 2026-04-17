<script setup lang="ts">
import { ref } from 'vue';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { login } from '../router';

/** 密码输入值 */
const password = ref('');
/** 错误信息 */
const error = ref('');
/** 登录请求加载状态 */
const loading = ref(false);

/** 提交登录表单 */
async function submit() {
  if (!password.value.trim()) {
    error.value = '请输入密码';
    return;
  }
  error.value = '';
  loading.value = true;
  try {
    await login(password.value.trim());
  } catch {
    error.value = '密码错误';
  } finally {
    loading.value = false;
  }
}
</script>

<template>
  <div class="min-h-screen flex items-center justify-center px-4">
    <Card class="w-full max-w-sm bg-white border-[#e8e2d9] rounded-2xl shadow-lg shadow-black/5">
      <CardHeader class="text-center pb-2">
        <div class="flex justify-center mb-2">
          <img src="/favicon.svg" alt="Logo" class="w-10 h-10" />
        </div>
        <CardTitle class="text-2xl font-semibold text-[#29261e] tracking-tight">cc-bridge</CardTitle>
        <p class="text-[#8c8475] text-sm mt-1">管理控制台</p>
      </CardHeader>
      <CardContent>
        <form @submit.prevent="submit" class="space-y-4">
          <div>
            <Input
              v-model="password"
              type="password"
              placeholder="管理员密码"
              class="bg-[#f9f6f1] border-[#e8e2d9] text-[#29261e] placeholder-[#b5b0a6] focus:border-[#c4704f] focus:ring-[#c4704f]/20 h-11"
            />
          </div>
          <p
            v-if="error"
            class="text-red-500 text-sm text-center"
          >
            {{ error }}
          </p>
          <Button
            type="submit"
            :disabled="loading"
            class="w-full bg-[#c4704f] hover:bg-[#b5623f] text-white font-medium h-11 rounded-xl transition-all duration-200 hover:shadow-md"
          >
            {{ loading ? '登录中...' : '登录' }}
          </Button>
        </form>
      </CardContent>
    </Card>
  </div>
</template>
