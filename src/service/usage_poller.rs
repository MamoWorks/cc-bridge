use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::model::account::{AccountAuthType, AccountStatus};
use crate::service::account::AccountService;

/// 账户间隔,避免瞬间打爆 Anthropic usage 端点。
const PER_ACCOUNT_GAP: Duration = Duration::from_millis(500);

/// 后台用量轮询服务（活动驱动）：
/// - 空闲态：不发起任何 `/api/oauth/usage` 调用，等待 `/v1/messages` 业务活动
/// - 首次活动到来 → 立即拉一遍所有 OAuth 账号的用量，进入活跃态
/// - 活跃态：每 `interval` tick 一次；若上一窗口内仍有业务活动则继续 tick；
///   若一个完整窗口内没有任何活动 → 回到空闲态停止轮询
///
/// 这样部署在 24h 长跑的实例上，没人用的时候完全不打上游 usage 端点。
pub struct UsagePollerService {
    account_svc: Arc<AccountService>,
    interval: Duration,
}

impl UsagePollerService {
    pub fn new(account_svc: Arc<AccountService>, interval: Duration) -> Self {
        Self {
            account_svc,
            interval,
        }
    }

    /// 启动后台循环。应在 main 中 tokio::spawn 调用。
    pub async fn run(self: Arc<Self>) {
        info!(
            "usage poller: started in idle mode (interval={:?}); waits for /v1/messages activity",
            self.interval
        );
        loop {
            // ===== 空闲态：等待第一次 /v1/messages 活动 =====
            loop {
                if self.account_svc.take_messages_activity() {
                    break;
                }
                self.account_svc.wait_for_messages_activity().await;
            }

            info!("usage poller: activity detected → first poll");
            self.tick().await;

            // ===== 活跃态：每 interval 检查一次活动 =====
            loop {
                sleep(self.interval).await;
                if self.account_svc.take_messages_activity() {
                    info!("usage poller: continued activity → polling");
                    self.tick().await;
                } else {
                    info!(
                        "usage poller: no activity in last {:?} → going idle",
                        self.interval
                    );
                    break; // 回到外层空闲态
                }
            }
        }
    }

    async fn tick(&self) {
        let accounts = match self.account_svc.list_accounts().await {
            Ok(list) => list,
            Err(e) => {
                warn!("usage poller: list accounts failed: {}", e);
                return;
            }
        };

        let targets: Vec<i64> = accounts
            .iter()
            .filter(|a| a.auth_type == AccountAuthType::Oauth && a.status == AccountStatus::Active)
            .map(|a| a.id)
            .collect();

        debug!("usage poller: polling {} oauth accounts", targets.len());

        for id in targets {
            match self.account_svc.refresh_usage(id).await {
                Ok(_) => debug!("usage poller: refreshed account {}", id),
                Err(e) => warn!("usage poller: account {} failed: {}", id, e),
            }
            sleep(PER_ACCOUNT_GAP).await;
        }
    }
}
