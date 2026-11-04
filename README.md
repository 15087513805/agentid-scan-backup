# agentid-scan-backup — GitHub Actions 发现层兜底（免费极致版）

小云本地常驻服务（registry_service / factory_service）之外的**独立第二发现层**：
寄住在 GitHub Actions 上，小云的 VM 被替换/宕机时照常每 5 分钟扫一轮，
新命中写入 `feed.jsonl`，小云恢复后按 feed 补消费，一块不漏。

## 为什么必须公开仓库
- 公开仓库：标准 runner 分钟**无限免费用** → 可以跑满 */5 节奏 + 大窗口。
- 私有仓库：每月只有 2,000 分钟，本节奏几天就烧完。
- 仓库内容只有公开链上数据 + 扫描脚本（无密钥、无钱包信息），公开无实质损失；
  我们的优势在分诊速度，不在这份原始数据。

## 每轮做什么
1. `factory_scan.py`：增量扫 four.meme / flap / gang.fun 建币事件（水位线 `factory-scan-state.json`）。
2. `registry_scan.py --max-blocks 3000`：增量扫新部署合约字节码是否引用 Agent ID 注册表（水位线 `registry-scan-state.json`）。
3. `collect.py`：按完整 CA 与历史 feed 去重，新项逐条追加 `feed.jsonl`，并免费调 GoPlus 补蜜罐/开源/税字段。
4. 状态 + feed 一起 commit 回仓库（bot 提交也保活仓库，避免 60 天无活动停用定时任务）。

## 消费端（小云侧）
- 本地 hook 每 5 分钟拉 `feed.jsonl` 尾部，新行唤醒主会话分诊；
- 监控轮次的 3b/3c 与本地服务结果按 CA 对账，Actions feed 只作兜底与交叉验证，不替代本地实时层。

## 极限与降级
- GitHub 定时任务有分钟级排队延迟（高峰可达 10–20 分钟）→ 只做发现兜底，不做秒级热路径。
- rpc-bsc.48.club（getLogs 唯一免费可用端点）若失效，factory 步会报错并保留旧水位，下一轮自动续扫，不跳块。
- 若 GitHub 收紧免费政策：降级顺序 = 先拉长间隔到 */15，再迁回本地常驻服务（主层一直在）。
