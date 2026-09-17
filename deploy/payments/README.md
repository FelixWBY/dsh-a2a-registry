# 订单与支付接入

## 已实现的通用核心

- `RegistryBillingProvider` 定义支付提供方边界；浏览器只提交方案标识和幂等键，金额、币种、周期和支付提供方由服务端方案快照确定。
- PostgreSQL SaaS 控制面 schema v3 已加入 `billing_orders` 和 `billing_provider_events`。两表按组织隔离并启用强制行级安全，在线账号只拥有最小业务权限。
- `billing_orders` 以 `organization_id + idempotency_key` 唯一约束和请求摘要保证幂等：相同请求返回同一订单，同键更换方案或价格会冲突。订单只保存支付提供方结账标识和到期时间，不保存托管结账地址。
- 订单状态覆盖 `creating`、`checkout-pending`、`failed`、`expired`、`paid`、`disputed` 和 `refunded`，并按该顺序只允许单调推进；普通付款事件不能清除争议，退款也不会被后到事件覆盖。只有支付适配器验签后提交的 `checkout-paid` 事件可以确认付款时间；浏览器跳转不能标记付款。
- `billing_provider_events` 以 `provider + event_id` 唯一约束防止事件重放，并保存事件类型、载荷摘要、发生时间和接收时间。相同事件可安全重试，内容冲突的重放会失败；每个已验签事件都会留存，低优先级、晚到或相同时间戳事件只补齐确定性的时间投影，不会把订单状态倒退。
- Registry 已固定提供 `POST /registry-api/v1/billing/webhooks/:provider`。该入口不使用浏览器 OIDC，会先执行现有来源地址限流，再按 `maxBillingWebhookBytes` 有界读取未经解码的原始字节，并把小写且保留重复值的只读请求头交给部署适配器。查询参数、错误方法、未知或未启用的提供方、空体、不完整体和超限体均拒绝。
- 支付适配器必须先校验签名、商户身份和事件时间，只返回规范事件。Registry 强制使用路径对应的提供方名称、自行计算原始正文 SHA-256，不保存原始正文；只有 `applyVerifiedBillingEvent` 事务成功后才返回 Registry 固定生成的确认响应：Stripe 为 204 空体，支付宝为 200 `text/plain` 的 `success`。适配器不能借确认响应回显请求或秘密；相同事件和相同原始正文可安全重试，数据库失败不会误答成功。
- 支付生命周期默认关闭。生产启用时必须在同一最终 overlay 中同时使用固定条目标识 `registry-billing-provider`、设置 `saas.billingProvider: true`，并把 `registryBillingProvider` 加入 `registry-runtime.inject`；三项缺一会被生产配置图门禁拒绝，显式开关关闭时即使意外出现服务也不会暴露方案、结账或 Webhook 能力。
- 组织所有者可以在设置页查看方案、创建第三方托管结账并查看最近订单；Admin 和 Member 不能操作组织计费。列表有固定上限，不提供无限查询。
- 默认不装载任何支付提供方。此时状态明确显示“未配置”，方案、订单和结账接口在完成 Owner 鉴权后返回 HTTP 501，不创建假订单，也不产生真实交易。

## 真实适配器仍需实现

1. 分别实现 Stripe 和支付宝适配器；方案由服务端白名单映射到 Stripe Price 或支付宝商品，不接受浏览器提交金额、币种、手续费或商户账号。
2. Stripe 使用 Checkout Sessions；订阅使用 Billing + Checkout，不自行循环调用 PaymentIntent。支付宝使用已签约产品对应的官方托管支付流程。
3. 只把第三方托管的 HTTPS 结账地址返回给当前请求。支付成功跳转只用于展示，不能更新订单状态。
4. 分别实现 `RegistryBillingProvider.verifyWebhook`：Stripe 按官方签名和时间窗校验原始字节，支付宝按所签约产品的官方异步通知规则校验签名、应用／商户身份与通知时间。固定入口已经存在，但仓库仍没有任何真实商户验签代码或密钥。Stripe 与支付宝不能互相推断成功。
5. 为退款、争议、订阅取消和失败续费补齐各商户产品的规范事件映射；不能绕过现有事务、防重放和单调状态投影。托管结账成功跳转只用于展示，永远不能把订单改为已付款。
6. 平台手续费只能来自商户后台或服务端固定配置，不能信任客户端比例；若使用 Stripe Connect 代收分账，必须另行完成平台合规与账户模型。

## 仍需部署者提供

- Stripe 商户、产品/Price、Webhook endpoint secret；若要代收分账，需另行完成 Connect 平台合规与账户设计。
- 支付宝开放平台应用、应用私钥、安全保存的支付宝公钥/证书、回调域名和签约产品。
- 价格、税费、退款、隐私、用户协议与发票规则。
- 公网 HTTPS 域名和独立秘密管理。不要把 `.pem`、API key 或 populated `.env` 提交到仓库。
- 使用真实但受控的金额完成结账、验签回调、重复回调、退款和争议演练，并保存不含支付敏感数据的验收证据。

缺少以上资料时，正确状态就是保持支付关闭；这不会阻止组织、Harness 绑定、披露和 A2A 文本请求 MVP 上线验证。
