# 证书链检查站（Offline Cert-Chain Policy Checkpoint）

一个**完全离线**的证书链构建与策略验证站。所有 trust anchor、用途、主机名与算法策略都由
一次检查会话显式提供，并带版本持久化；**不读取操作系统信任库，也不联网获取中间证书**。

## 运行

需要 JDK 17；Gradle Wrapper 已随仓库提交。

```bash
./gradlew classes                                   # 准备阶段
./gradlew test                                      # 全部测试（即时生成测试 PKI）
./gradlew run --args='--host 127.0.0.1 --port 5239' # 启动 Web
```

打开 http://127.0.0.1:5239 ，页面标题为“**证书链检查站**”。

其它参数：`--data <dir>`（会话存储目录，默认 `certstation-data/`）、`--web <dir>`（静态页面目录）。

## 能力

- **PEM 解析**：逐块容错，损坏块/不支持的标签/私钥块被跳过并在最终响应中列全错误；
  重复证书按 DER `sha256` 指纹去重；输入顺序任意。
- **链枚举**：处理同 subject 多个中间证书、交叉签发（同一中间密钥被多根签发）、
  自签根不在输入尾部等情况；按 DN + AKI/SKI 连边，DFS + 指纹环检测枚举所有候选；
  未到达显式 anchor 的链标记为“不完整”。
- **链验证**（失败定位到具体证书下标、指纹与约束 OID）：
  - 签名正确性（逐级用签发者公钥验签）
  - 时间有效性：时刻**等于 notBefore 可用，等于 notAfter 已过期**，全部 UTC
  - basic constraints（叶非 CA、中间必须 cA）
  - path length（定位到声明 pathLenConstraint 的 CA）
  - key usage（digitalSignature / keyCertSign）
  - extended key usage（serverAuth / clientAuth / anyEKU，含中间 EKU 约束）
  - name constraints（permitted/excluded，DNS 子树与 IP CIDR）
  - 主机名匹配（SAN 优先、CN 回退、单层通配符、IPv4/IPv6）
  - 算法/密钥策略（见下）
- **策略版本化与历史重放**：策略条目带 `effectiveAt`；在某个历史时刻检查时，
  只有生效时间不晚于该时刻的条目参与判定。支持“退役签名算法（MD5/SHA1/…）”
  与“最小密钥长度（RSA/EC/…）”两类。
- **稳定选链**：合格链按「链长度 → anchor 优先级 → 链指纹」排序，结果可复现。
- **证明 JSON**：导出选中链（含每证 PEM）、其余链失败原因、活跃策略、anchor 摘要、
  解析错误与去重计数，声明 `containsPrivateKey:false`，不含任何私钥材料。
- **会话持久化**：anchor 增删与策略变更递增 revision 并记录历史；每次检查落盘到
  `certstation-data/checks/`。

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/session` | 会话版本、anchor、策略、历史 |
| POST/DELETE | `/api/anchors` | 加入/删除显式信任锚（body 或 `?id=`） |
| POST/DELETE | `/api/policy` | 加入/删除策略条目 |
| POST | `/api/check` | 检查并返回全部候选链 + 逐证解释 + 输入 PEM 回显 |
| POST | `/api/proof` | 同上，但返回不含私钥的证明 JSON |

## 结构

- `Der.kt`：仅依赖 JDK 的最小 DER 解析（SKI/AKI/NameConstraints 等扩展）
- `CertModel.kt` / `Pem.kt`：证书信息模型与 PEM 解析去重
- `ChainBuilder.kt`：候选链枚举
- `Validator.kt` / `Policy.kt` / `Hostname.kt`：策略与匹配规则
- `Session.kt` / `Service.kt` / `HttpServer.kt` / `Main.kt`：会话、编排与 Web
- `src/test/.../TestPki.kt`：用 BouncyCastle **即时生成**测试 PKI（BC 仅用于测试）

测试覆盖：交叉签发、同名中间、名称约束、path length、KU/EKU、算法退役与历史重放、
时间端点、无序输入、重复块、稳定选链、证明无私钥和完整 HTTP 流程。
