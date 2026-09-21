# 证书链检查站（离线策略验证）

面向内网服务的离线证书链策略检查站。输入一组 PEM 证书和一个验证时刻，枚举所有可能的证书链，
选择满足策略的链，并逐证书解释其余链为何失败。

## 特性

- **完全离线**：不访问操作系统信任库，不联网获取中间证书；trust anchor、用途、名称与算法策略全部由检查会话显式提供，并按版本保存（修改 anchor/策略自动生成新版本，历史检查按当时策略重放）。
- **链构建**：处理同 subject 的多个中间证书、交叉签发、自签根不在输入尾部、无序输入；自签根只有显式作为 anchor 才被信任。
- **验证维度**：签名、时间有效性（等于 notBefore 可用、等于 notAfter 过期，全部 UTC）、basic constraints、path length、key usage、extended key usage、名称约束（DNS/IP/directoryName）、主机名匹配（最左通配符）。
- **策略**：算法可按指定日期退役（如 SHA1、RSA），可配置最小密钥长度；按验证时刻选择当时生效的策略版本。
- **选链**：多条合格链按 最短链 → anchor 优先级 → 稳定指纹 排序。
- **解析容错**：单个坏 PEM 块不影响其他块；私钥块被拒绝且绝不进入导出；重复证书按 DER SHA-256 指纹去重；最终响应列全错误。
- **导出**：可导出不含私钥的证明 JSON（`containsPrivateKeys=false`）。

## 运行

```bash
./gradlew classes          # 准备阶段
./gradlew test             # 测试（即时生成测试 PKI）
./gradlew run --args='--host 127.0.0.1 --port 5239'
# 打开 http://127.0.0.1:5239 → “证书链检查站”
```

## API

- `POST /api/check` — 检查。请求体：`{bundlePem, anchors:[{label,pem}], hostname, purpose, verifyAt, policy:{versions:[...]}, sessionId?}`
- `POST /api/proof` — 导出证明 JSON（无私钥）
- `GET /api/session/{id}/{version}` — 查询会话历史版本快照
- `GET /api/health` — 健康检查

策略版本示例：

```json
{"versions":[{"version":"v2026","effectiveAt":"1970-01-01T00:00:00Z",
  "minKeyBitsRsa":2048,"minKeyBitsEc":224,
  "retiredAlgorithms":{"SHA1":"2017-01-01T00:00:00Z"}}]}
```
