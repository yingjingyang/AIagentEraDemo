# Solana 合约漏洞分析清单

## 工具
- `anchor-cli` / `cargo` / `solana` CLI
- `soteria` 或 `seahorse-analyzer`（若可用）
- `cargo-audit`, `cargo-outdated`
- `anchor test`, `solana-test-validator`

## 单个程序分析
1. **环境初始化**
   - 运行 `anchor build`，确保 BPF 可执行文件生成。
   - `anchor test` 或 `cargo test-bpf` 验证基础用例。
2. **账户模型梳理**
   - 绘制每个指令（IX）的账户要求：`Signer`, `Writable`, `Owner`。
   - 检查 PDA 派生、种子碰撞、防止 `bump` 泄漏。
3. **常见风险点**
   - 未校验 `ctx.accounts.*` 的 owner 或数据长度。
   - 未限制权限导致任意账户可调用（缺少 `require!(ctx.accounts.authority.key == expected, ...)`）。
   - 资金托管账户的 lamports 可被关闭或转移。
   - 时间/价格喂价依赖（oracle 滞后）。
4. **PoC**
   - 使用 Anchor 测试：在 `tests/*.ts` 中编写场景，借助 `ProgramTestContext`；或 Rust 集成测试调用 `solana_program_test`。
   - 若需快速脚本，可使用 `@solana/web3.js` 与 `ts-node`。
5. **修复建议**
   - 强制账户 owner、seeds、`constraint` 宏。
   - 使用 `require_keys_eq`, `assert_eq!`, `checked_sub/add`。
   - 将关键状态放入 PDA 并限制 `close` 权限。

## 目录批量分析
1. 遍历 `programs/*`，对每个 `Cargo.toml` 运行 `cargo clippy -- -D warnings`。
2. `anchor test --skip-build` 对每个程序运行单元 + 集成测试。
3. 收集 `logs/`、`target/deploy/*.so` 的构建信息和 `cargo audit` 输出。
4. 统一输出：程序名 | 指令 | 风险 | PoC 链接 | 修复建议。
