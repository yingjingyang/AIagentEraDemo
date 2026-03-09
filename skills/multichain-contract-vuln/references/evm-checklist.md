# EVM 合约漏洞分析清单

## 准备
- 安装依赖：`slither`, `mythril`, `foundry` (forge + cast), `echidna`, `python3`, `solc-select`。
- 切换到项目根目录，执行 `forge test` 或 `npm test` 确保编译通过。
- 若合约无 `foundry.toml`/`hardhat.config.ts`，使用 `solc-select use <version>` 并在 `slither.config.json` 中声明。

## 单个合约分析流程
1. **快速画像**
   - 阅读合约注释、权限模型（`Ownable`, `AccessControl` 等）。
   - 列出关键外部函数、状态变量、资金流。
2. **静态扫描**
   - `slither <path/to/Contract.sol>`：记录高/中危结果。
   - 对可疑函数运行 `myth analyze <contract>`（或 `myth -v4 analyze --rpc <rpc>`）。
3. **语义审查**
   - 手动检查重入、算数精度丢失、授权绕过、业务逻辑缺陷。
   - 关注 `delegatecall`, `selfdestruct`, `tx.origin`, `block.timestamp`。
4. **PoC/Exploit**
   - 使用 Foundry：`forge test --match-contract <ExploitTest>`，在 `setUp()` 中部署目标合约并模拟攻击者操作。
   - 若需要 fork 主网：`FOUNDRY_FORK_URL=<rpc> forge test --fork-url $FOUNDRY_FORK_URL`。
5. **修复建议**
   - 参考 OpenZeppelin 安全库；补充访问控制、重入保护（`nonReentrant`）、检查-效应-交互模式。

## 目录批量分析
1. 在项目根执行 `slither . --json reports/slither.json`（必要时 `--filter-paths` 排除依赖）。
2. 执行 `forge coverage` 或 `forge test` 收集 Fuzz 失败点。
3. 对每个合约生成汇总表：合约名 | 风险 | 漏洞描述 | PoC 状态 | 修复状态。
4. 以严重度排序（Critical > High > Medium > Low > Informational）。
