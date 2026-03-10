---
name: multichain-contract-vuln
description: "安全审计与漏洞报告技能：针对单个或批量 EVM / Solana 合约执行静态+动态分析，整理漏洞报告并生成对应 PoC 攻击代码与修复建议。"
---

## 何时使用
- 用户要求审计单个 Solidity/Vyper 合约或 Solana Anchor/Rust 程序。
- 用户提供一个包含多份合约的目录并希望批量扫描。
- 需要输出结构化漏洞报告、PoC 攻击脚本/测试和修复建议。

## 快速指引
1. **确认范围**：链别（EVM / Solana）、合约路径或目录、编译/测试框架。
   - 仅有链上地址？先按 [On-chain Source Retrieval](references/onchain-fetch.md) 抓取源码：
     - EVM：使用 `scripts/run_cli.py --evm-address <addr> --network mainnet --chain evm`（需 `ETHERSCAN_API_KEY`，否则回退 Sourcify）。
     - Solana：`solana program dump` 获取 `.so`，`anchor idl fetch` 拉取 IDL，或联系项目索取源码。
2. **选择检查清单**：
   - [EVM Checklist](references/evm-checklist.md) 适用于 Solidity/Vyper。
   - [Solana Checklist](references/solana-checklist.md) 适用于 Anchor/Rust 程序。
3. **执行分析**：按照对应清单完成工具运行、手工审查和 PoC 编写。
4. **输出报告**：遵循 [Report Template](references/report-template.md) 填写审计结果，逐个漏洞列出 PoC 与修复建议；执行摘要仅展示项目、链别、范围、时间、工具与问题统计，不在此描述方法，方法细节统一写在第 2 节《方法论》；除非用户另行指定，整份报告（标题、描述、漏洞详情）默认使用英文，可在需要时附中文摘要作为补充。

## 流程细节

### 链上源码获取
- **EVM**：`scripts/run_cli.py --evm-address 0x... --network <mainnet|sepolia|goerli> --chain evm`。脚本会：
  1. 读取 `ETHERSCAN_API_KEY`（或 `--etherscan-api-key`），调用 Etherscan API 下载验证源码；
  2. 若无 API Key，则尝试从 Sourcify full_match 仓库拉取；
  3. 将源码写入临时目录（打印路径），随后继续执行 Slither 分析。
- **Solana**：
  1. `solana program dump <PROGRAM_ID> tmp/<id>.so`，并用 `solana program show` 获取 ProgramData；
  2. `anchor idl fetch <PROGRAM_ID> -o idl.json`；
  3. 若仍缺源码，在报告中声明“基于 IDL/BPF 反编译”。

### 1. 单合约分析
- **EVM**
  - 准备：确认 `solc` 版本，安装 `slither`, `mythril`, `foundry`。
  - 命令示例：
    - `slither contracts/MyToken.sol --print human-summary`
    - `myth a contracts/MyToken.sol --execution-timeout 90`
    - `forge test --match-contract ExploitMyToken`
  - PoC：在 `test/Exploit.t.sol` 中模拟攻击者，确保测试断言展示资金损失或权限提升。
- **Solana**
  - 准备：`anchor build && anchor test`，确认 `solana-test-validator` 运行。
  - 静态检查：`cargo clippy --all -- -D warnings`、`cargo audit`。
  - PoC：在 `tests/*.ts`（TypeScript）或 `tests/*.rs`（Rust）中构造恶意交易序列。

### 2. 目录批量分析
- 遍历目录：EVM 项目运行 `slither . --json reports/slither.json`；Solana 项目遍历 `programs/*` 运行 `anchor test`。
- 将所有发现整理为 `CSV/Markdown` 表，字段包含 `Contract/Program | Severity | Title | PoC | Fix Status`。
- 对每个发现补充 PoC：
  - EVM：Foundry/Hardhat 测试或脚本（`cast send`）。
  - Solana：Anchor 测试或 `@solana/web3.js` 脚本。

### 3. 漏洞报告
- 复制 [Report Template](references/report-template.md) 填写。
- 每个漏洞需要：
  - **描述**：根因与影响。
  - **攻击代码**：可执行的测试或脚本片段，标注依赖和命令。
  - **修复建议**：代码级修补、访问控制或架构建议。
- 附录包含：命令行输出、工具版本、测试日志。

## 产出要求
- **始终输出 Markdown 报告**：将审计结论写入 `reports/<scope>-multichain-audit.md`（若文件夹不存在先创建）。结构遵循 [Report Template](references/report-template.md)。如用户额外要求 PDF，可在 Markdown 基础上导出。
- **在最终回复中明确报告绝对路径**，如 `/Users/.../reports/<scope>-multichain-audit.md`，便于用户定位。
- 若用户提供仓库：在 `reports/` 目录下保存工具输出与 PoC 脚本，方便复查，并在报告附录中引用**绝对路径**（例如 `/Users/.../repos/.../FeiProtocol.attack.sol`）。
- 对每个漏洞明确当前状态：`Unfixed / Pending Review / Fixed`。

## 提示
- 若分析需要主网数据，使用 RPC fork（EVM）或 `solana-test-validator --clone`（Solana）。
- 对高危漏洞优先提供最小可运行 PoC，必要时给出 gas/费用估算。
- 如果工具输出为英文，可保留英文并补充中文总结，确保审计方易读。
