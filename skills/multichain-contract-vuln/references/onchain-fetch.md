# On-chain Source Retrieval

## EVM 合约
1. **Etherscan**（推荐）
   - 需要 API Key（设置环境变量 `ETHERSCAN_API_KEY`）。
   - CLI 示例：
     ```bash
     python3 scripts/run_cli.py \
       --evm-address 0x... \
       --network mainnet \
       --chain evm
     ```
   - 自动下载验证源代码到临时目录，并继续执行 Slither 分析。
2. **Sourcify 备选**
   - 若未配置 API Key，CLI 会尝试从 Sourcify `https://repo.sourcify.dev/contracts/full_match/<chainId>/<address>/` 拉取。
   - 也可手动使用 `curl` / `wget` 下载 `metadata.json` + `sources/`。
3. **cast**（只获取字节码）
   - `cast code <address>` 可验证代理/实现，但需配合 Etherscan/Sourcify 获取源码。

## Solana 程序
1. **下载 BPF**
   - `solana program dump <PROGRAM_ID> target/<PROGRAM_ID>.so`
   - 使用 `solana program show --program-data <PROGRAM_ID>` 确认升级权限。
2. **获取 IDL / 源码**
   - 尝试 `anchor idl fetch <PROGRAM_ID> -o idl.json`
   - 查询 Github / RPC 事件，或向项目方索取源码仓库。
3. **反编译（无源码时）**
   - `solana-accountsdb` / `bpf-tools/llvm-objdump` 读取 `.so`，结合 IDL 做黑盒审计。

> 说明：若无法获得完整源码，应在报告中注明“仅基于反编译/IDL，风险评估有限”。