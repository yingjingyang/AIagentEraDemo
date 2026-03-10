# Smart Contract Vulnerability Report Template

> Copy the following structure into the final deliverable. Enrich each section with the actual scope, PoCs, and remediation guidance.

## 1. Executive Summary
- Project / Codebase:
- Blockchain: EVM / Solana
- Scope: Single contract / repository
- Audit Window:
- Tooling (list tool names/versions only; keep methodology details in Section 2):
- Summary: Identified **X** issues (Critical **a** / High **b** / Medium **c** / Low **d** / Informational **e**)

## 2. Methodology
- Static analysis: tools & commands executed
- Dynamic/fuzz testing: tooling, scenarios, coverage
- Manual review focus areas: permissions, fund flows, state machines

## 3. Findings (ordered by severity)

### [Severity] Finding Title
- **Contract / Instruction**:
- **Description**:
- **Impact**:
- **Preconditions**:
- **Exploitability**: Low / Medium / High
- **Status**: Unfixed / Fixed (pending validation) / Verified fixed

#### 3.1 Reproduction / Exploit Code
- **EVM**: Provide Foundry/Hardhat tests or scripts (`forge test --match-test ...`).
- **Solana**: Provide Anchor/TypeScript tests with the transaction sequence.
- Use fenced code blocks (```language) for critical snippets.

#### 3.2 Remediation Guidance
- Explain the root cause (e.g., checks-effects-interactions violations, access control gaps, arithmetic errors).
- Provide reference implementations or code diffs where possible.
- If governance upgrades are required, document the steps.

## 4. Additional Observations
- Gas optimization, style notes, documentation suggestions.

## 5. Appendix
- Command logs
- Test output summaries
- Toolchain versions (solc/anchor-cli/etc.)
