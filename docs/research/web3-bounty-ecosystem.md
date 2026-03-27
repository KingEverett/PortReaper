# Web3 Bug Bounty Ecosystem Research

*Compiled 2026-03-25 from deep research across 4 parallel agents*

## Platforms & Economics

### Major Platforms
- **Immunefi**: Largest. $110M+ paid, 45K researchers, 400+ programs. Critical payouts = 10% of funds at risk ($50K-$15M). Solodit MCP server for AI integration.
- **Code4rena**: Competitive audit contests. $30K-$500K pools. Payout formula rewards unique findings. 0% platform cut (public goods model 2025+).
- **Sherlock**: Fixed senior pay + competitive pool. Stakers can be slashed 50% if audited protocol is exploited. Only High/Medium rewarded.
- **Hats Finance**: Fully decentralized, on-chain, no KYC.
- **Cantina (Spearbit)**: AI-native, curated researcher network. $5M Coinbase bounty.

### Payout Data
- Bridge bugs: $10M+ (Wormhole)
- L2/rollup bugs: $2M+ (Optimism)
- Core DeFi: $50K-$1M
- Median across all: ~$2K
- Smart contract bugs = 77.5% of all Immunefi payouts
- Power law: top 30 hunters are millionaires, most earn $0

## Key Data Sources
- **Solodit**: 50K+ findings, free API, MCP server built for AI agents — primary data source
- **Code4rena/Sherlock GitHub repos**: Full audit reports in markdown
- **DefiHackLabs (SunWeb3Sec)**: Foundry reproductions of real exploits
- **DeFi Llama API**: TVL data for target prioritization
- **Rekt.news**: Exploit database and post-mortems

## Vulnerability Classes (by payout tier)

### Tier 1 ($1M-$10M+)
- Bridge/cross-chain verification bypasses
- L2 consensus/validation bugs
- Infinite/arbitrary token minting
- Direct fund theft from core contracts

### Tier 2 ($100K-$1M)
- Oracle manipulation → fund theft
- Reentrancy in core contracts
- Governance takeover
- Flash loan + economic exploit chains
- ZK circuit soundness bugs

### Tier 3 ($10K-$100K)
- Access control in non-core functions
- Precision/rounding errors → gradual drain
- Signature replay attacks
- ERC-20 integration issues (fee-on-transfer, rebasing)

## Security Tooling

### Smart Contract Analysis
- **Slither**: Static analysis, 90+ detectors, Python API for custom detectors
- **Aderyn (Cyfrin)**: Rust-based, fast, has MCP server for AI integration
- **Mythril**: Symbolic execution, bytecode analysis
- **Foundry**: Fuzz testing, invariant testing, fork testing
- **Halmos**: Symbolic testing on Foundry tests
- **Certora**: Formal verification (commercial)

### AI Auditing (Current State)
- ~30% recall standalone (Nethermind data)
- Best as pair auditor, not replacement
- **Hound** (scabench-org): Most sophisticated open-source AI auditor, knowledge-graph-based
- **forefy/.context**: Prompt framework turning coding agents into auditors
- **EVMbench**: 117 vulns benchmark — agents detect 65% but can't reliably exploit

### Monitoring
- Forta Network (decentralized detection bots)
- OpenZeppelin Defender (alerts + automated response)
- Tenderly (simulation, debugging, fork testing)

## Top Hunter Methodology Patterns
- Specialize in one vuln class, not generalist
- Spend 2-3 weeks deep-diving per target
- Pick targets by: TVL × bounty size × code freshness ÷ competition
- Study disclosed reports for same protocol category before hunting
- Use Sherlock judging contests as feedback loop

## Gap Analysis
**No end-to-end automated bounty hunting pipeline exists.** Karl (2019, nmap + Mythril) is the closest. The opportunity is in orchestration: monitor programs → pull scope → multi-tool scan → AI triage → prioritized findings.
