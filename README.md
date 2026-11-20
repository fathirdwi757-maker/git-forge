# git-forge

[![make.fun entry](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/fathirdwi757-maker/git-forge/rank.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/fathirdwi757-maker/git-forge/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A GitHub-compatible git forge in a single dependency-free Node process. One in-memory store backs four surfaces: git smart HTTP (protocol v2 ls-refs and fetch with shallow/deepen clones, receive-pack pushes with fast-forward rules), the REST v3 API (repositories, branches, commits, contents, labels, issues, pull requests with three-way merges), GraphQL v4 (connections, node lookups, mutations), and an MCP endpoint exposing the canonical GitHub tool set — a change made on any surface is visible on all the others.

## Run it

```sh
node --experimental-strip-types main.ts
```

<sub>Entered on [make.fun](https://make.fun/?ref=7k4mkbbj&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
