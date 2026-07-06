# 高级用法

本页用于承载兼容性和自动化细节，避免主 README 继续变长。

## 动作帮助

使用动作级帮助可以看到更短、更相关的参数列表：

```bash
dmsa-forge add -h
dmsa-forge search -h
dmsa-forge add --help-advanced
```

默认动作帮助刻意保持简洁。对动作使用 `--help-advanced` 可以查看认证参数、兼容别名、验证重试控制和高级工作流参数。

## 自动推断默认值

dMSA Forge 保持运行状态都体现在命令行中，不加载项目配置文件。常用值会从显式命令参数推断：

- `DOMAIN/user` 会推断 `--scope-domain`、`--scope-base-dn` 和 `--base-dn`。
- 如果 `DOMAIN/user` 不是 DNS FQDN，合法的 `--target-ou` DN 可以反向推断 domain scope 和 base DN。
- 显式传入合法 `--scope-base-dn` 且未传 `--base-dn` 时，会用 scope base DN 作为默认 base DN。
- `--method` 默认是 `LDAP`，`--port` 默认是 `389`。
- 未显式传 `--method` 和 `--port` 时，执行阶段会先尝试 LDAP/389；如果连接失败，才会继续尝试 LDAPS/636。
- 单独传 `--port 636` 会推断 `LDAPS`；单独传 `--port 389` 会推断 `LDAP`。
- `--method LDAPS` 默认使用端口 `636`；只要显式传了任一连接参数，就不会再做 method/port 试探。
- 对真实 `add` 执行来说，`--target-account` 必填，它决定写入 `msDS-ManagedAccountPrecededByLink` 的账号 DN。
- 设置 `--dmsa-name` 后，`--dns-hostname` 默认是 `<dmsa-name>.<account-domain>`。
- 对真实 `add` 执行来说，`--principals-allowed` 必填，它决定写入 `msDS-GroupMSAMembership` 的 SID。
- 自动 DC IP 解析只使用本地 DNS，不会 ping 或探测；特殊用途地址会在进入 Kerberos 命令建议前被拒绝。
- 对 `search` 来说，`--target-ou` 用于缩小 OU 搜索基准，DC 前置检查是 best-effort。

显式参数始终覆盖推断值。需要指定 DC 主机名时使用 `--dc-host`；只有 DNS 或路由需要 IP 覆盖时才使用 `--dc-ip`。推断决策和连接候选都会写入终端输出与结构化报告。

目标账号名和 `--principals-allowed` 名称解析会优先使用精确的 `sAMAccountName`、UPN、CN 或 name 匹配。如果 LDAP 返回多个可用候选且无法精确判定，执行会失败关闭，并提示使用完整 DN 或 SID。

## 本地 Wrapper

生成的 `next_steps` 命令会继承检测到的 proxychains wrapper；如果本次执行是 `proxychains -f chain1080.conf -q dmsa-forge ...`，后续建议命令也会使用同样前缀。如果本地 wrapper 无法推断，可以显式传入 `--next-step-prefix 'proxychains -f chain1080.conf -q'`。

## Plan 快捷入口

`dmsa-forge plan ACTION ...` 等价于 `dmsa-forge ACTION ... --dry-run`。

```bash
dmsa-forge plan add eighteen.htb/user --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen --target-account ACCOUNT_TO_SUCCEED --principals-allowed SID_OR_NAME
```

它使用和普通 dry-run 相同的校验与报告格式。

## Profiles

- `safe`：启用默认脱敏 dry-run，并尽可能从账号域名推导 scope。
- `report`：启用 JSON 报告并隐藏 banner。
- `ci`：启用 JSON、quiet 输出和 no-banner。

命令行显式参数优先于 profile 默认值。Profile 是轻量本地预设，不是配置文件。

## 报告 Schema

结构化 JSON 报告包含：

- `schema_version`：当前为 `1.0`；
- `operation_id`：本地运行标识，便于复盘关联；
- `mode`：`dry_run` 或 `execute`；
- `connection`、`scope`、`inputs`、`controls` 和 `ldap_operations`；
- `result`：命令特定结果。

使用 `--output-only --output FILE` 可以仅写入 JSON 文件，文件权限为 `0600`。

## 排查

LDAP 动作失败时，结构化输出会尽量保留本地决策点。优先查看 `result.error_code`、`result.error`，以及存在时的 `result.ldap_result` 或 `result.verification_errors`。

常见本地校验会在 LDAP 执行前拦截：

- `--dmsa-name` 必须是 DNS-safe label，例如 `redpen` 或 `dMSA-REDPEN01`；
- `--dns-hostname` 必须是完整 DNS hostname，例如 `redpen.eighteen.htb`；
- 执行类 workflow 中，`--scope-domain` 和 `--scope-base-dn` 必须一致。

## 兼容性

`--lean` 是更推荐的短预设，用于更轻量的本地输出和搜索默认值。`--low-noise` 继续作为兼容别名保留。

旧的 `modify` workflow 已移除。请使用 `delete`、`add` 和 `verify`；旧 `modify` 命令会返回迁移错误，不会进入 LDAP。
