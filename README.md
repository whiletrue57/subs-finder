# subs-finder

定时从 GitHub 搜索最近更新过的 Clash / Mihomo YAML 配置, 输出 top-15 raw URL 清单

## 工作方式

1. GitHub Actions 每周一凌晨自动运行 [.github/workflows/subs-finder.yml](../.github/workflows/subs-finder.yml)
2. [find_clash.py](find_clash.py) 通过 GitHub Code Search 用多组 query 召回候选 (按 `type:` 协议字段、`filename:clash.yaml`、完整 Clash 三件套等)
3. 对每个候选拉最近一次 commit 时间, 过滤超过 30 天未更新的
4. 拉 raw 内容, 用 PyYAML 解析, 校验 `proxies` 是合法 list 且至少 5 个含 `type/server/port` 的节点
5. 按 commit 时间倒序取前 15, 写到 [output/clash-latest.txt](output/clash-latest.txt) 和 `clash-latest.json`
6. 有变化就自动 commit 回 main


```yaml
sub-urls-remote:
  - https://raw.githubusercontent.com/<owner>/<repo>/main/output/clash-latest.txt
```

## 本地手动跑

```bash
cd subs-finder
pip install -r requirements.txt
export GH_SEARCH_TOKEN=ghp_xxx     # PAT, 只需 public_repo / 无 scope 即可
python find_clash.py --dry-run     # 看结果不写文件
python find_clash.py --top 15 --max-age-days 30
```

## 配置 PAT (一次性)

1. 在 https://github.com/settings/tokens 创建一个 fine-grained 或 classic PAT
   - 不需要任何 scope (默认 public 读权限即可调 search/code 和 repos/commits)
   - 名称建议 `subs-finder`
2. 在仓库设置里加 secret:
   - Settings → Secrets and variables → Actions → New repository secret
   - Name: `GH_SEARCH_TOKEN`
   - Value: 上面生成的 PAT
3. 没有 PAT 时 workflow 会回落到 `GITHUB_TOKEN`, 但 Code Search 配额很低, 容易卡。

## 配置 Telegram 失败通知 (可选)

workflow 失败 (Run subs-finder / Commit if changed 任一 step 报错) 时会发 TG 消息, 不配 secret 就静默跳过。

1. 找 [@BotFather](https://t.me/BotFather) 建一个 bot, 拿到 token
2. 发一条消息给 bot, 然后访问 `https://api.telegram.org/bot<token>/getUpdates` 取 `chat.id`
3. 在仓库 Secrets 里加两条:
   - `TG_BOT_TOKEN` = bot token
   - `TG_CHAT_ID` = 上一步的 chat id (可以是个人或群组)

可以跟你的 Worker 那套 `TGTOKEN`/`TGID` 复用同一个 bot, 但 Cloudflare Secret 和 GitHub Secret 是两套, 要分别录入。

## 维护黑名单

`blocklist.txt` 命中的候选直接跳过, 不浪费 commit API 调用。三种格式:

- `owner/repo` — 拉黑整个仓库
- `owner/repo/path/to/file.yaml` — 拉黑指定文件
- `https://raw.githubusercontent.com/...` — 直接粘 raw URL (会自动拆 owner/repo/path)

用 [block.py](block.py) 维护更省事, 自动去重 + 排序:

```bash
python subs-finder/block.py add https://raw.githubusercontent.com/foo/bar/main/x.yaml
python subs-finder/block.py add owner/repo  # 拉黑整个仓库
python subs-finder/block.py remove owner/repo/path.yaml
python subs-finder/block.py list
```

何时加: subs-check 跑完发现某个订阅源长期 0 可用, 就把它的 raw URL 复制粘贴到 `block.py add`。

## 参数

| 参数 | 默认 | 说明 |
|------|------|------|
| `--top` | 15 | 输出多少条 |
| `--min-proxies` | 5 | YAML 至少要有几个合法节点才算合格 |
| `--max-age-days` | 30 | 文件最近一次 commit 不能超过多少天 |
| `--out-dir` | `subs-finder/output` | 输出目录 |
| `--dry-run` | off | 只打印结果, 不写文件 |

## 已知限制

- GitHub Code Search 对 YAML 内容的索引有滞后, 偶尔会扫到刚被删的文件 — 脚本会在拉 raw 时自动跳过。
- search/code 端点有 30 req/min (PAT) 上限, 当前 5 query × 2 page × 50 result, 远低于限额。
- 同一个仓库可能被多次命中不同节点类型, 脚本按 (owner, repo, path) 去重并按 sha256 去重内容。
- 无法保证抓到的订阅可用
