#!/usr/bin/env python3
"""subs-finder blocklist 维护工具。

用法:
    python block.py add <url-or-spec> [<url-or-spec> ...]
    python block.py list
    python block.py remove <url-or-spec>
    python block.py from-log [--threshold 5] [--min-total 5] [--dry-run]
        # 从 stdin 读 subs-check 日志, 抽 "订阅成功率过低" 行,
        # 占比低于 threshold 的 URL 批量加入黑名单。

接受三种 spec 格式 (跟 blocklist.txt 一致):
    owner/repo
    owner/repo/path/to/file.yaml
    https://raw.githubusercontent.com/owner/repo/branch/path/to/file.yaml

add/remove 后自动去重 + 排序 + 保留头部注释。
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

BLOCKLIST = Path(__file__).parent / "blocklist.txt"
RAW_PREFIX = "https://raw.githubusercontent.com/"

HEADER = """\
# subs-finder 黑名单 - 命中的候选直接跳过, 不进入 commit-time / raw 校验阶段
# 格式 (一行一条, # 开头注释, 大小写不敏感):
#   owner/repo                              -> 拉黑整个仓库
#   owner/repo/path/to/file.yaml            -> 拉黑指定文件
#   https://raw.githubusercontent.com/...   -> 直接粘 raw URL 也行 (会自动拆 owner/repo/path)
"""


def normalize(spec: str) -> str:
    s = spec.strip()
    if not s:
        return ""
    if s.startswith(RAW_PREFIX):
        return s
    parts = s.split("/")
    if len(parts) < 2:
        raise ValueError(f"invalid spec: {spec!r}")
    return s


def read_existing() -> tuple[list[str], list[str]]:
    """返回 (注释行列表, 规则行列表), 文件不存在时给空。"""
    if not BLOCKLIST.exists():
        return [], []
    comments: list[str] = []
    rules: list[str] = []
    for line in BLOCKLIST.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            comments.append(line.rstrip())
        else:
            rules.append(stripped)
    return comments, rules


def write_back(rules: list[str], inline_comments: list[str] | None = None) -> None:
    rules = sorted(set(r for r in rules if r))
    out = [HEADER.rstrip()]
    if inline_comments:
        for c in inline_comments:
            if c.strip() and c not in HEADER:
                out.append(c)
    out.append("")
    out.extend(rules)
    out.append("")
    BLOCKLIST.write_text("\n".join(out), encoding="utf-8")


def cmd_add(specs: list[str]) -> int:
    _, rules = read_existing()
    existing = set(rules)
    added: list[str] = []
    for spec in specs:
        try:
            n = normalize(spec)
        except ValueError as e:
            print(f"  [skip] {e}", file=sys.stderr)
            continue
        if not n or n in existing:
            print(f"  [dup]  {n}", file=sys.stderr)
            continue
        rules.append(n)
        existing.add(n)
        added.append(n)
        print(f"  [add]  {n}", file=sys.stderr)
    if not added:
        print("[done] no new entries", file=sys.stderr)
        return 0
    write_back(rules)
    print(f"[done] +{len(added)} entries -> {BLOCKLIST}", file=sys.stderr)
    return 0


def cmd_remove(specs: list[str]) -> int:
    _, rules = read_existing()
    before = set(rules)
    targets = {normalize(s) for s in specs if s.strip()}
    after = [r for r in rules if r not in targets]
    removed = before - set(after)
    for r in sorted(removed):
        print(f"  [del]  {r}", file=sys.stderr)
    if not removed:
        print("[done] nothing matched", file=sys.stderr)
        return 0
    write_back(after)
    print(f"[done] -{len(removed)} entries -> {BLOCKLIST}", file=sys.stderr)
    return 0


def cmd_list() -> int:
    _, rules = read_existing()
    for r in sorted(set(rules)):
        print(r)
    print(f"# total: {len(set(rules))}", file=sys.stderr)
    return 0


# subs-check 日志格式 (参考用户截图):
#   2026-05-29 14:55:40 WRN 订阅成功率过低: <URL> 总节点数=120 成功节点数=4 成功占比=3.3%
LOG_RE = re.compile(
    r"订阅成功率过低[:：]\s*(\S+)\s*"
    r"总节点数\s*=\s*(\d+)\s*"
    r"成功节点数\s*=\s*(\d+)\s*"
    r"成功占比\s*=\s*([\d.]+)\s*%"
)


def cmd_from_log(threshold: float, min_total: int, dry_run: bool) -> int:
    """从 stdin 读 subs-check 日志, 抽出占比低于 threshold 的 URL 加进黑名单。

    min_total: 总节点数 < min_total 的行直接忽略 (样本太小, 噪声大).
    """
    text = sys.stdin.read()
    if not text.strip():
        print("[error] empty stdin; pipe in subs-check logs", file=sys.stderr)
        return 1
    candidates: dict[str, tuple[int, int, float]] = {}
    for m in LOG_RE.finditer(text):
        url, total, ok, pct_s = m.group(1), int(m.group(2)), int(m.group(3)), float(m.group(4))
        if total < min_total:
            print(f"  [skip:small] {url} (total={total} < {min_total})", file=sys.stderr)
            continue
        if pct_s >= threshold:
            print(f"  [skip:ok] {url} (pct={pct_s}% >= {threshold}%)", file=sys.stderr)
            continue
        prev = candidates.get(url)
        if prev is None or pct_s < prev[2]:
            candidates[url] = (total, ok, pct_s)
    if not candidates:
        print("[done] no entries below threshold", file=sys.stderr)
        return 0
    print(f"[from-log] {len(candidates)} URL(s) below {threshold}%:", file=sys.stderr)
    for url, (total, ok, pct_s) in sorted(candidates.items(), key=lambda kv: kv[1][2]):
        print(f"  {pct_s:>5.2f}%  ok={ok:<3} total={total:<4} {url}", file=sys.stderr)
    if dry_run:
        print("[dry-run] not writing blocklist", file=sys.stderr)
        return 0
    return cmd_add(list(candidates.keys()))


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    pa = sub.add_parser("add", help="添加一条或多条")
    pa.add_argument("specs", nargs="+")
    pr = sub.add_parser("remove", help="删除一条或多条")
    pr.add_argument("specs", nargs="+")
    sub.add_parser("list", help="列出当前所有规则")
    pf = sub.add_parser("from-log", help="从 stdin 读 subs-check 日志批量加黑名单")
    pf.add_argument("--threshold", type=float, default=5.0, help="成功占比 (%) 低于此值就拉黑, 默认 5")
    pf.add_argument("--min-total", type=int, default=5, help="总节点数小于此值忽略, 默认 5")
    pf.add_argument("--dry-run", action="store_true", help="只打印, 不写盘")
    args = p.parse_args()
    if args.cmd == "add":
        return cmd_add(args.specs)
    if args.cmd == "remove":
        return cmd_remove(args.specs)
    if args.cmd == "list":
        return cmd_list()
    if args.cmd == "from-log":
        return cmd_from_log(args.threshold, args.min_total, args.dry_run)
    return 1


if __name__ == "__main__":
    sys.exit(main())
