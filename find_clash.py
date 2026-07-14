#!/usr/bin/env python3
"""subs-finder: 从 GitHub 搜索最近更新过的 Clash/Mihomo YAML 配置, 输出 top-N raw URL 清单。

用法:
    GH_SEARCH_TOKEN=ghp_xxx python find_clash.py
    python find_clash.py --dry-run --top 10 --max-age-days 30
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
import yaml

GITHUB_API = "https://api.github.com"

SEARCH_QUERIES = [
    # 按 type 字段命中各种协议
    '"proxies:" "type: vmess" language:YAML',
    '"proxies:" "type: ss" language:YAML',
    '"proxies:" "type: trojan" language:YAML',
    '"proxies:" "type: vless" language:YAML',
    '"proxies:" "type: hysteria2" language:YAML',
    # 按文件名直击常见 Clash 配置
    'filename:clash.yaml "proxies:"',
    'filename:config.yaml "proxies:" "proxy-groups:"',
    # 完整 Clash 配置三件套, 抓那些自带 rules 的整套订阅
    '"proxies:" "proxy-groups:" "rules:" language:YAML',
]

SKIP_PATTERNS = [
    "test", "example", "template", "sample", "demo",
    "fixture", "schema", "docs/", "doc/", ".github/",
]

PER_PAGE = 50
MAX_PAGES = 2  # 8 queries x 2 pages x 50 = 800 raw matches max
SEARCH_SLEEP = 2.0
DETAIL_SLEEP = 0.4
MAX_FILE_BYTES = 5_000_000
COMMIT_WORKERS = 8  # 并发拉 file-level commit 时间

# 节点指纹只忽略展示/来源字段，其余连接参数全部参与哈希。
# 这样能识别“同一节点、不同名称”，同时保留 ws path、Reality key 等关键差异。
FINGERPRINT_IGNORED_KEYS = {
    "name",
    "sub_url",
    "sub_tag",
    "interface-name",
    "routing-mark",
}

FINGERPRINT_KEY_ALIASES = {
    "servername": "sni",
    "obfs_password": "obfs-password",
    "skip_cert_verify": "skip-cert-verify",
    "client_fingerprint": "client-fingerprint",
}

DEFAULT_BLOCKLIST = Path(__file__).parent / "blocklist.txt"
RAW_PREFIX = "https://raw.githubusercontent.com/"

# 已知"日更带日期文件名"的源: 这类仓库每天生成一个新文件 (无固定 latest),
# GitHub Code Search 对它们命中不稳, 改为直接列目录取日期最大的文件。
#   owner/repo : 仓库
#   branch     : 分支
#   dir        : 目录 (相对仓库根)
#   pattern    : 带一个捕获组的正则, 组内是用于排序的日期串 (YYYYMMDD 等可字典序比较的格式)
KNOWN_DAILY_SOURCES = [
    {
        "owner": "danmaifu",
        "repo": "mianfeijiedian",
        "branch": "main",
        "dir": "feed",
        "pattern": r"^clash-(\d{8})\.yaml$",
    },
]


def load_blocklist(path: Path) -> tuple[set[str], set[tuple[str, str, str]]]:
    """读取黑名单文件, 返回 (repo 集合, (owner,repo,path) 集合), 全部 lower-case。"""
    repos: set[str] = set()
    files: set[tuple[str, str, str]] = set()
    if not path.exists():
        return repos, files
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(RAW_PREFIX):
            rest = line[len(RAW_PREFIX):]
            parts = rest.split("/", 3)
            if len(parts) < 4:
                continue
            owner, repo, _, file_path = parts
            files.add((owner.lower(), repo.lower(), file_path.lower()))
            continue
        parts = line.split("/", 2)
        if len(parts) == 2:
            repos.add(f"{parts[0].lower()}/{parts[1].lower()}")
        elif len(parts) == 3:
            files.add((parts[0].lower(), parts[1].lower(), parts[2].lower()))
    return repos, files


def is_blocked(owner: str, repo: str, path: str, repos: set[str], files: set[tuple[str, str, str]]) -> bool:
    if f"{owner.lower()}/{repo.lower()}" in repos:
        return True
    if (owner.lower(), repo.lower(), path.lower()) in files:
        return True
    return False


def make_headers(token: str) -> dict:
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def search_code(query: str, page: int, headers: dict) -> dict:
    url = f"{GITHUB_API}/search/code"
    # sort=indexed 让最近被 GitHub 索引的文件靠前; 老仓库不会出现在前几页
    params = {
        "q": query,
        "per_page": PER_PAGE,
        "page": page,
        "sort": "indexed",
        "order": "desc",
    }
    for attempt in range(3):
        r = requests.get(url, headers=headers, params=params, timeout=30)
        if r.status_code == 403 and "rate limit" in r.text.lower():
            reset = int(r.headers.get("X-RateLimit-Reset", "0"))
            wait = max(reset - int(time.time()), 10)
            wait = min(wait, 90)
            print(f"  [rate-limited] sleep {wait}s", file=sys.stderr)
            time.sleep(wait)
            continue
        if r.status_code == 422:
            # invalid query; bail this query
            return {"items": []}
        r.raise_for_status()
        return r.json()
    r.raise_for_status()
    return {"items": []}


def get_last_commit_date(owner: str, repo: str, path: str, headers: dict) -> str | None:
    url = f"{GITHUB_API}/repos/{owner}/{repo}/commits"
    params = {"path": path, "per_page": 1}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=30)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    data = r.json()
    if not data:
        return None
    try:
        return data[0]["commit"]["committer"]["date"]
    except (KeyError, IndexError, TypeError):
        return None


def fetch_raw(owner: str, repo: str, default_branch: str | None, path: str) -> tuple[str | None, str | None]:
    encoded_path = "/".join(urllib.parse.quote(seg) for seg in path.split("/"))
    branches: list[str] = []
    if default_branch:
        branches.append(default_branch)
    for b in ("main", "master"):
        if b not in branches:
            branches.append(b)
    for b in branches:
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{b}/{encoded_path}"
        try:
            r = requests.get(url, timeout=30, stream=True)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        cl = r.headers.get("Content-Length")
        if cl and cl.isdigit() and int(cl) > MAX_FILE_BYTES:
            return None, None
        try:
            text = r.text
        except Exception:
            continue
        if len(text) > MAX_FILE_BYTES:
            return None, None
        return url, text
    return None, None


def parse_clash_proxies(text: str) -> tuple[list[dict], dict]:
    """安全解析 Clash/Mihomo YAML，返回有效节点和配置形态信息。"""
    try:
        data = yaml.safe_load(text)
    except Exception:
        return [], {}
    if not isinstance(data, dict):
        return [], {}
    proxies = data.get("proxies")
    if not isinstance(proxies, list):
        return [], {}
    valid: list[dict] = []
    for p in proxies:
        if isinstance(p, dict) and p.get("type") and p.get("server") and p.get("port"):
            valid.append(p)
    shape = {
        "has_proxy_groups": isinstance(data.get("proxy-groups"), list),
        "has_rules": isinstance(data.get("rules"), list),
    }
    return valid, shape


def _normalize_fingerprint_value(value):
    """递归规范化 YAML 值，稳定处理映射顺序和字符串空白。"""
    if isinstance(value, dict):
        normalized = {}
        for raw_key in sorted(value, key=str):
            raw_value = value[raw_key]
            key = FINGERPRINT_KEY_ALIASES.get(str(raw_key), str(raw_key))
            if key in FINGERPRINT_IGNORED_KEYS:
                continue
            item = _normalize_fingerprint_value(raw_value)
            if item is None or item == "" or item == [] or item == {}:
                continue
            normalized[key] = item
        return {key: normalized[key] for key in sorted(normalized)}
    if isinstance(value, list):
        return [_normalize_fingerprint_value(item) for item in value]
    if isinstance(value, str):
        return value.strip()
    return value


def proxy_fingerprint(proxy: dict) -> str:
    """生成与名称、来源无关的节点连接参数指纹。"""
    canonical = _normalize_fingerprint_value(proxy)
    if isinstance(canonical, dict):
        for key in ("type", "server", "network", "sni"):
            value = canonical.get(key)
            if isinstance(value, str):
                canonical[key] = value.lower()
        port = canonical.get("port")
        if isinstance(port, str) and port.isdigit():
            canonical["port"] = int(port)
    payload = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def source_path_score(repo: str, path: str) -> float:
    """根据仓库和路径命名估计其作为自动生成节点源的可能性。"""
    text = f"{repo}/{path}".lower()
    tokens = set(re.split(r"[^a-z0-9]+", text))
    score = 0.45
    if tokens & {"output", "outputs", "result", "results", "sub", "subs", "subscription", "subscribe", "snippets"}:
        score += 0.18
    if tokens & {"live", "alive", "valid", "checked", "checker", "speed", "nodes", "proxies", "proxy"}:
        score += 0.22
    if tokens & {"config", "configs", "rule", "rules", "overwrite"}:
        score -= 0.20
    return min(max(score, 0.0), 1.0)


def source_size_score(nodes: int) -> float:
    """偏好中等规模节点源，压低超大聚合文件带来的测试成本。"""
    coverage = min(math.log1p(nodes) / math.log1p(100), 1.0)
    if nodes <= 500:
        bloat_penalty = 1.0
    else:
        bloat_penalty = max(math.sqrt(500 / nodes), 0.20)
    return coverage * bloat_penalty


def source_shape_score(shape: dict) -> float:
    """纯节点片段优先；含完整规则的个人配置仍保留候选资格。"""
    extras = int(bool(shape.get("has_proxy_groups"))) + int(bool(shape.get("has_rules")))
    return (1.0, 0.75, 0.55)[extras]


def source_freshness_score(commit_dt: datetime, max_age_days: int) -> float:
    age = max((datetime.now(timezone.utc) - commit_dt).total_seconds(), 0.0)
    window = max(max_age_days * 86400, 1)
    return max(0.0, 1.0 - age / window)


def static_source_score(repo: str, path: str, nodes: int, shape: dict, commit_dt: datetime, max_age_days: int) -> float:
    """组合静态信号；实测反馈缺席时提供可解释的质量近似。"""
    freshness = source_freshness_score(commit_dt, max_age_days)
    size = source_size_score(nodes)
    path_hint = source_path_score(repo, path)
    shape_hint = source_shape_score(shape)
    return 0.35 * freshness + 0.25 * size + 0.25 * path_hint + 0.15 * shape_hint


def count_proxies(text: str) -> int:
    proxies, _ = parse_clash_proxies(text)
    return len(proxies)


def should_skip(path: str, repo_full: str) -> bool:
    lower = (path + " " + repo_full).lower()
    return any(p in lower for p in SKIP_PATTERNS)


def resolve_daily_sources(headers: dict, block_repos: set[str], block_files: set[tuple[str, str, str]]) -> dict:
    """对每个已知日更源, 列目录取日期最大的文件, 直接产出 candidate entry。

    返回 {(owner, repo, path): entry}, 与 collect_candidates 同构, 便于合并。
    用 GitHub Contents API 列目录, 不依赖 Code Search (它对带日期文件名命中不稳)。
    """
    found: dict[tuple[str, str, str], dict] = {}
    for src in KNOWN_DAILY_SOURCES:
        owner, repo, branch = src["owner"], src["repo"], src["branch"]
        dir_path, pattern = src["dir"], src["pattern"]
        regex = re.compile(pattern)
        url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{dir_path}"
        try:
            r = requests.get(url, headers=headers, params={"ref": branch}, timeout=30)
        except requests.RequestException as e:
            print(f"[daily] {owner}/{repo}: request failed ({e})", file=sys.stderr)
            continue
        if r.status_code != 200:
            print(f"[daily] {owner}/{repo}: list {dir_path} -> HTTP {r.status_code}", file=sys.stderr)
            continue
        try:
            items = r.json()
        except ValueError:
            continue
        if not isinstance(items, list):
            print(f"[daily] {owner}/{repo}: unexpected response (dir too large?)", file=sys.stderr)
            continue
        best_name, best_key = None, None
        for it in items:
            name = it.get("name", "")
            m = regex.match(name)
            if not m:
                continue
            key = m.group(1)
            if best_key is None or key > best_key:
                best_key, best_name = key, name
        if not best_name:
            print(f"[daily] {owner}/{repo}: no file matched {pattern}", file=sys.stderr)
            continue
        path = f"{dir_path}/{best_name}" if dir_path else best_name
        if is_blocked(owner, repo, path, block_repos, block_files):
            print(f"[daily] {owner}/{repo}/{path}: blocked, skip", file=sys.stderr)
            continue
        cand_key = (owner, repo, path)
        found[cand_key] = {
            "owner": owner,
            "repo": repo,
            "path": path,
            "default_branch": branch,
        }
        print(f"[daily] {owner}/{repo}: latest -> {path}", file=sys.stderr)
    return found


def collect_candidates(headers: dict, max_age_days: int, block_repos: set[str], block_files: set[tuple[str, str, str]]) -> dict:
    seen: dict[tuple[str, str, str], dict] = {}
    repo_cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    blocked = 0
    for q in SEARCH_QUERIES:
        print(f"[search] {q}", file=sys.stderr)
        for page in range(1, MAX_PAGES + 1):
            try:
                resp = search_code(q, page, headers)
            except requests.HTTPError as e:
                print(f"  [error] page {page}: {e}", file=sys.stderr)
                break
            items = resp.get("items") or []
            if not items:
                break
            for it in items:
                try:
                    repo_obj = it["repository"]
                    repo_full = repo_obj["full_name"]
                    owner, repo = repo_full.split("/", 1)
                    path = it["path"]
                except (KeyError, ValueError):
                    continue
                key = (owner, repo, path)
                if key in seen or should_skip(path, repo_full):
                    continue
                if is_blocked(owner, repo, path, block_repos, block_files):
                    blocked += 1
                    continue
                # 仓库级 pushed_at 只是粗筛 (例如几年没动的死库直接踢掉),
                # 但活跃仓库里塞陈年 yaml 的情况很常见, 真正排序必须靠 file-level commit
                pushed_at = repo_obj.get("pushed_at")
                if pushed_at:
                    try:
                        pushed_dt = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
                        if pushed_dt < repo_cutoff:
                            continue
                    except ValueError:
                        pass
                seen[key] = {
                    "owner": owner,
                    "repo": repo,
                    "path": path,
                    "default_branch": repo_obj.get("default_branch"),
                }
            time.sleep(SEARCH_SLEEP)
    if blocked:
        print(f"[blocklist] skipped {blocked} hits", file=sys.stderr)
    return seen


def enrich_commit_dates(candidates: dict, headers: dict, max_age_days: int) -> list[tuple]:
    """并发拉每个文件最近一次 commit 时间, 过滤超期, 返回按时间倒序的列表。"""
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    keys = list(candidates.keys())
    total = len(keys)
    print(f"[enrich] fetching file-level commit dates for {total} candidates ({COMMIT_WORKERS} workers)", file=sys.stderr)
    results: list[tuple] = []

    def fetch(key):
        owner, repo, path = key
        date_str = get_last_commit_date(owner, repo, path, headers)
        return key, date_str

    done = 0
    with ThreadPoolExecutor(max_workers=COMMIT_WORKERS) as ex:
        futures = [ex.submit(fetch, k) for k in keys]
        for fut in as_completed(futures):
            key, date_str = fut.result()
            done += 1
            if done % 50 == 0:
                print(f"  [enrich] {done}/{total}", file=sys.stderr)
            if not date_str:
                continue
            try:
                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            except ValueError:
                continue
            if dt < cutoff:
                continue
            entry = candidates[key]
            entry["commit_date"] = date_str
            entry["commit_dt"] = dt
            results.append((key, entry))
    results.sort(key=lambda kv: kv[1]["commit_dt"], reverse=True)
    print(f"[enrich] {len(results)}/{total} survive file-level freshness", file=sys.stderr)
    return results


def evaluate(ordered: list[tuple], args, headers: dict) -> list[dict]:
    target = max(args.top * max(args.candidate_multiplier, 1), args.top + 10)
    valid: list[dict] = []
    seen_hashes: set[str] = set()
    total = len(ordered)
    for idx, ((owner, repo, path), entry) in enumerate(ordered, 1):
        prefix = f"  [{idx}/{total}] {owner}/{repo}/{path}"
        raw_url, text = fetch_raw(owner, repo, entry.get("default_branch"), path)
        if not text:
            print(f"{prefix} [skip:no-raw]", file=sys.stderr)
            continue
        proxies, shape = parse_clash_proxies(text)
        nodes = len(proxies)
        if nodes < args.min_proxies:
            print(f"{prefix} [skip:proxies={nodes}]", file=sys.stderr)
            continue
        h = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
        if h in seen_hashes:
            print(f"{prefix} [skip:dup-content]", file=sys.stderr)
            continue
        seen_hashes.add(h)
        fingerprints = {proxy_fingerprint(proxy) for proxy in proxies}
        if len(fingerprints) < args.min_proxies:
            print(f"{prefix} [skip:unique-proxies={len(fingerprints)}]", file=sys.stderr)
            continue
        static_score = static_source_score(
            f"{owner}/{repo}", path, len(fingerprints), shape, entry["commit_dt"], args.max_age_days
        )
        valid.append({
            "url": raw_url,
            "repo": f"{owner}/{repo}",
            "path": path,
            "nodes": nodes,
            "unique_nodes": len(fingerprints),
            "commit_date": entry["commit_date"],
            "static_score": static_score,
            "_fingerprints": fingerprints,
        })
        print(
            f"{prefix} [ok nodes={nodes} unique={len(fingerprints)} "
            f"static={static_score:.3f} date={entry['commit_date']}]",
            file=sys.stderr,
        )
        if len(valid) >= target:
            print(f"  [early-stop] reached candidate pool {target}", file=sys.stderr)
            break
        time.sleep(DETAIL_SLEEP)
    return valid


def select_sources(candidates: list[dict], args) -> list[dict]:
    """按静态质量、节点增量和仓库多样性贪心选择最终来源。"""
    remaining = list(candidates)
    selected: list[dict] = []
    covered: set[str] = set()
    repo_counts: dict[str, int] = {}

    while remaining and len(selected) < args.top:
        best_idx = None
        best_rank = None
        best_metrics = None
        for idx, candidate in enumerate(remaining):
            repo = candidate["repo"]
            repo_count = repo_counts.get(repo, 0)
            if repo_count >= args.max_per_repo:
                continue
            fingerprints = candidate["_fingerprints"]
            new_nodes = len(fingerprints - covered)
            novelty = new_nodes / max(len(fingerprints), 1)
            repo_diversity = 1.0 / (repo_count + 1)
            score = 0.60 * candidate["static_score"] + 0.30 * novelty + 0.10 * repo_diversity
            rank = (score, novelty, candidate["static_score"], candidate["commit_date"])
            if best_rank is None or rank > best_rank:
                best_idx = idx
                best_rank = rank
                best_metrics = (score, novelty, new_nodes)

        if best_idx is None or best_metrics is None:
            break
        candidate = remaining.pop(best_idx)
        score, novelty, new_nodes = best_metrics
        fingerprints = candidate.pop("_fingerprints")
        overlap_nodes = len(fingerprints) - new_nodes
        candidate["score"] = round(score, 6)
        candidate["static_score"] = round(candidate["static_score"], 6)
        candidate["novelty_ratio"] = round(novelty, 6)
        candidate["new_nodes"] = new_nodes
        candidate["overlap_nodes"] = overlap_nodes
        selected.append(candidate)
        covered.update(fingerprints)
        repo_counts[candidate["repo"]] = repo_counts.get(candidate["repo"], 0) + 1
        print(
            f"  [select {len(selected)}/{args.top}] {candidate['repo']}/{candidate['path']} "
            f"score={score:.3f} novelty={novelty:.1%} new={new_nodes} overlap={overlap_nodes}",
            file=sys.stderr,
        )

    return selected


def write_outputs(selected: list[dict], validated_count: int, args) -> None:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    top = selected[: args.top]
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lines = [
        "# auto-generated by subs-finder",
        f"# generated_at: {now}",
        f"# top: {len(top)}  validated: {validated_count}",
        "# do not edit by hand; see subs-finder/find_clash.py",
        "",
    ]
    lines.extend(e["url"] for e in top)
    lines.append("")
    txt_path = out_dir / "clash-latest.txt"
    json_path = out_dir / "clash-latest.json"
    if args.dry_run:
        print("--- dry-run: clash-latest.txt ---")
        print("\n".join(lines))
        return
    txt_path.write_text("\n".join(lines), encoding="utf-8")
    json_path.write_text(
        json.dumps(
            {
                "generated_at": now,
                "validated_count": validated_count,
                "selection_policy": {
                    "candidate_multiplier": args.candidate_multiplier,
                    "max_per_repo": args.max_per_repo,
                    "signals": ["freshness", "size", "path", "shape", "node_novelty", "repo_diversity"],
                },
                "top": top,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"[done] wrote {txt_path} ({len(top)} urls)", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--top", type=int, default=15)
    p.add_argument("--min-proxies", type=int, default=5)
    p.add_argument("--max-age-days", type=int, default=7)
    p.add_argument("--candidate-multiplier", type=int, default=4)
    p.add_argument("--max-per-repo", type=int, default=1)
    p.add_argument("--out-dir", default=str(Path(__file__).parent / "output"))
    p.add_argument("--blocklist", default=str(DEFAULT_BLOCKLIST))
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    token = os.environ.get("GH_SEARCH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""

    if not token:
        print("ERROR: set GH_SEARCH_TOKEN or GITHUB_TOKEN", file=sys.stderr)
        return 1
    headers = make_headers(token)

    block_repos, block_files = load_blocklist(Path(args.blocklist))
    if block_repos or block_files:
        print(f"[blocklist] loaded {len(block_repos)} repos, {len(block_files)} files", file=sys.stderr)

    candidates = collect_candidates(headers, args.max_age_days, block_repos, block_files)
    daily = resolve_daily_sources(headers, block_repos, block_files)
    for k, v in daily.items():
        candidates.setdefault(k, v)
    print(f"[summary] {len(candidates)} unique candidate files ({len(daily)} from daily sources)", file=sys.stderr)
    if not candidates:
        return 2
    ordered = enrich_commit_dates(candidates, headers, args.max_age_days)
    if not ordered:
        print("[summary] no candidates passed file-level freshness filter", file=sys.stderr)
        return 3
    valid = evaluate(ordered, args, headers)
    print(f"[summary] {len(valid)} validated", file=sys.stderr)
    if not valid:
        return 3
    selected = select_sources(valid, args)
    print(f"[summary] {len(selected)} selected from {len(valid)} validated", file=sys.stderr)
    if not selected:
        return 3
    write_outputs(selected, len(valid), args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
