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
import os
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

DEFAULT_BLOCKLIST = Path(__file__).parent / "blocklist.txt"
RAW_PREFIX = "https://raw.githubusercontent.com/"


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


def count_proxies(text: str) -> int:
    try:
        data = yaml.safe_load(text)
    except Exception:
        return 0
    if not isinstance(data, dict):
        return 0
    proxies = data.get("proxies")
    if not isinstance(proxies, list):
        return 0
    valid = 0
    for p in proxies:
        if isinstance(p, dict) and p.get("type") and p.get("server") and p.get("port"):
            valid += 1
    return valid


def should_skip(path: str, repo_full: str) -> bool:
    lower = (path + " " + repo_full).lower()
    return any(p in lower for p in SKIP_PATTERNS)


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
    target = max(args.top * 2, args.top + 5)
    valid: list[dict] = []
    seen_hashes: set[str] = set()
    total = len(ordered)
    for idx, ((owner, repo, path), entry) in enumerate(ordered, 1):
        prefix = f"  [{idx}/{total}] {owner}/{repo}/{path}"
        raw_url, text = fetch_raw(owner, repo, entry.get("default_branch"), path)
        if not text:
            print(f"{prefix} [skip:no-raw]", file=sys.stderr)
            continue
        nodes = count_proxies(text)
        if nodes < args.min_proxies:
            print(f"{prefix} [skip:proxies={nodes}]", file=sys.stderr)
            continue
        h = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
        if h in seen_hashes:
            print(f"{prefix} [skip:dup-content]", file=sys.stderr)
            continue
        seen_hashes.add(h)
        valid.append({
            "url": raw_url,
            "repo": f"{owner}/{repo}",
            "path": path,
            "nodes": nodes,
            "commit_date": entry["commit_date"],
        })
        print(f"{prefix} [ok nodes={nodes} date={entry['commit_date']}]", file=sys.stderr)
        if len(valid) >= target:
            print(f"  [early-stop] reached {target} validated", file=sys.stderr)
            break
        time.sleep(DETAIL_SLEEP)
    valid.sort(key=lambda x: x["commit_date"], reverse=True)
    return valid


def write_outputs(valid: list[dict], args) -> None:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    top = valid[: args.top]
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lines = [
        "# auto-generated by subs-finder",
        f"# generated_at: {now}",
        f"# top: {len(top)}  validated: {len(valid)}",
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
                "validated_count": len(valid),
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
    print(f"[summary] {len(candidates)} unique candidate files", file=sys.stderr)
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
    write_outputs(valid, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
