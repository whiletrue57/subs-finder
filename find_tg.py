#!/usr/bin/env python3
"""find_tg: 从 Telegram 公开频道预览页抓取代理节点，输出 Clash YAML。

用法:
    python find_tg.py
    python find_tg.py --channels tg_channels.txt --out output/tg-nodes.yaml --dry-run

原理: 抓取 https://t.me/s/<channel> (无需登录/API key)，
正则提取 vmess://, vless://, ss://, trojan://, hysteria2:// 链接，
解码为 Clash proxy dict，去重后输出 YAML。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import time
from html import unescape
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import requests
import yaml

DEFAULT_CHANNELS = Path(__file__).parent / "tg_channels.txt"
DEFAULT_OUT = Path(__file__).parent / "output" / "tg-nodes.yaml"

PROTOCOL_RE = re.compile(
    r"(?:vmess|vless|ss|trojan|hysteria2|hy2)://[A-Za-z0-9+/=@:.\[\]?&#%_~!$'()*+,;-]+",
    re.ASCII,
)

FETCH_TIMEOUT = 20
FETCH_SLEEP = 2.0  # 请求间隔，避免被限流
MAX_PAGES = 3  # 每频道最多翻几页（首页 + before 翻页）

BEFORE_RE = re.compile(r'data-before="(\d+)"')

# t.me 真实 IP（绕过本地 DNS 劫持）
TG_REAL_IP = "149.154.167.99"


def _tg_session() -> requests.Session:
    """创建绕过 DNS 劫持的 session，通过底层 socket 层面强制解析 t.me。"""
    import socket
    _orig_getaddrinfo = socket.getaddrinfo

    def _patched_getaddrinfo(host, port, *args, **kwargs):
        if host == "t.me":
            return _orig_getaddrinfo(TG_REAL_IP, port, *args, **kwargs)
        return _orig_getaddrinfo(host, port, *args, **kwargs)

    socket.getaddrinfo = _patched_getaddrinfo
    s = requests.Session()
    return s


# ---------------------------------------------------------------------------
# base64 辅助
# ---------------------------------------------------------------------------

def b64_decode(s: str) -> str:
    """兼容 urlsafe/standard base64，自动补 padding。"""
    s = s.strip()
    pad = 4 - len(s) % 4
    if pad < 4:
        s += "=" * pad
    try:
        return base64.urlsafe_b64decode(s).decode("utf-8", errors="replace")
    except Exception:
        return base64.b64decode(s).decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# 协议解析器: URI -> Clash proxy dict
# ---------------------------------------------------------------------------

def _parse_transport_opts(params: dict, proxy: dict) -> None:
    """从 query params 解析 ws/grpc/h2 传输层配置，写入 proxy dict。"""
    net = params.get("type", ["tcp"])[0]
    if net == "tcp":
        return
    proxy["network"] = net
    if net == "ws":
        ws_opts: dict = {}
        path = params.get("path", [""])[0]
        host = params.get("host", [""])[0]
        if path:
            ws_opts["path"] = unquote(path)
        if host:
            ws_opts["headers"] = {"Host": host}
        if ws_opts:
            proxy["ws-opts"] = ws_opts
    elif net == "grpc":
        sn = params.get("serviceName", [""])[0]
        if sn:
            proxy["grpc-opts"] = {"grpc-service-name": sn}
    elif net == "h2":
        h2_opts: dict = {}
        path = params.get("path", [""])[0]
        host = params.get("host", [""])[0]
        if path:
            h2_opts["path"] = unquote(path)
        if host:
            h2_opts["host"] = [host]
        if h2_opts:
            proxy["h2-opts"] = h2_opts


def _parse_tls_opts(params: dict, proxy: dict) -> None:
    """从 query params 解析 TLS/Reality 配置。"""
    security = params.get("security", [""])[0]
    sni = params.get("sni", [""])[0]
    fp = params.get("fp", [""])[0]
    alpn = params.get("alpn", [""])[0]

    if security in ("tls", "reality"):
        proxy["tls"] = True
    if sni:
        proxy["servername"] = sni
    if fp:
        proxy["client-fingerprint"] = fp
    if alpn:
        proxy["alpn"] = alpn.split(",")

    if security == "reality":
        pbk = params.get("pbk", [""])[0]
        sid = params.get("sid", [""])[0]
        reality_opts: dict = {}
        if pbk:
            reality_opts["public-key"] = pbk
        if sid:
            reality_opts["short-id"] = sid
        if reality_opts:
            proxy["reality-opts"] = reality_opts


def parse_vmess(uri: str) -> dict | None:
    """vmess://base64(JSON)"""
    try:
        payload = b64_decode(uri[8:])
        obj = json.loads(payload)
    except Exception:
        return None
    server = obj.get("add", "").strip()
    port = obj.get("port", 0)
    uuid = obj.get("id", "").strip()
    if not server or not port or not uuid:
        return None
    proxy: dict = {
        "name": str(obj.get("ps", f"{server}:{port}")).strip(),
        "type": "vmess",
        "server": server,
        "port": int(port),
        "uuid": uuid,
        "alterId": int(obj.get("aid", 0)),
        "cipher": "auto",
    }
    tls = obj.get("tls", "")
    if tls == "tls":
        proxy["tls"] = True
    sni = obj.get("sni", "") or obj.get("host", "")
    if sni:
        proxy["servername"] = sni
    net = obj.get("net", "tcp")
    if net and net != "tcp":
        proxy["network"] = net
        host = obj.get("host", "")
        path = obj.get("path", "")
        if net == "ws":
            ws_opts: dict = {}
            if path:
                ws_opts["path"] = path
            if host:
                ws_opts["headers"] = {"Host": host}
            if ws_opts:
                proxy["ws-opts"] = ws_opts
        elif net == "grpc" and path:
            proxy["grpc-opts"] = {"grpc-service-name": path}
        elif net == "h2":
            h2_opts: dict = {}
            if path:
                h2_opts["path"] = path
            if host:
                h2_opts["host"] = [host]
            if h2_opts:
                proxy["h2-opts"] = h2_opts
    return proxy


def parse_vless(uri: str) -> dict | None:
    """vless://UUID@host:port?params#remark"""
    try:
        parsed = urlparse(uri)
    except Exception:
        return None
    uuid = parsed.username or ""
    server = parsed.hostname or ""
    port = parsed.port
    if not uuid or not server or not port:
        return None
    params = parse_qs(parsed.query)
    proxy: dict = {
        "name": unquote(parsed.fragment) or f"{server}:{port}",
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": uuid,
    }
    flow = params.get("flow", [""])[0]
    if flow:
        proxy["flow"] = flow
    _parse_tls_opts(params, proxy)
    _parse_transport_opts(params, proxy)
    return proxy


def parse_ss(uri: str) -> dict | None:
    """ss://... (SIP002 和旧版 base64 两种格式)"""
    body = uri[5:]  # 去掉 ss://
    fragment = ""
    if "#" in body:
        body, fragment = body.rsplit("#", 1)
    # 去掉 query
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)

    try:
        if "@" in body:
            # SIP002: base64(method:password)@host:port
            userinfo, hostport = body.rsplit("@", 1)
            decoded = b64_decode(userinfo)
            if ":" not in decoded:
                return None
            method, password = decoded.split(":", 1)
            if ":" not in hostport:
                return None
            host, port_s = hostport.rsplit(":", 1)
            host = host.strip("[]")
        else:
            # 旧版: base64(method:password@host:port)
            decoded = b64_decode(body)
            if "@" not in decoded:
                return None
            left, hostport = decoded.rsplit("@", 1)
            if ":" not in left:
                return None
            method, password = left.split(":", 1)
            if ":" not in hostport:
                return None
            host, port_s = hostport.rsplit(":", 1)
            host = host.strip("[]")
    except Exception:
        return None

    try:
        port = int(port_s)
    except ValueError:
        return None
    if not host or not method:
        return None

    proxy: dict = {
        "name": unquote(fragment) or f"{host}:{port}",
        "type": "ss",
        "server": host,
        "port": port,
        "cipher": method,
        "password": password,
    }

    if query:
        qp = parse_qs(query)
        plugin = qp.get("plugin", [""])[0]
        if "obfs" in plugin:
            parts = plugin.split(";")
            opts: dict = {}
            for p in parts[1:]:
                if "=" in p:
                    k, v = p.split("=", 1)
                    opts[k.strip()] = v.strip()
            proxy["plugin"] = "obfs"
            proxy["plugin-opts"] = {
                "mode": opts.get("obfs", "http"),
                "host": opts.get("obfs-host", ""),
            }
    return proxy


def parse_trojan(uri: str) -> dict | None:
    """trojan://password@host:port?params#remark"""
    try:
        parsed = urlparse(uri)
    except Exception:
        return None
    password = parsed.username or ""
    server = parsed.hostname or ""
    port = parsed.port
    if not password or not server or not port:
        return None
    params = parse_qs(parsed.query)
    proxy: dict = {
        "name": unquote(parsed.fragment) or f"{server}:{port}",
        "type": "trojan",
        "server": server,
        "port": port,
        "password": unquote(password),
    }
    sni = params.get("sni", [""])[0]
    if sni:
        proxy["sni"] = sni
    _parse_tls_opts(params, proxy)
    _parse_transport_opts(params, proxy)
    return proxy


def parse_hysteria2(uri: str) -> dict | None:
    """hysteria2://auth@host:port?params#remark (或 hy2://)"""
    try:
        normalized = uri
        if normalized.startswith("hy2://"):
            normalized = "hysteria2://" + normalized[6:]
        parsed = urlparse(normalized)
    except Exception:
        return None
    auth = parsed.username or ""
    server = parsed.hostname or ""
    port = parsed.port
    if not server or not port:
        return None
    params = parse_qs(parsed.query)
    proxy: dict = {
        "name": unquote(parsed.fragment) or f"{server}:{port}",
        "type": "hysteria2",
        "server": server,
        "port": port,
        "password": unquote(auth) if auth else "",
    }
    sni = params.get("sni", [""])[0]
    if sni:
        proxy["sni"] = sni
    insecure = params.get("insecure", ["0"])[0]
    if insecure == "1":
        proxy["skip-cert-verify"] = True
    obfs = params.get("obfs", [""])[0]
    obfs_pw = params.get("obfs-password", [""])[0]
    if obfs:
        proxy["obfs"] = obfs
    if obfs_pw:
        proxy["obfs-password"] = obfs_pw
    return proxy


PARSERS = {
    "vmess": parse_vmess,
    "vless": parse_vless,
    "ss": parse_ss,
    "trojan": parse_trojan,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
}


def parse_proxy_uri(uri: str) -> dict | None:
    """分发到对应协议解析器。"""
    scheme = uri.split("://", 1)[0].lower()
    fn = PARSERS.get(scheme)
    if not fn:
        return None
    try:
        return fn(uri)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Telegram 频道抓取
# ---------------------------------------------------------------------------

def load_channels(path: Path) -> list[str]:
    """读取频道列表文件。"""
    channels: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # 支持 @channel 或 t.me/channel 或裸 channel
        line = line.lstrip("@")
        if line.startswith("t.me/"):
            line = line[5:]
        if line.startswith("https://t.me/"):
            line = line[13:]
        channels.append(line)
    return channels


def fetch_channel_page(channel: str) -> str:
    """抓取 TG 频道公开预览页 HTML，支持翻页获取更多消息。"""
    session = _tg_session()
    url = f"https://t.me/s/{channel}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    all_html = ""
    for _ in range(MAX_PAGES):
        r = session.get(url, headers=headers, timeout=FETCH_TIMEOUT)
        r.raise_for_status()
        html = r.text
        all_html += html
        m = BEFORE_RE.search(html)
        if not m:
            break
        before = m.group(1)
        url = f"https://t.me/s/{channel}?before={before}"
        time.sleep(1)
    return all_html


def extract_uris_from_html(html: str) -> list[str]:
    """从 HTML 中提取代理协议链接，处理 HTML 实体转义。"""
    text = unescape(html)
    matches = PROTOCOL_RE.findall(text)
    # 清理尾部可能的 HTML 残留
    cleaned: list[str] = []
    for m in matches:
        m = m.rstrip("<>\"')")  # 去掉 HTML 标签闭合残留
        cleaned.append(m)
    return cleaned


def proxy_fingerprint(proxy: dict) -> str:
    """生成节点连接参数指纹用于去重。"""
    key_fields = {}
    for k, v in sorted(proxy.items()):
        if k in ("name",):
            continue
        key_fields[k] = v
    payload = json.dumps(key_fields, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description="从 Telegram 公开频道抓取代理节点")
    p.add_argument("--channels", default=str(DEFAULT_CHANNELS), help="频道列表文件")
    p.add_argument("--out", default=str(DEFAULT_OUT), help="输出 YAML 路径")
    p.add_argument("--dry-run", action="store_true", help="只打印不写盘")
    args = p.parse_args()

    channels_path = Path(args.channels)
    if not channels_path.exists():
        print(f"ERROR: channels file not found: {channels_path}", file=sys.stderr)
        return 1

    channels = load_channels(channels_path)
    if not channels:
        print("ERROR: no channels loaded", file=sys.stderr)
        return 1
    print(f"[tg] loaded {len(channels)} channels", file=sys.stderr)

    all_proxies: list[dict] = []
    seen_fp: set[str] = set()
    total_raw = 0

    for ch in channels:
        try:
            html = fetch_channel_page(ch)
        except requests.RequestException as e:
            print(f"  [{ch}] fetch failed: {e}", file=sys.stderr)
            time.sleep(FETCH_SLEEP)
            continue

        uris = extract_uris_from_html(html)
        parsed = 0
        dupes = 0
        for uri in uris:
            proxy = parse_proxy_uri(uri)
            if not proxy:
                continue
            total_raw += 1
            fp = proxy_fingerprint(proxy)
            if fp in seen_fp:
                dupes += 1
                continue
            seen_fp.add(fp)
            all_proxies.append(proxy)
            parsed += 1

        print(
            f"  [{ch}] uris={len(uris)} parsed={parsed} dupes={dupes}",
            file=sys.stderr,
        )
        time.sleep(FETCH_SLEEP)

    print(
        f"[tg] total: {total_raw} raw -> {len(all_proxies)} unique proxies",
        file=sys.stderr,
    )

    if not all_proxies:
        print("[tg] no proxies found", file=sys.stderr)
        return 0

    # 输出标准 Clash YAML
    clash_config = {"proxies": all_proxies}
    yaml_text = yaml.dump(
        clash_config,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
    )

    if args.dry_run:
        print("--- dry-run ---")
        print(yaml_text[:3000])
        print(f"... ({len(all_proxies)} proxies total)")
        return 0

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(yaml_text, encoding="utf-8")
    print(f"[done] wrote {out_path} ({len(all_proxies)} proxies)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
