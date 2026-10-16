
#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线 (精简版)
=====================================
流程:
  1. 获取 VPN Gate 原始节点
  2. 只保留带 TCP 入口的 SSTP 节点
  3. 去重
  4. 并发调用检测 Worker
  5. 获取并合并优选域名与优选 API (Cloudflare 入口)
  6. 生成 public/data.json + public/index.html + public/nodes.txt + public/clash.yaml
     (clash.yaml 节点分类参考 warp-masque 风格：手动/自动/故障转移 + 应用分流组)
"""

import base64
import csv
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote

import requests
import yaml

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))

VPNGATE_API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)
WORKER_CHECK_URL = os.environ.get("CHECK_WORKER", "https://ch.zy234.cc.cd/check?sstp=vpn:vpn@")
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "32")))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "90"))
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]

COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

# 静态优选域名池
EDGE_HOSTS = [
    h.strip()
    for h in os.environ.get(
        "EDGE_HOSTS",
        "fn.130519.xyz:443,"
"cf.nyanya.moe:443,"
"cdn.7zz.cn:443,"
"www.wuduanyun.com:443,"
"saas.072159.xyz:443,"
"ikankeji.com:443,"
"auto.dolby.dpdns.org:443,"
"eii.at:443,"
"cloudflare.idc.rocks:443,"
"cf.xreak.top:443,"
"cf.1o.ee:443,"
"cf.itv888.cn:443,"
"224322.xyz:443,"
"vps.cheng2001.top:443,"
"cf.877774.xyz:443,"
"cdn.204910.best:443,"
"cf-cname.xingpingcn.top:443,"
"p.etime.vip:443,"
"bbs.alipansou.com:443,"
"tt.78607323.xyz:443,"
"cdn.667891.xyz:443,"
"saas.sin.fan:443,"
"cdn.ctn32.us.kg:443,"
"www.giannidelprete.it:443,"
"ahrefs.com:443,"
"www.blibli.com:443,"
"www.dbs.com.sg:443,"
"53.fs1.hubspotusercontent-na1.net:443,"
"staticdelivery.nexusmods.com:443,"
"jobsdb.com:443,"
"www.shopify.com:443,"
"dongbanghong.com:443,"
"api.gzcrtw.com:443,"
"openai.com:443,"
"stores.staples.com:443,"
"www.jp.pima.gov:443,"
"cloudflare-ip.mofashi.ltd:443,"
"kickstarter.com:443,"
"www.leics.police.uk:443,"
"www.gov.il:443,"
"www.broadcom.com:443,"
"funko.com:443,"
"versantstore.pearson.com:443,"
"www.vastnovel.com:443,"
"coreweave.com:443,"
"baota.us.kg:443,"
"www.zendesk.com:443,"
"prizepicks.com:443,"
"www.wto.org:443",
    ).split(",")
    if h.strip()
]

# 优选 API 地址配置 (支持逗号分隔多个，可配置在 GitHub Action Secret / Env 中)
OPTIMAL_API = os.environ.get("OPTIMAL_API", "https://cf.090227.xyz/ct?ips=6&port=443,https://cf.090227.xyz/cu?port=443,https://cf.090227.xyz/cmcc?ips=8&port=443")

NODES_URL = os.environ.get("NODES_URL", "https://zgs360.github.io/z_gate/nodes.txt")

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
_section = None

def log(section, msg=""):
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)

def die(msg):
    log("FATAL", f"[失败] {msg}")
    sys.exit(1)

# ---------------------------------------------------------------------------
# 数据抓取
# ---------------------------------------------------------------------------
def fetch_vpngate():
    try:
        log("VPN GATE", f"获取官方 API: {VPNGATE_API}")
        resp = requests.get(VPNGATE_API, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"})
        resp.raise_for_status()
        rows = parse_csv(resp.text)
        if rows:
            log("VPN GATE", f"主源(官方 API) 获取到 {len(rows)} 个原始节点")
            return rows, "vpngate.net/api/iphone"
        raise RuntimeError("官方 API 返回 0 行数据")
    except Exception as exc:
        log("VPN GATE", f"官方 API 获取失败: {exc}")

    try:
        log("VPN GATE", f"回退镜像: {VPNGATE_MIRROR}")
        resp = requests.get(VPNGATE_MIRROR, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        rows = parse_mirror_json(resp.json())
        if rows:
            log("VPN GATE", f"回退源(镜像) 获取到 {len(rows)} 个原始节点")
            return rows, "github-mirror"
    except Exception as exc:
        log("VPN GATE", f"回退镜像也失败: {exc}")
    die("VPN Gate 官方 API 与回退镜像均不可用, 数据源完全失败")

def parse_csv(text):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")

    header = lines[header_idx].lstrip("#").split(",")
    data_lines = lines[header_idx + 1:]
    idx = {}
    for col in ("hostname", "ip", "countrylong", "countryshort", "openvpn_configdata_base64"):
        for i, h in enumerate(header):
            if h.strip().lstrip("*").lower() == col:
                idx[col] = i
                break
    if "openvpn_configdata_base64" not in idx:
        for i, h in enumerate(header):
            if "base64" in h.lower():
                idx["openvpn_configdata_base64"] = i
                break
    pos = {
        "hostname": idx.get("hostname", 0),
        "ip": idx.get("ip", 1),
        "countrylong": idx.get("countrylong", 5),
        "countryshort": idx.get("countryshort", 6),
        "openvpn_configdata_base64": idx.get("openvpn_configdata_base64", len(header) - 1),
    }

    rows = []
    for ln in data_lines:
        fields = next(csv.reader(io.StringIO(ln)))
        if len(fields) < 7: continue
        host = fields[pos["hostname"]].strip()
        ip = fields[pos["ip"]].strip()
        if not host or not ip: continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": fields[pos["countrylong"]].strip(),
            "country_short": fields[pos["countryshort"]].strip(),
            "config_b64": fields[pos["openvpn_configdata_base64"]].strip(),
        })
    return rows

def parse_mirror_json(data):
    servers = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict):
            servers.append(item)
    rows = []
    for s in servers:
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if not host or not ip: continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": str(s.get("countrylong") or s.get("country_long") or s.get("country") or "").strip(),
            "country_short": str(s.get("countryshort") or s.get("country_short") or "").strip(),
            "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or "").strip(),
        })
    return rows

# ---------------------------------------------------------------------------
# 优选 API 获取与解析
# ---------------------------------------------------------------------------
def fetch_optimal_api_endpoints(api_urls_str):
    """
    拉取优选 API，解析如: 172.66.1.179:443#CF 电信优选 格式的内容
    提取出纯 'IP:端口' (例如 172.66.1.179:443)
    """
    if not api_urls_str.strip():
        return []
    
    endpoints = []
    urls = [u.strip() for u in api_urls_str.split(",") if u.strip()]
    for url in urls:
        try:
            log("OPTIMAL API", f"请求优选 API: {url}")
            resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                lines = resp.text.strip().splitlines()
                count = 0
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # 剥离 # 后的备注，提取 IP:端口
                    endpoint = line.split("#")[0].strip()
                    if endpoint:
                        # 补充缺失端口默认 443
                        if ":" not in endpoint:
                            endpoint = f"{endpoint}:443"
                        endpoints.append(endpoint)
                        count += 1
                log("OPTIMAL API", f"成功从 API 获取到 {count} 个优选端点")
            else:
                log("OPTIMAL API", f"API 返回状态码异常: {resp.status_code}")
        except Exception as e:
            log("OPTIMAL API", f"拉取优选 API 失败 ({url}): {e}")
    return endpoints

def get_combined_edge_hosts():
    """
    合并静态优选域名与优选 API 端点
    """
    # 1. 优先读取 HOSTS_ENTRY 或 EDGE_HOSTS
    _entry = os.environ.get("HOSTS_ENTRY", "").strip()
    static_hosts = [e.strip() for e in _entry.split(",") if e.strip()] if _entry else EDGE_HOSTS

    # 2. 拉取优选 API 端点
    api_hosts = fetch_optimal_api_endpoints(OPTIMAL_API)

    # 3. 合并与去重 (保留原始列表顺序)
    combined = []
    seen = set()
    for h in static_hosts + api_hosts:
        if h and h not in seen:
            seen.add(h)
            combined.append(h)

    log("EDGE POOL", f"汇总入口地址池: 静态域名 {len(static_hosts)} 个, API 获取 {len(api_hosts)} 个, 合并有效入口共 {len(combined)} 个")
    return combined if combined else EDGE_HOSTS

# ---------------------------------------------------------------------------
# 筛选 SSTP 节点
# ---------------------------------------------------------------------------
_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)

def to_sstp_nodes(rows):
    nodes = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                cfg = ""
        if not _PROTO_TCP_RE.search(cfg): continue
        m = _REMOTE_RE.search(cfg)
        if not m: continue
        port = int(m.group(1))
        if not (1 <= port <= 65535): continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append({"host": host, "port": port, "ip": r["ip"], "country": r["country_long"], "country_code": r["country_short"]})
    return nodes

def dedupe(nodes):
    seen = set()
    out = []
    for n in nodes:
        key = (n["host"].lower(), n["port"], "sstp")
        if key in seen: continue
        seen.add(key)
        out.append(n)
    return out

# ---------------------------------------------------------------------------
# 检测 Worker
# ---------------------------------------------------------------------------
def classify_network(host, exit_org, is_datacenter=None):
    if is_datacenter is True: return "datacenter"
    if is_datacenter is False: return "residential"
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS): return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS): return "residential"
    h = host.lower()
    if h.startswith("public-vpn"): return "datacenter"
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h): return "residential"
    return "unknown"

def check_one(node, session):
    url = WORKER_CHECK_URL + quote(f"{node['host']}:{node['port']}", safe="")
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"
    try:
        r = session.get(url, timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
        if r.status_code != 200:
            out["error"] = f"HTTP {r.status_code}"
            out["worker_error"] = True
            return out
        j = r.json()
        ok = bool(j.get("success"))
        out["success"] = ok
        out["status"] = "success" if ok else "failed"
        out["latency_ms"] = j.get("responseTime")
        out["colo"] = j.get("colo")
        out["error"] = (None if ok else (j.get("error") or j.get("message") or "check failed"))
        exit_info = j.get("exit") or {}
        if exit_info:
            asn = exit_info.get("asn") or {}
            org = asn.get("org") or asn.get("name") or ""
            out["exit"] = {
                "ip": exit_info.get("ip"),
                "country": exit_info.get("country"),
                "country_code": exit_info.get("country_code"),
                "city": exit_info.get("city"),
                "continent": exit_info.get("continent"),
                "asn": asn.get("asn"),
                "org": org,
                "type": asn.get("type"),
                "is_datacenter": exit_info.get("is_datacenter"),
            }
            out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
        else:
            out["residential"] = classify_network(out["host"], None, None)
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["worker_error"] = True
        return out

def check_all(nodes, session):
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n, session) for n in nodes]
        for fut in as_completed(futures):
            results.append(fut.result())
    return results

# ---------------------------------------------------------------------------
# 生成数据
# ---------------------------------------------------------------------------
def build_outputs(results, raw_count, sstp_count, source):
    available = [r for r in results if r.get("success")]
    countries = {}
    for n in available:
        c = n["country"] or "未知"
        countries.setdefault(c, {"code": n["country_code"] or "?", "nodes": []})["nodes"].append(n)

    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "checked": len(results),
        "success": len(available),
        "failed": len(results) - len(available),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n["residential"] == "residential"),
        "datacenter_est": sum(1 for n in available if n["residential"] == "datacenter"),
    }
    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n["residential"] == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n["residential"] == "datacenter")
        grp["nodes"].sort(key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"]))
        by_country[name] = grp

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "worker": WORKER_CHECK_URL,
        "stats": stats,
        "countries": by_country,
        "available": available,
    }
    return data

def iter_named_nodes(data, edge_hosts):
    """
    按国家 + 住宅/机房 分类生成命名节点，与 nodes.txt / clash 分组保持一致。
    产出: (name, entry, node_dict)
    """
    countries = data["countries"]
    edge = edge_hosts or ["127.0.0.1:443"]
    idx = 0
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            name = f"{zh}-住宅-{i:02d}"
            yield name, entry, n
        for i, n in enumerate(dc_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            name = f"{zh}-机房-{i:02d}"
            yield name, entry, n


def build_nodes_text(data, edge_hosts):
    """
    生成纯节点行版本 (无注释): 每行 = 入口地址#名字$sstp://...
    """
    lines = []
    for name, entry, n in iter_named_nodes(data, edge_hosts):
        lines.append(f"{entry}#{name}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


def build_clash_config(data, edge_hosts):
    """
    生成与 warp-masque.yaml 类似风格的 mihomo/Clash Meta 配置：
    - proxies: 所有可用 SSTP 节点（按国家-住宅/机房命名）
    - proxy-groups: 节点选择 / 手动切换 / 自动选择 / 故障转移 + 常用应用分流组
    - 完整 rule-providers + rules（沿用 ACL4SSR 风格）
    """
    named = list(iter_named_nodes(data, edge_hosts))
    proxy_names = [name for name, _, _ in named]

    proxies = []
    for name, _entry, n in named:
        proxies.append({
            "name": name,
            "type": "sstp",
            "server": n["host"],
            "port": n["port"],
            "username": "vpn",
            "password": "vpn",
            "skip-cert-verify": True,
            "udp": True,
        })

    # 核心策略组（完全对齐 warp-masque 结构）
    proxy_groups = [
        {
            "name": "🚀 节点选择",
            "type": "select",
            "proxies": ["♻️ 自动选择", "🔄 故障转移", "☑️ 手动切换", "DIRECT"],
        },
        {
            "name": "☑️ 手动切换",
            "type": "select",
            "proxies": proxy_names if proxy_names else ["DIRECT"],
        },
        {
            "name": "♻️ 自动选择",
            "type": "url-test",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
            "lazy": False,
            "proxies": proxy_names if proxy_names else ["DIRECT"],
        },
        {
            "name": "🔄 故障转移",
            "type": "fallback",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 180,
            "proxies": proxy_names if proxy_names else ["DIRECT"],
        },
        # 应用分流组（与 warp-masque 保持一致）
        {
            "name": "📹 油管视频",
            "type": "select",
            "proxies": ["🚀 节点选择", "♻️ 自动选择", "🔄 故障转移", "☑️ 手动切换", "DIRECT"],
        },
        {
            "name": "🎥 奈飞视频",
            "type": "select",
            "proxies": ["🚀 节点选择", "♻️ 自动选择", "🔄 故障转移", "☑️ 手动切换", "DIRECT"],
        },
        {
            "name": "🌍 国外媒体",
            "type": "select",
            "proxies": ["🚀 节点选择", "♻️ 自动选择", "🔄 故障转移", "🎯 全球直连"],
        },
        {
            "name": "📲 电报信息",
            "type": "select",
            "proxies": ["🚀 节点选择", "♻️ 自动选择", "🎯 全球直连"],
        },
        {
            "name": "🤖 AI服务",
            "type": "select",
            "proxies": ["🚀 节点选择", "♻️ 自动选择", "🔄 故障转移", "☑️ 手动切换", "DIRECT"],
        },
        {
            "name": "Ⓜ️ 微软服务",
            "type": "select",
            "proxies": ["🎯 全球直连", "🚀 节点选择", "♻️ 自动选择"],
        },
        {
            "name": "🍎 苹果服务",
            "type": "select",
            "proxies": ["🎯 全球直连", "🚀 节点选择", "♻️ 自动选择"],
        },
        {
            "name": "📢 谷歌FCM",
            "type": "select",
            "proxies": ["🚀 节点选择", "🎯 全球直连", "♻️ 自动选择"],
        },
        {
            "name": "🎯 全球直连",
            "type": "select",
            "proxies": ["DIRECT", "🚀 节点选择", "♻️ 自动选择"],
        },
        {
            "name": "🛑 全球拦截",
            "type": "select",
            "proxies": ["REJECT", "DIRECT"],
        },
        {
            "name": "🍃 应用净化",
            "type": "select",
            "proxies": ["REJECT", "DIRECT"],
        },
        {
            "name": "🐟 漏网之鱼",
            "type": "select",
            "proxies": ["🚀 节点选择", "🎯 全球直连", "♻️ 自动选择"],
        },
    ]

    # 可选：按国家再分一组（方便手动选）
    country_groups = {}
    for name, _, n in named:
        code = (n.get("country_code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or code
        if zh not in country_groups:
            country_groups[zh] = []
        country_groups[zh].append(name)
    for zh, names in sorted(country_groups.items()):
        proxy_groups.append({
            "name": f"🏳️ {zh}",
            "type": "select",
            "proxies": names,
        })

    # 住宅 / 机房 两个快捷组
    res_names = [name for name, _, n in named if n.get("residential") == "residential"]
    dc_names = [name for name, _, n in named if n.get("residential") != "residential"]
    if res_names:
        proxy_groups.append({
            "name": "🏠 住宅节点",
            "type": "select",
            "proxies": res_names,
        })
    if dc_names:
        proxy_groups.append({
            "name": "🏢 机房节点",
            "type": "select",
            "proxies": dc_names,
        })

    rule_providers = {
        "rule00": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/cmliu/ACL4SSR/refs/heads/main/Clash/CFnat.list",
            "path": "./ruleset/rule00.list",
        },
        "rule01": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list",
            "path": "./ruleset/rule01.list",
        },
        "rule02": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/UnBan.list",
            "path": "./ruleset/rule02.list",
        },
        "rule03": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanAD.list",
            "path": "./ruleset/rule03.list",
        },
        "rule04": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list",
            "path": "./ruleset/rule04.list",
        },
        "rule05": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/adobe.list",
            "path": "./ruleset/rule05.list",
        },
        "rule06": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/IDM.list",
            "path": "./ruleset/rule06.list",
        },
        "rule07": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/GoogleFCM.list",
            "path": "./ruleset/rule07.list",
        },
        "rule08": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/GoogleCN.list",
            "path": "./ruleset/rule08.list",
        },
        "rule09": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/SteamCN.list",
            "path": "./ruleset/rule09.list",
        },
        "rule10": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Microsoft.list",
            "path": "./ruleset/rule10.list",
        },
        "rule11": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Apple.list",
            "path": "./ruleset/rule11.list",
        },
        "rule12": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Telegram.list",
            "path": "./ruleset/rule12.list",
        },
        "rule13": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/OpenAi.list",
            "path": "./ruleset/rule13.list",
        },
        "rule14": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/juewuy/ShellClash/master/rules/ai.list",
            "path": "./ruleset/rule14.list",
        },
        "rule15": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/Copilot.list",
            "path": "./ruleset/rule15.list",
        },
        "rule16": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/GithubCopilot.list",
            "path": "./ruleset/rule16.list",
        },
        "rule17": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/Claude.list",
            "path": "./ruleset/rule17.list",
        },
        "rule18": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/Gemini.list",
            "path": "./ruleset/rule18.list",
        },
        "rule19": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/YouTube.list",
            "path": "./ruleset/rule19.list",
        },
        "rule20": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Netflix.list",
            "path": "./ruleset/rule20.list",
        },
        "rule21": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ProxyMedia.list",
            "path": "./ruleset/rule21.list",
        },
        "rule22": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/Emby.list",
            "path": "./ruleset/rule22.list",
        },
        "rule23": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ProxyLite.list",
            "path": "./ruleset/rule23.list",
        },
        "rule24": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/CMBlog.list",
            "path": "./ruleset/rule24.list",
        },
        "rule25": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list",
            "path": "./ruleset/rule25.list",
        },
        "rule26": {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaCompanyIp.list",
            "path": "./ruleset/rule26.list",
        },
    }

    # AI 域名直写规则（与 warp-masque 一致）
    ai_domains = [
        "openai.fm", "operator.chatgpt.com", "chat.com", "anthropic.com", "claude.ai",
        "claudeusercontent.com", "gemini.google.com", "aistudio.google.com",
        "generativelanguage.googleapis.com", "notebooklm.google.com", "notebooklm.google",
        "labs.google", "deepmind.com", "x.ai", "grok.com", "meta.ai", "perplexity.ai",
        "pplx.ai", "perplexity.com", "mistral.ai", "chat.mistral.ai", "cohere.com",
        "cohere.ai", "ai21.com", "together.ai", "together.xyz", "fireworks.ai", "groq.com",
        "huggingface.co", "hf.co", "huggingface.js.org", "replicate.com", "replicate.delivery",
        "runpod.io", "modal.com", "openrouter.ai", "poe.com", "quora.com", "cursor.com",
        "cursor.sh", "codeium.com", "windsurf.com", "tabnine.com", "sourcegraph.com",
        "phind.com", "v0.dev", "v0.app", "bolt.new", "lovable.dev", "devin.ai",
        "cognition.ai", "midjourney.com", "stability.ai", "stablediffusionweb.com",
        "leonardo.ai", "runwayml.com", "pika.art", "lumalabs.ai", "ideogram.ai",
        "recraft.ai", "krea.ai", "civitai.com", "elevenlabs.io", "eleven-labs.com",
        "play.ht", "suno.com", "suno.ai", "udio.com", "assemblyai.com", "deepgram.com",
        "you.com", "kagi.com", "exa.ai", "tavily.com", "jasper.ai", "copy.ai",
        "writesonic.com", "notion.so", "langchain.com", "langsmith.com", "wandb.ai",
        "weightsandbiases.com", "pinecone.io", "weaviate.io", "qdrant.tech", "chromadb.com",
        "deepseek.com", "moonshot.cn", "moonshotai.com", "kimi.com", "bigmodel.cn",
        "zhipuai.cn", "z.ai", "minimaxi.com", "minimax.io", "hailuoai.com",
        "siliconflow.cn", "dashscope.aliyuncs.com",
    ]
    rules = [f"DOMAIN-SUFFIX,{d},🤖 AI服务" for d in ai_domains]
    rules.extend([
        "RULE-SET,rule00,🎯 全球直连",
        "RULE-SET,rule01,🎯 全球直连",
        "RULE-SET,rule02,🎯 全球直连",
        "RULE-SET,rule03,🛑 全球拦截",
        "RULE-SET,rule04,🍃 应用净化",
        "RULE-SET,rule05,🍃 应用净化",
        "RULE-SET,rule06,🍃 应用净化",
        "RULE-SET,rule07,📢 谷歌FCM",
        "RULE-SET,rule08,🎯 全球直连",
        "RULE-SET,rule09,🎯 全球直连",
        "RULE-SET,rule10,Ⓜ️ 微软服务",
        "RULE-SET,rule11,🍎 苹果服务",
        "RULE-SET,rule12,📲 电报信息",
        "RULE-SET,rule13,🤖 AI服务",
        "RULE-SET,rule14,🤖 AI服务",
        "RULE-SET,rule15,🤖 AI服务",
        "RULE-SET,rule16,🤖 AI服务",
        "RULE-SET,rule17,🤖 AI服务",
        "RULE-SET,rule18,🤖 AI服务",
        "RULE-SET,rule19,📹 油管视频",
        "RULE-SET,rule20,🎥 奈飞视频",
        "RULE-SET,rule21,🌍 国外媒体",
        "RULE-SET,rule22,🌍 国外媒体",
        "RULE-SET,rule23,🚀 节点选择",
        "RULE-SET,rule24,🚀 节点选择",
        "RULE-SET,rule25,🎯 全球直连",
        "RULE-SET,rule26,🎯 全球直连",
        "GEOIP,LAN,🎯 全球直连,no-resolve",
        "GEOIP,CN,🎯 全球直连",
        "MATCH,🐟 漏网之鱼",
    ])

    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "ipv6": True,
        "unified-delay": True,
        "tcp-concurrent": True,
        "find-process-mode": "off",
        "external-controller": "127.0.0.1:9090",
        "profile": {
            "store-selected": True,
            "store-fake-ip": True,
        },
        "sniffer": {
            "enable": True,
            "sniff": {
                "HTTP": {"ports": [80, "8080-8880"], "override-destination": True},
                "TLS": {"ports": [443, 8443]},
                "QUIC": {"ports": [443, 8443]},
            },
            "skip-domain": ["+.push.apple.com", "+.apple.com"],
        },
        "dns": {
            "enable": True,
            "listen": "0.0.0.0:1053",
            "ipv6": True,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "fake-ip-filter": ["+.lan", "+.local", "*.msftconnecttest.com", "*.msftncsi.com"],
            "default-nameserver": ["223.5.5.5", "119.29.29.29"],
            "nameserver": ["https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"],
            "proxy-server-nameserver": ["https://223.5.5.5/dns-query"],
            "nameserver-policy": {
                "geosite:cn,private": ["https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"],
                "geosite:geolocation-!cn": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
            },
        },
        "proxies": proxies,
        "proxy-groups": proxy_groups,
        "rule-providers": rule_providers,
        "rules": rules,
    }

    # 文件头注释
    header = (
        "# VPN Gate SSTP - mihomo / Clash Meta 配置\n"
        f"# 由 vpngate.py 自动生成，生成时间: {data.get('generated_at', '')}\n"
        f"# 可用节点: {len(proxy_names)} 个（经 Worker 检测）\n"
        "# 节点命名规则: 国家-住宅/机房-序号（与 nodes.txt 一致）\n"
        "# 注意: 需要支持 type: sstp 的内核（部分 mihomo 版本/分支可能需要额外编译或插件）\n"
        "# 若内核不支持 SSTP，可仅使用 nodes.txt 配合 edgetunnel 等工具\n"
        "#\n"
    )
    body = yaml.dump(
        config,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
        width=120,
    )
    return header + body


def write_outputs(data, edge_hosts):
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    html_path = os.path.join(PUBLIC_DIR, "index.html")
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
    else:
        html = (
            "<html><head><meta charset='utf-8'><title>VPN Gate SSTP 节点</title></head>"
            "<body><h1>VPN Gate SSTP 节点</h1><pre id='out'></pre></body>"
            "<script>fetch('data.json').then(r=>r.json()).then(d=>out.textContent=JSON.stringify(d.stats)).catch(e=>out.textContent='加载失败:'+e)</script></html>"
        )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    nodes_path = os.path.join(PUBLIC_DIR, "nodes.txt")
    with open(nodes_path, "w", encoding="utf-8") as f:
        f.write(build_nodes_text(data, edge_hosts))

    clash_path = os.path.join(PUBLIC_DIR, "clash.yaml")
    with open(clash_path, "w", encoding="utf-8") as f:
        f.write(build_clash_config(data, edge_hosts))

    return data_path, html_path, nodes_path, clash_path

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    session = requests.Session()
    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 返回 0 个原始节点 (数据源异常, 不允许生成空结果)")

    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 个原始节点中没有解析出任何 SSTP(TCP) 节点 — 数据格式可能已变化, 需要人工适配")
    uniq = dedupe(sstp_nodes)

    if MAX_CHECK_NODES > 0:
        uniq = uniq[:MAX_CHECK_NODES]

    log("VPN GATE", f"获取原始节点: {raw_count}")
    log("VPN GATE", f"SSTP 节点: {sstp_count}")
    log("VPN GATE", f"去重后: {len(uniq)}")

    log("CLOUDFLARE WORKER", f"提交检测: {len(uniq)} (并发 {CONCURRENCY}, 单请求超时 {CHECK_TIMEOUT}s)")
    t0 = time.time()
    results = check_all(uniq, session)
    elapsed = time.time() - t0

    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f"检测成功: {len(success)}")
    log("CLOUDFLARE WORKER", f"检测失败: {len(failed)}" + (f" (其中 Worker 异常 {len(worker_errors)})" if worker_errors else ""))
    log("CLOUDFLARE WORKER", f"耗时: {elapsed:.1f}s")

    if uniq and not success and len(worker_errors) == len(uniq):
        die("Worker 全部请求异常, 检测服务不可用 — 本次运行判定失败 (不生成空结果)")

    data = build_outputs(results, raw_count, sstp_count, source)
    log("RESULT", f"可用节点: {len(success)}")
    log("RESULT", f"国家数量: {data['stats']['countries']}")

    # 动态拉取 API 并与静态优选域名混合
    edge_hosts = get_combined_edge_hosts()

    data_path, html_path, nodes_path, clash_path = write_outputs(data, edge_hosts)
    log("WEBSITE", f"生成 {os.path.relpath(data_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(html_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(nodes_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(clash_path, REPO_DIR)}")
    log("USAGE", f"自动轮换: 把 {NODES_URL} 填入 edgetunnel 后台「自定义优选IP」框 (一次配置, 之后自动更新)")
    log("USAGE", f"Clash/mihomo: 直接使用 public/clash.yaml（节点已按国家-住宅/机房分类，并含自动/故障转移组）")
    log("WEBSITE", "完成 (GitHub Pages 部署由 workflow 执行)")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
