#!/usr/bin/env python3
"""
从 public/nodes.txt 生成与 warp-masque.yaml 同风格的 mihomo / Clash Meta 配置
============================================================================
用法（在仓库根目录执行）:
    python gen_clash.py

输入:  public/nodes.txt   （由 vpngate.py 生成）
输出:  public/clash-sstp.yaml

不修改 vpngate.py，不影响现有 GitHub Actions 流水线。
"""

import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    print("请先安装 PyYAML:  pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# 路径
# ---------------------------------------------------------------------------
REPO_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = Path(os.environ.get("PUBLIC_DIR", REPO_DIR / "public"))
NODES_TXT = PUBLIC_DIR / "nodes.txt"
OUTPUT_YAML = PUBLIC_DIR / "clash-sstp.yaml"

# ---------------------------------------------------------------------------
# 解析 nodes.txt
# 格式:  入口地址#名字$sstp://vpn:vpn@host:port
# ---------------------------------------------------------------------------
_LINE_RE = re.compile(
    r"^(?P<entry>[^#]+)#(?P<name>.+?)\$sstp://vpn:vpn@(?P<host>[^:]+):(?P<port>\d+)\s*$"
)

def parse_nodes_txt(path: Path):
    if not path.exists():
        print(f"[错误] 找不到 {path}，请先运行 vpngate.py", file=sys.stderr)
        sys.exit(1)

    proxies = []
    names = []
    residential = []
    datacenter = []
    by_country = {}

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue

        name = m.group("name").strip()
        host = m.group("host").strip()
        port = int(m.group("port"))

        proxies.append({
            "name": name,
            "type": "sstp",
            "server": host,
            "port": port,
            "username": "vpn",
            "password": "vpn",
            "skip-cert-verify": True,
            "udp": True,
        })
        names.append(name)

        if "住宅" in name:
            residential.append(name)
        else:
            datacenter.append(name)

        # 提取国家前缀（日本-住宅-01 → 日本）
        country = name.split("-")[0] if "-" in name else "未知"
        by_country.setdefault(country, []).append(name)

    return proxies, names, residential, datacenter, by_country


# ---------------------------------------------------------------------------
# 构建完整配置
# ---------------------------------------------------------------------------
def build_config(proxies, names, residential, datacenter, by_country):
    # 核心策略组
    proxy_groups = [
        {
            "name": "🚀 节点选择",
            "type": "select",
            "proxies": ["♻️ 自动选择", "🔄 故障转移", "☑️ 手动切换", "DIRECT"],
        },
        {
            "name": "☑️ 手动切换",
            "type": "select",
            "proxies": names if names else ["DIRECT"],
        },
        {
            "name": "♻️ 自动选择",
            "type": "url-test",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
            "lazy": False,
            "proxies": names if names else ["DIRECT"],
        },
        {
            "name": "🔄 故障转移",
            "type": "fallback",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 180,
            "proxies": names if names else ["DIRECT"],
        },
    ]

    # 住宅 / 机房
    if residential:
        proxy_groups.append({
            "name": "🏠 住宅节点",
            "type": "select",
            "proxies": residential,
        })
    if datacenter:
        proxy_groups.append({
            "name": "🏢 机房节点",
            "type": "select",
            "proxies": datacenter,
        })

    # 按国家
    for country in sorted(by_country.keys()):
        proxy_groups.append({
            "name": f"🏳️ {country}",
            "type": "select",
            "proxies": by_country[country],
        })

    # 应用分流组（与 warp-masque 对齐）
    app_groups = [
        ("📹 油管视频", ["🚀 节点选择", "♻️ 自动选择", "🔄 故障转移", "☑️ 手动切换", "DIRECT"]),
        ("🎥 奈飞视频", ["🚀 节点选择", "♻️ 自动选择", "🔄 故障转移", "☑️ 手动切换", "DIRECT"]),
        ("🌍 国外媒体", ["🚀 节点选择", "♻️ 自动选择", "🔄 故障转移", "🎯 全球直连"]),
        ("📲 电报信息", ["🚀 节点选择", "♻️ 自动选择", "🎯 全球直连"]),
        ("🤖 AI服务",   ["🚀 节点选择", "♻️ 自动选择", "🔄 故障转移", "☑️ 手动切换", "DIRECT"]),
        ("Ⓜ️ 微软服务", ["🎯 全球直连", "🚀 节点选择", "♻️ 自动选择"]),
        ("🍎 苹果服务", ["🎯 全球直连", "🚀 节点选择", "♻️ 自动选择"]),
        ("📢 谷歌FCM",  ["🚀 节点选择", "🎯 全球直连", "♻️ 自动选择"]),
        ("🎯 全球直连", ["DIRECT", "🚀 节点选择", "♻️ 自动选择"]),
        ("🛑 全球拦截", ["REJECT", "DIRECT"]),
        ("🍃 应用净化", ["REJECT", "DIRECT"]),
        ("🐟 漏网之鱼", ["🚀 节点选择", "🎯 全球直连", "♻️ 自动选择"]),
    ]
    for name, proxies_list in app_groups:
        proxy_groups.append({
            "name": name,
            "type": "select",
            "proxies": proxies_list,
        })

    # rule-providers（精简版，足够日常使用）
    rule_providers = {
        "rule00": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": "https://raw.githubusercontent.com/cmliu/ACL4SSR/refs/heads/main/Clash/CFnat.list",
            "path": "./ruleset/rule00.list",
        },
        "rule01": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list",
            "path": "./ruleset/rule01.list",
        },
        "rule03": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanAD.list",
            "path": "./ruleset/rule03.list",
        },
        "rule04": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list",
            "path": "./ruleset/rule04.list",
        },
        "rule07": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/GoogleFCM.list",
            "path": "./ruleset/rule07.list",
        },
        "rule10": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Microsoft.list",
            "path": "./ruleset/rule10.list",
        },
        "rule11": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Apple.list",
            "path": "./ruleset/rule11.list",
        },
        "rule12": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Telegram.list",
            "path": "./ruleset/rule12.list",
        },
        "rule13": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/OpenAi.list",
            "path": "./ruleset/rule13.list",
        },
        "rule19": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/YouTube.list",
            "path": "./ruleset/rule19.list",
        },
        "rule20": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Netflix.list",
            "path": "./ruleset/rule20.list",
        },
        "rule21": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ProxyMedia.list",
            "path": "./ruleset/rule21.list",
        },
        "rule25": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list",
            "path": "./ruleset/rule25.list",
        },
        "rule26": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaCompanyIp.list",
            "path": "./ruleset/rule26.list",
        },
    }

    # 常用 AI 域名直写
    ai_domains = [
        "openai.com", "chatgpt.com", "anthropic.com", "claude.ai",
        "gemini.google.com", "aistudio.google.com", "x.ai", "grok.com",
        "perplexity.ai", "mistral.ai", "cohere.com", "groq.com",
        "huggingface.co", "cursor.com", "cursor.sh", "deepseek.com",
        "moonshot.cn", "kimi.com", "siliconflow.cn",
    ]
    rules = [f"DOMAIN-SUFFIX,{d},🤖 AI服务" for d in ai_domains]
    rules += [
        "RULE-SET,rule00,🎯 全球直连",
        "RULE-SET,rule01,🎯 全球直连",
        "RULE-SET,rule03,🛑 全球拦截",
        "RULE-SET,rule04,🍃 应用净化",
        "RULE-SET,rule07,📢 谷歌FCM",
        "RULE-SET,rule10,Ⓜ️ 微软服务",
        "RULE-SET,rule11,🍎 苹果服务",
        "RULE-SET,rule12,📲 电报信息",
        "RULE-SET,rule13,🤖 AI服务",
        "RULE-SET,rule19,📹 油管视频",
        "RULE-SET,rule20,🎥 奈飞视频",
        "RULE-SET,rule21,🌍 国外媒体",
        "RULE-SET,rule25,🎯 全球直连",
        "RULE-SET,rule26,🎯 全球直连",
        "GEOIP,LAN,🎯 全球直连,no-resolve",
        "GEOIP,CN,🎯 全球直连",
        "MATCH,🐟 漏网之鱼",
    ]

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
                "TLS":  {"ports": [443, 8443]},
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
            "nameserver": [
                "https://223.5.5.5/dns-query",
                "https://1.12.12.12/dns-query",
            ],
            "proxy-server-nameserver": ["https://223.5.5.5/dns-query"],
            "nameserver-policy": {
                "geosite:cn,private": [
                    "https://223.5.5.5/dns-query",
                    "https://1.12.12.12/dns-query",
                ],
                "geosite:geolocation-!cn": [
                    "https://1.1.1.1/dns-query",
                    "https://8.8.8.8/dns-query",
                ],
            },
        },
        "proxies": proxies,
        "proxy-groups": proxy_groups,
        "rule-providers": rule_providers,
        "rules": rules,
    }
    return config


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    proxies, names, residential, datacenter, by_country = parse_nodes_txt(NODES_TXT)

    if not proxies:
        print("[警告] nodes.txt 中没有解析到任何节点，仍会生成空配置", file=sys.stderr)

    config = build_config(proxies, names, residential, datacenter, by_country)

    header = (
        "# VPN Gate SSTP - mihomo / Clash Meta 配置\n"
        f"# 由 gen_clash.py 自动生成\n"
        f"# 生成时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"# 节点数量: {len(proxies)}\n"
        "# 数据来源: public/nodes.txt（由 vpngate.py 生成）\n"
        "# 节点命名: 国家-住宅/机房-序号\n"
        "# 注意: 需要支持 type: sstp 的内核；若不支持可只使用 nodes.txt + edgetunnel\n"
        "#\n"
    )

    PUBLIC_DIR.mkdir(parents=True, exist_ok=True)
    body = yaml.dump(
        config,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
        width=120,
    )
    OUTPUT_YAML.write_text(header + body, encoding="utf-8")

    print(f"[完成] 已生成 {OUTPUT_YAML}")
    print(f"       节点总数: {len(proxies)}")
    print(f"       住宅节点: {len(residential)}")
    print(f"       机房节点: {len(datacenter)}")
    print(f"       国家数量: {len(by_country)}")


if __name__ == "__main__":
    main()
