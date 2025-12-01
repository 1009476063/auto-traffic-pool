#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitHub Actions 自动获取 VPN 订阅链接并更新 Gist 脚本
频率：每 10 分钟
保留：100 条最新的订阅链接
"""

import random
import json
import os
import sys
import ssl
import urllib.request
import urllib.parse
import time
import requests
import urllib3 # 用于禁用警告
import base64
import binascii
import socket
import datetime
import hashlib
import concurrent.futures

# 禁用 SSL 警告，以防 IP 直连的证书问题干扰运行
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- 配置 ---
BASE_URL = "https://159.138.8.160"
BASE_URL = "https://159.138.8.160"
MAX_LINES = 300  # 限制保留的节点数量 (针对 AI/流媒体优化，保留更多优质节点)
GIST_FILENAME = "vpn_subs.txt" # Gist 中的文件名

# 从环境变量获取 Gist 配置
GIST_ID = os.environ.get('GIST_ID')
GIST_TOKEN = os.environ.get('GIST_TOKEN')

# --- 核心逻辑函数 ---

def generate_random_device_id():
    """生成随机设备ID，确保每次请求都是一个新的身份"""
    def _generate_hex(length):
        return ''.join(random.choices('0123456789abcdef', k=length))
    
    # 格式模仿您的脚本，确保兼容性
    device_id = f"{random.randint(100000, 999999):06d}.{_generate_hex(8)}{_generate_hex(4)}{_generate_hex(4)}{_generate_hex(12)}"
    return device_id


def login_and_get_subscribe_url():
    """执行登录并获取订阅链接的全过程"""
    try:
        # 1. 登录获取 token
        random_invite = str(random.randint(1000000000, 9999999999))
        device_id = generate_random_device_id()
        
        print(f"[AUTH] Generated Device ID: {device_id}")
        
        login_url = f"{BASE_URL}/api/v1/passport/auth/loginByDeviceId"
        payload = {
            "invite_token": random_invite,
            "device_id": device_id
        }
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Shadowrocket/1082 CFNetwork/1333.0.4 Darwin/21.5.0"
        }
        
        # 使用 requests 库进行 POST 请求，简化 SSL 跳过操作
        response = requests.post(login_url, json=payload, headers=headers, verify=False, timeout=15)
        response.raise_for_status() # 检查 HTTP 状态码
        
        data = response.json()
        auth_data = data.get("data", {}).get("auth_data")
        
        if not auth_data:
            print(f"[AUTH] Login failed: {data}")
            return None
                
        print("[AUTH] Login successful. Fetching subscribe URL...")

        # 2. 获取订阅链接
        sub_url_api = f"{BASE_URL}/api/v1/user/getSubscribe"
        headers["Authorization"] = auth_data
        
        sub_resp = requests.get(sub_url_api, headers=headers, verify=False, timeout=15)
        sub_resp.raise_for_status() # 检查 HTTP 状态码
        
        sub_data = sub_resp.json()
        subscribe_url = sub_data.get("data", {}).get("subscribe_url")

        if subscribe_url:
            print(f"[SUCCESS] New URL obtained: {subscribe_url}")
            return subscribe_url
        else:
            print(f"[ERROR] Failed to extract subscribe_url: {sub_data}")
            return None
                
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] HTTP Request failed: {str(e)}")
        return None
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {str(e)}")
        return None


def decode_base64(data):
    """处理可能带或不带 padding 的 Base64 字符串"""
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')


def should_exclude_node(node_line):
    """检查节点是否需要过滤 (香港、免费、到期提示等)"""
    keywords = [
        # 1. 地区过滤 (AI/流媒体不友好地区)
        "香港", "HK", "Hong Kong", "HongKong", "Hongkong", # OpenAI/Claude 常封锁 HK
        "CN", "China", "回国", "中国", # 无法访问外网
        "RU", "Russia", "俄罗斯", # 制裁/封锁
        "IR", "Iran", "伊拉克", "伊朗", # 封锁
        "KP", "North Korea", "朝鲜",
        
        # 2. 质量/营销过滤
        "免费", "Free", "网站", "地址", "频道", "群组",
        "套餐到期", "长期有效", "剩余流量", "距离下次重置", "过期时间"
    ]
    
    try:
        # 0. 全局递归解码匹配 (最强力、最通用的过滤)
        # 循环解码最多 3 次，防止双重/三重编码
        current_line = node_line
        for _ in range(3):
            try:
                decoded = urllib.parse.unquote(current_line)
                if decoded == current_line:
                    break # 解码后无变化，停止
                current_line = decoded
                
                # 检查关键词
                upper_line = current_line.upper()
                for kw in keywords:
                    if kw.upper() in upper_line:
                        return True
            except:
                break

        # 1. 处理 VMESS (JSON base64)
        if node_line.startswith("vmess://"):
            b64_part = node_line[8:]
            try:
                json_str = decode_base64(b64_part)
                node_data = json.loads(json_str)
                name = node_data.get("ps", "").upper()
                for kw in keywords:
                    if kw.upper() in name:
                        return True
            except:
                pass 
        
        return False
        
    except Exception as e:
        print(f"[FILTER] Error checking node: {e}")
        return False
        
    except Exception as e:
        print(f"[FILTER] Error checking node: {e}")
        return False


def parse_node_host_port(node_line):
    """解析节点链接，提取 host, port, is_tls, sni, password, protocol"""
    try:
        # 1. VMESS
        if node_line.startswith("vmess://"):
            b64_part = node_line[8:]
            json_str = decode_base64(b64_part)
            data = json.loads(json_str)
            host = data.get("add")
            port = data.get("port")
            
            # 判断是否为 TLS
            is_tls = False
            sni = host # 默认 SNI 为 host
            
            if data.get("tls") == "tls" or str(port) == "443":
                is_tls = True
                # 优先获取 sni，其次是 host (伪装域名)，最后是 add
                if data.get("sni"):
                    sni = data.get("sni")
                elif data.get("host"):
                    sni = data.get("host")
                    
            return host, port, is_tls, sni, None, "vmess"
            
        # 2. SS / TROJAN / VLESS
        if node_line.startswith("ss://"):
            # SS 通常不是 TLS
            body = node_line[5:].split("#")[0]
            if "@" in body:
                part = body.split("@")[-1]
                if ":" in part:
                    host_str, port_str = part.split(":", 1)
                    return host_str, int(port_str.split("/")[0].split("?")[0]), False, None, None, "ss"
            else:
                decoded = decode_base64(body)
                if "@" in decoded:
                    part = decoded.split("@")[-1]
                    if ":" in part:
                        host_str, port_str = part.split(":", 1)
                        return host_str, int(port_str), False, None, None, "ss"
                        
        # 3. Trojan (通常是 TLS)
        if node_line.startswith("trojan://"):
            parsed = urllib.parse.urlparse(node_line)
            # 提取 SNI (peer 或 sni 参数)
            params = urllib.parse.parse_qs(parsed.query)
            sni = parsed.hostname
            if 'sni' in params:
                sni = params['sni'][0]
            elif 'peer' in params:
                sni = params['peer'][0]
            
            password = parsed.username
            return parsed.hostname, parsed.port, True, sni, password, "trojan"
            
        # 4. VLESS
        if node_line.startswith("vless://"):
            parsed = urllib.parse.urlparse(node_line)
            is_tls = False
            sni = parsed.hostname
            
            if "security=tls" in node_line or parsed.port == 443:
                is_tls = True
                params = urllib.parse.parse_qs(parsed.query)
                if 'sni' in params:
                    sni = params['sni'][0]
                    
            return parsed.hostname, parsed.port, is_tls, sni, None, "vless"

    except Exception as e:
        pass
    return None, None, False, None, None, "unknown"


def check_trojan_google_access(host, port, password, sni, timeout=5):
    """
    Trojan 协议真连接测试 (连接 www.google.com:80)
    """
    try:
        # 1. 建立 TLS 连接
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        sock = context.wrap_socket(sock, server_hostname=sni)
        
        # 2. 构建 Trojan 请求
        # 格式: [hex(sha224(password))] + [CRLF] + [Cmd(1=CONNECT)] + [AddrType(3=Domain)] + [Addr] + [Port] + [CRLF]
        password_hash = hashlib.sha224(password.encode()).hexdigest()
        
        # 目标: www.google.com:80
        target_host = "www.google.com"
        target_port = 80
        
        # Cmd(1) + AddrType(3) + Len(1) + Host + Port(2)
        # \x01 (CONNECT)
        # \x03 (DOMAIN)
        # \x0E (Length of www.google.com = 14)
        # www.google.com
        # \x00\x50 (Port 80)
        
        # BUG FIX: Trojan 协议要求发送 56 字节的 hex 字符串，而不是 28 字节的 raw bytes
        req = password_hash.encode() + b"\r\n"
        req += b"\x01\x03" # CONNECT + DOMAIN
        req += len(target_host).to_bytes(1, 'big')
        req += target_host.encode()
        req += target_port.to_bytes(2, 'big')
        req += b"\r\n"
        
        sock.sendall(req)
        
        # 3. 发送 HTTP 请求
        # 如果 Trojan 代理成功，我们现在就相当于直连了 Google
        http_req = f"HEAD / HTTP/1.1\r\nHost: {target_host}\r\nUser-Agent: curl/7.64.1\r\nConnection: close\r\n\r\n"
        sock.sendall(http_req.encode())
        
        # 4. 读取响应
        response = sock.recv(1024)
        sock.close()
        
        if b"HTTP/1.1 200" in response or b"HTTP/1.1 301" in response or b"HTTP/1.1 302" in response:
            return True, "Google OK"
        elif response:
            return True, "Alive (No Google)" # 有响应但不是 Google 预期响应，可能被劫持或 Google 封锁
        else:
            return False, "No Response"
            
    except Exception as e:
        return False, str(e)


def smart_connectivity_check(host, port, is_tls=False, sni=None, password=None, protocol="unknown", timeout=3, retries=2):
    """
    智能连通性检查
    - Trojan: 尝试连接 Google
    - 其他: SSL 握手 + HTTP Probe
    """
    if not host or not port:
        return False, 9999
        
    # 如果没有指定 SNI，默认使用 host
    if not sni:
        sni = host
        
    # 优先尝试 Trojan 真连接测试
    if protocol == "trojan" and password:
        is_google, msg = check_trojan_google_access(host, port, password, sni)
        if is_google:
            return True, 100 # 假定延迟
        
        # 如果 Google 失败，不要直接放弃！
        # 可能是 GitHub Action 环境无法连接 Google，或者节点暂时被 Google 封锁但仍可用。
        # 回退到普通的 SSL 握手 + HTTP Probe 检查。
        # print(f"[DEBUG] Trojan Google check failed for {host}: {msg}. Falling back to SSL probe.")
        pass

    for i in range(retries):
        try:
            start_time = time.time()
            # 建立 TCP 连接
            sock = socket.create_connection((host, int(port)), timeout=timeout)
            
            # 如果是 TLS 节点，尝试 SSL 握手
            if is_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # 关键：使用正确的 SNI 进行握手
                sock = context.wrap_socket(sock, server_hostname=sni)
                
                # HTTP Probe (活跃探测) - 移除，因为会导致大量误杀
                # 只要 SSL 握手成功，就认为节点是活的
                pass
            
            latency = (time.time() - start_time) * 1000
            sock.close()
            return True, latency
        except Exception as e:
            if i == retries - 1:
                return False, 9999
            time.sleep(0.5)
            continue
            
    return False, 9999


def fetch_and_parse_nodes(subscribe_url):
    """下载订阅链接内容并解析为节点列表"""
    
    urls_to_try = [subscribe_url]
    
    # 尝试构造 IP 直连 URL (Bypass DNS/CDN blocking)
    try:
        parsed = urllib.parse.urlparse(subscribe_url)
        # 替换域名为 IP (从 BASE_URL 提取，这里直接硬编码配置里的 IP)
        ip_host = "159.138.8.160" 
        if parsed.hostname != ip_host:
            new_url = parsed._replace(netloc=ip_host).geturl()
            urls_to_try.append(new_url)
            print(f"[FETCH] Added fallback IP URL: {new_url}")
    except Exception as e:
        print(f"[FETCH] Failed to construct fallback URL: {e}")

    for url in urls_to_try:
        try:
            print(f"[FETCH] Downloading nodes from: {url}")
            
            # 轮询 UA，模拟不同客户端
            user_agents = [
                "Shadowrocket/1082 CFNetwork/1333.0.4 Darwin/21.5.0",
                "2rayNG/1.8.5",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ]
            
            content = ""
            for ua in user_agents:
                try:
                    headers = {"User-Agent": ua}
                    print(f"[FETCH] Trying UA: {ua[:20]}...")
                    resp = requests.get(url, headers=headers, verify=False, timeout=30)
                    resp.raise_for_status()
                    content = resp.text.strip()
                    if content:
                        print(f"[FETCH] Success with UA: {ua[:20]}...")
                        break
                except Exception as e:
                    print(f"[FETCH] Failed with UA {ua[:20]}: {e}")
            
            if not content:
                print(f"[FETCH] Failed to get content from {url}")
                continue

            print(f"[DEBUG] Raw content length: {len(content)}")
            
            # 尝试 Base64 解码
            try:
                decoded_content = decode_base64(content)
                nodes = [line.strip() for line in decoded_content.split('\n') if line.strip()]
                
                # 过滤香港节点 + 测速筛选
                filtered_nodes = []
                print(f"[CHECK] Starting connectivity check for {len(nodes)} nodes...")
                
                for node in nodes:
                    # 1. 剔除黑名单节点 (HK, 免费, 到期提示)
                    if should_exclude_node(node):
                        continue
                        
                    # 2. 测速/连通性检查 (QX 风格 + SSL + SNI)
                    host, port, is_tls, sni, password, protocol = parse_node_host_port(node)
                    if host and port:
                        is_alive, latency = smart_connectivity_check(host, port, is_tls, sni, password, protocol)
                        if is_alive:
                            # print(f"[ALIVE] {host}:{port} - {latency:.0f}ms")
                            filtered_nodes.append(node)
                        else:
                            # print(f"[DEAD] {host}:{port}")
                            pass
                    else:
                        # 解析失败的节点，保守起见保留
                        filtered_nodes.append(node)
                
                if filtered_nodes:
                    print(f"[FETCH] Successfully parsed {len(filtered_nodes)} nodes (Filtered {len(nodes) - len(filtered_nodes)} bad/HK nodes).")
                    return filtered_nodes
            except Exception as e:
                print(f"[ERROR] Base64 decode failed: {e}")
                # 可能是明文
                nodes = [line.strip() for line in content.split('\n') if line.strip()]
                
                # 同样过滤
                filtered_nodes = []
                for n in nodes:
                    if should_exclude_node(n):
                        continue
                    
                    host, port, is_tls, sni, password, protocol = parse_node_host_port(n)
                    if host and port:
                        is_alive, _ = smart_connectivity_check(host, port, is_tls, sni, password, protocol)
                        if is_alive:
                            filtered_nodes.append(n)
                    else:
                        filtered_nodes.append(n)

                if filtered_nodes:
                    return filtered_nodes

        except Exception as e:
            print(f"[ERROR] Failed to fetch from {url}: {e}")
            
    return []


def check_nodes_parallel(nodes, max_workers=20):
    """
    并行检测节点连通性
    """
    valid_nodes = []
    print(f"[CHECK] Starting parallel connectivity check for {len(nodes)} nodes with {max_workers} workers...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_node = {}
        
        for node in nodes:
            # 提交测速任务
            future = executor.submit(smart_connectivity_check, *parse_node_host_port(node))
            future_to_node[future] = node
        
        for future in concurrent.futures.as_completed(future_to_node):
            node = future_to_node[future]
            try:
                is_alive, latency = future.result()
                if is_alive:
                    valid_nodes.append(node)
            except Exception as e:
                pass
                
    print(f"[CHECK] Finished. {len(valid_nodes)}/{len(nodes)} nodes are alive.")
    return valid_nodes


def sort_nodes(nodes):
    """
    对节点进行分类和排序
    优先级: 
    1. 协议: Trojan (Top) > VMess/SS (Mid) > VLESS (Bottom)
    2. 名称: 字母顺序
    """
    def get_protocol_score(node_line):
        if node_line.startswith("trojan://"): return 1
        if node_line.startswith("vmess://"): return 2
        if node_line.startswith("ss://"): return 2
        if node_line.startswith("vless://"): return 3
        return 99

    def get_node_name(node_line):
        try:
            if node_line.startswith("vmess://"):
                data = json.loads(decode_base64(node_line[8:]))
                return data.get("ps", "")
            if "#" in node_line:
                return urllib.parse.unquote(node_line.split("#")[-1])
        except:
            pass
        return ""

    # 排序 key: (协议分数, 名称)
    return sorted(nodes, key=lambda n: (get_protocol_score(n), get_node_name(n)))


def update_gist(new_nodes):
    """更新 Gist，全量清洗"""
    if not GIST_TOKEN or not GIST_ID:
        print("[ERROR] GIST_TOKEN or GIST_ID not set.")
        return

    headers = {
        "Authorization": f"token {GIST_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # 1. 获取现有 Gist 内容
    gist_url = f"https://api.github.com/gists/{GIST_ID}"
    try:
        response = requests.get(gist_url, headers=headers)
        response.raise_for_status()
        gist_data = response.json()
        
        existing_content = gist_data['files'][GIST_FILENAME]['content']
        existing_nodes = existing_content.split('\n') if existing_content else []
        
        # 2. 合并去重 (新节点优先)
        # 使用 set 去重，但保持顺序? 不，我们最后会排序
        unique_nodes = list(set(new_nodes + existing_nodes))
        unique_nodes = [n for n in unique_nodes if n.strip()] # 去空行
        
        print(f"[UPDATE] Total unique nodes before check: {len(unique_nodes)}")
        
        # 3. 关键词过滤 (全量)
        clean_nodes = [n for n in unique_nodes if not should_exclude_node(n)]
        print(f"[FILTER] Removed {len(unique_nodes) - len(clean_nodes)} nodes matching blacklist keywords.")
        
        # 4. 全量测速清洗 (并行)
        if clean_nodes:
            final_nodes = check_nodes_parallel(clean_nodes)
        else:
            final_nodes = []
            
        # 5. 排序
        final_nodes = sort_nodes(final_nodes)
        
        # 6. 截断
        if len(final_nodes) > MAX_LINES:
            final_nodes = final_nodes[:MAX_LINES]
            
        print(f"[UPDATE] Final active nodes count: {len(final_nodes)}")
        
        # 7. 更新 Gist
        new_content = '\n'.join(final_nodes)
        
        data = {
            "files": {
                GIST_FILENAME: {
                    "content": new_content
                }
            }
        }
        
        patch_response = requests.patch(f"https://api.github.com/gists/{GIST_ID}", headers=headers, json=data)
        patch_response.raise_for_status()
        print("Gist updated successfully!")
        
    except Exception as e:
        print(f"Error updating Gist: {e}")


def main():
    """主函数，包含随机休眠"""
    # 随机休眠 1-60 秒，避免整点并发被防火墙识别
    sleep_time = random.randint(1, 60)
    print(f"--- Starting in {sleep_time} seconds ---")
    time.sleep(sleep_time)

    subscribe_url = login_and_get_subscribe_url()
    
    if subscribe_url:
        nodes = fetch_and_parse_nodes(subscribe_url)
        if nodes:
            update_gist(nodes)
        else:
            print("[MAIN] No nodes parsed from subscription. Skipping update.")
    else:
        print("\n[MAIN] Failed to get subscribe URL. Aborting Gist update.")
        sys.exit(1)


if __name__ == "__main__":
    main()
