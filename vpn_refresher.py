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
import concurrent.futures

# 禁用 SSL 警告，以防 IP 直连的证书问题干扰运行
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- 配置 ---
BASE_URL = "https://159.138.8.160"
BASE_URL = "https://159.138.8.160"
MAX_LINES = 400  # 保留的节点最大数量
GIST_FILE_NAME = "vpn_subs.txt" # Gist 中的文件名

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
        "香港", "HK", "Hong Kong", "HongKong", "Hongkong", 
        "免费", "Free",
        "套餐到期", "长期有效", "剩余流量"
    ]
    
    try:
        # 0. 全局解码匹配 (最强力、最通用的过滤)
        # 将整个链接解码，直接查关键词。这能解决 VLESS/Trojan 名字在 fragment 里被编码导致漏网的问题
        try:
            decoded_line = urllib.parse.unquote(node_line).upper()
            for kw in keywords:
                if kw.upper() in decoded_line:
                    return True
        except:
            pass

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
    """解析节点链接，提取 host, port, is_tls, sni"""
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
                    
            return host, port, is_tls, sni
            
        # 2. SS / TROJAN / VLESS
        if node_line.startswith("ss://"):
            # SS 通常不是 TLS
            body = node_line[5:].split("#")[0]
            if "@" in body:
                part = body.split("@")[-1]
                if ":" in part:
                    host_str, port_str = part.split(":", 1)
                    return host_str, int(port_str.split("/")[0].split("?")[0]), False, None
            else:
                decoded = decode_base64(body)
                if "@" in decoded:
                    part = decoded.split("@")[-1]
                    if ":" in part:
                        host_str, port_str = part.split(":", 1)
                        return host_str, int(port_str), False, None
                        
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
                
            return parsed.hostname, parsed.port, True, sni
            
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
                    
            return parsed.hostname, parsed.port, is_tls, sni

    except Exception as e:
        pass
    return None, None, False, None


def smart_connectivity_check(host, port, is_tls=False, sni=None, timeout=3, retries=2):
    """
    智能连通性检查 (仿 Quantumult X 机制)
    - Timeout: 3秒
    - Retries: 重试机制
    - SSL Handshake: 使用正确的 SNI 进行握手
    """
    if not host or not port:
        return False, 9999
        
    # 如果没有指定 SNI，默认使用 host
    if not sni:
        sni = host
        
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
            
            latency = (time.time() - start_time) * 1000
            sock.close()
            return True, latency
        except Exception as e:
            # print(f"[DEBUG] Check failed for {host}:{port} (TLS={is_tls}, SNI={sni}): {e}")
            # 如果是最后一次尝试且失败，则返回 False
            if i == retries - 1:
                return False, 9999
            # 否则继续重试
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
                    host, port, is_tls, sni = parse_node_host_port(node)
                    if host and port:
                        is_alive, latency = smart_connectivity_check(host, port, is_tls, sni)
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
                    
                    host, port, is_tls, sni = parse_node_host_port(n)
                    if host and port:
                        is_alive, _ = smart_connectivity_check(host, port, is_tls, sni)
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
        files = gist_data.get("files", {})
        
        existing_content = ""
        if GIST_FILE_NAME in files:
            existing_content = files[GIST_FILE_NAME].get("content", "")
            
        # 解析现有节点 (处理 Base64 或明文)
        existing_nodes = []
        if existing_content:
            try:
                # 尝试 Base64 解码
                decoded = decode_base64(existing_content)
                existing_nodes = [line.strip() for line in decoded.split('\n') if line.strip()]
            except:
                # 可能是明文
                existing_nodes = [line.strip() for line in existing_content.split('\n') if line.strip()]
        
        print(f"[GIST] Found {len(existing_nodes)} existing nodes.")
        
        # 2. 合并新旧节点
        # 新节点在前，旧节点在后
        all_nodes = new_nodes + existing_nodes
        
        # 3. 去重 (保持顺序)
        seen = set()
        unique_nodes = []
        for node in all_nodes:
            if node not in seen:
                unique_nodes.append(node)
                seen.add(node)
                
        # 4. 全量测速清洗 (并行)
        # 只有当总节点数 > 0 时才检查
        if unique_nodes:
            final_nodes = check_nodes_parallel(unique_nodes)
        else:
            final_nodes = []
            
        # 5. 截断到最大数量
        final_nodes = final_nodes[:MAX_LINES]
        
        # 6. 编码并更新
        updated_content = "\n".join(final_nodes)
        base64_content = base64.b64encode(updated_content.encode('utf-8')).decode('utf-8')
        
        data = {
            "files": {
                GIST_FILE_NAME: {
                    "content": base64_content
                }
            }
        }
        
        patch_response = requests.patch(gist_url, headers=headers, json=data)
        patch_response.raise_for_status()
        print(f"[GIST] Successfully updated Gist with {len(final_nodes)} active nodes.")
        return True
        
    except Exception as e:
        print(f"[ERROR] Failed to update Gist: {e}")
        return False


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
