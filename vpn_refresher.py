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

# 禁用 SSL 警告，以防 IP 直连的证书问题干扰运行
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- 配置 ---
BASE_URL = "https://159.138.8.160"
BASE_URL = "https://159.138.8.160"
MAX_LINES = 384  # 保留的节点最大数量
GIST_FILE_NAME = "vpn_subs.txt" # Gist 中的文件名
GIST_FILE_NAME = "vpn_subs.txt" # Gist 中的文件名

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


def is_hong_kong(node_line):
    """检查节点是否为香港节点"""
    keywords = ["香港", "HK", "Hong Kong", "HongKong", "Hongkong"]
    
    try:
        # 1. 处理 VMESS
        if node_line.startswith("vmess://"):
            b64_part = node_line[8:]
            try:
                json_str = decode_base64(b64_part)
                node_data = json.loads(json_str)
                name = node_data.get("ps", "").upper()
                for kw in keywords:
                    if kw.upper() in name:
                        return True
                return False
            except:
                pass # 解码失败，回退到简单字符串匹配
        
        # 2. 处理 SS/Trojan/Vless (检查 URL fragment)
        # 格式: protocol://...@...?#name
        if "#" in node_line:
            name_part = node_line.split("#")[-1]
            try:
                name = urllib.parse.unquote(name_part).upper()
                for kw in keywords:
                    if kw.upper() in name:
                        return True
            except:
                pass
                
        # 3. 兜底：简单字符串匹配 (可能会误杀，但对于 HK 这种关键词风险较小)
        # 如果上面解析都失败了，或者协议不明确，直接查字符串
        upper_line = node_line.upper()
        # 排除协议头，只查内容，避免误杀 key 里的字符 (虽然概率极低)
        # 简单处理：直接查
        # for kw in keywords:
        #     if kw.upper() in upper_line:
        #         return True
        
        return False
        
    except Exception as e:
        print(f"[FILTER] Error checking node: {e}")
        return False


def parse_node_host_port(node_line):
    """解析节点链接，提取 host 和 port"""
    try:
        # 1. VMESS
        if node_line.startswith("vmess://"):
            b64_part = node_line[8:]
            json_str = decode_base64(b64_part)
            data = json.loads(json_str)
            return data.get("add"), data.get("port")
            
        # 2. SS / TROJAN / VLESS
        # 格式通常是 protocol://user:pass@host:port...
        # 或者 ss://base64...
        
        if node_line.startswith("ss://"):
            # SS 有两种格式，一种是 ss://base64(method:pass@host:port)
            # 另一种是 ss://base64(method:pass)@host:port
            body = node_line[5:].split("#")[0]
            if "@" in body:
                # 格式: method:pass@host:port
                # 这里 body 可能是 base64(method:pass)@host:port
                part = body.split("@")[-1]
                if ":" in part:
                    host_str, port_str = part.split(":", 1)
                    return host_str, int(port_str.split("/")[0].split("?")[0])
            else:
                # 纯 base64
                decoded = decode_base64(body)
                # 解码后可能是 method:pass@host:port
                if "@" in decoded:
                    part = decoded.split("@")[-1]
                    if ":" in part:
                        host_str, port_str = part.split(":", 1)
                        return host_str, int(port_str)
                        
        # 通用 URL 解析 (Trojan, Vless)
        if "://" in node_line and not node_line.startswith("vmess://") and not node_line.startswith("ss://"):
            parsed = urllib.parse.urlparse(node_line)
            return parsed.hostname, parsed.port

    except Exception as e:
        # print(f"[PARSE] Failed to parse node: {e}")
        pass
    return None, None


def smart_connectivity_check(host, port, timeout=3, retries=2):
    """
    智能连通性检查 (仿 Quantumult X 机制)
    - Timeout: 3秒 (与 QX 默认一致)
    - Retries: 重试机制，避免网络抖动误杀
    """
    if not host or not port:
        return False, 9999
        
    for i in range(retries):
        try:
            start_time = time.time()
            sock = socket.create_connection((host, int(port)), timeout=timeout)
            latency = (time.time() - start_time) * 1000
            sock.close()
            return True, latency
        except:
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
                    # 1. 剔除香港节点
                    if is_hong_kong(node):
                        continue
                        
                    # 2. 测速/连通性检查 (QX 风格)
                    host, port = parse_node_host_port(node)
                    if host and port:
                        is_alive, latency = smart_connectivity_check(host, port)
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
                    if is_hong_kong(n):
                        continue
                    host, port = parse_node_host_port(n)
                    if host and port:
                        is_alive, _ = smart_connectivity_check(host, port)
                        if is_alive:
                            filtered_nodes.append(n)
                    else:
                        filtered_nodes.append(n)

                if filtered_nodes:
                    return filtered_nodes

        except Exception as e:
            print(f"[ERROR] Failed to fetch from {url}: {e}")
            
    return []


def update_gist(new_nodes):
    """读取 Gist 现有内容，在顶部插入新节点，并保持最大行数"""
    gist_id = os.environ.get('GIST_ID')
    token = os.environ.get('GIST_TOKEN')

    if not gist_id or not token:
        print("[ERROR] GIST_ID or GIST_TOKEN environment variables not found.")
        return False

    if not new_nodes:
        print("[GIST] No new nodes to update.")
        return False

    api_url = f'https://api.github.com/gists/{gist_id}'
    headers = {'Authorization': f'token {token}'}

    try:
        # 1. 读取旧数据
        print(f"[GIST] Reading existing Gist content...")
        r = requests.get(api_url, headers=headers)
        r.raise_for_status()
        current_gist = r.json()
        
        # 尝试从指定文件名获取内容
        old_content = current_gist['files'].get(GIST_FILE_NAME, {}).get('content', '')
        
        # 2. 处理内容：去空行
        current_nodes = [line.strip() for line in old_content.split('\n') if line.strip()]
        
        # 3. 插入新数据到顶部 (去重)
        # 为了保持顺序，我们先把新节点加进去，然后用 dict.fromkeys 去重保持顺序
        # 新节点在前
        combined_nodes = new_nodes + current_nodes
        unique_nodes = list(dict.fromkeys(combined_nodes))
        
        print(f"[GIST] Merged {len(new_nodes)} new nodes with {len(current_nodes)} existing nodes. Total unique: {len(unique_nodes)}")

        # 4. 截断：只保留前 MAX_LINES 行
        if len(unique_nodes) > MAX_LINES:
            unique_nodes = unique_nodes[:MAX_LINES]
            print(f"[GIST] Pool trimmed to top {MAX_LINES} nodes.")

        final_content = '\n'.join(unique_nodes)

        # 5. 上传更新
        payload = {
            'files': {
                GIST_FILE_NAME: {
                    'content': final_content
                }
            }
        }
        print(f"[GIST] Updating Gist {gist_id}...")
        requests.patch(api_url, headers=headers, json=payload)
        print("✅ Gist updated successfully!")
        return True

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Gist API operation failed: {str(e)}")
        return False
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred during Gist update: {str(e)}")
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
