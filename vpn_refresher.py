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

# 禁用 SSL 警告，以防 IP 直连的证书问题干扰运行
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- 配置 ---
BASE_URL = "https://159.138.8.160"
MAX_LINES = 2000  # 保留的节点最大数量 (约 50-100 个订阅的量)
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


def fetch_and_parse_nodes(subscribe_url):
    """下载订阅链接内容并解析为节点列表"""
    try:
        print(f"[FETCH] Downloading nodes from: {subscribe_url}")
        resp = requests.get(subscribe_url, verify=False, timeout=30)
        resp.raise_for_status()
        
        content = resp.text.strip()
        if not content:
            return []
            
        # 尝试 Base64 解码
        try:
            decoded_content = decode_base64(content)
            # 按行分割，过滤空行
            nodes = [line.strip() for line in decoded_content.split('\n') if line.strip()]
            print(f"[FETCH] Successfully parsed {len(nodes)} nodes.")
            return nodes
        except Exception as e:
            print(f"[ERROR] Base64 decode failed: {e}")
            # 如果解码失败，可能返回的是明文或其他格式，视情况而定
            # 这里假设如果是明文，直接按行分割
            return [line.strip() for line in content.split('\n') if line.strip()]

    except Exception as e:
        print(f"[ERROR] Failed to fetch nodes: {e}")
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
