# -*- coding: utf-8 -*-
"""
56idc.net 多账号登录脚本
"""

import os
import re
import time
import base64
import json
from io import BytesIO
from curl_cffi import requests

# 验证码识别相关导入
try:
    from PIL import Image
    import pytesseract
    CAPTCHA_OCR_AVAILABLE = True
    print("✅ 验证码识别功能已启用 (OCR)")
except ImportError:
    CAPTCHA_OCR_AVAILABLE = False
    print("⚠️ 验证码识别功能不可用，请安装: pip install Pillow pytesseract")

# 配置部分
LOGIN_URL = "https://56idc.net/login"
LOGOUT_URL = "https://56idc.net/logout.php"

# SOCKS5 代理配置
socks5_proxy_url = os.environ.get("SOCKS5_PROXY", "")
proxy_config = {
    "http": socks5_proxy_url,
    "https": socks5_proxy_url
} if socks5_proxy_url else {}

if socks5_proxy_url:
    print(f"🌐 已配置 SOCKS5 代理: {socks5_proxy_url[:20]}...")
else:
    print("🌐 未配置代理，使用直连")

# Telegram 配置
telegram_bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
chat_id = os.environ.get("TG_CHAT_ID", "")
thread_id = os.environ.get("THREAD_ID", "")
telegram_api_url = os.environ.get("TELEGRAM_API_URL", "https://api.telegram.org")

if telegram_bot_token and chat_id:
    print("✅ 已配置 Telegram 通知")
else:
    print("⚠️ 未配置 Telegram 通知，将仅显示控制台输出")

# 多账号配置 - 从外部JSON字符串获取
accounts_json = os.environ.get("ACCOUNTS_JSON", "")

if not accounts_json:
    print("❌ 未找到账号配置！")
    print("请设置环境变量 ACCOUNTS_JSON，格式如下：")
    print('[{"username":"user1","password":"pass1"},{"username":"user2","password":"pass2"}]')
    exit(1)

try:
    ACCOUNTS = json.loads(accounts_json)
    if not isinstance(ACCOUNTS, list) or not ACCOUNTS:
        raise ValueError("账号配置必须是非空数组")
    
    # 验证每个账号配置并自动生成name
    for i, acc in enumerate(ACCOUNTS):
        if not isinstance(acc, dict) or not acc.get("username") or not acc.get("password"):
            raise ValueError(f"第{i+1}个账号配置无效，必须包含username和password字段")
        acc["name"] = f"账号{i+1}"  # 自动生成名称
            
except json.JSONDecodeError as e:
    print(f"❌ JSON格式错误: {e}")
    print("请检查 ACCOUNTS_JSON 环境变量的JSON格式")
    exit(1)
except ValueError as e:
    print(f"❌ 配置错误: {e}")
    exit(1)

print(f"✅ 已加载 {len(ACCOUNTS)} 个账号配置")

def send_telegram_notification(token, chat_id, message):
    """发送 Telegram 通知"""
    if not token or not chat_id:
        print("⚠️ Telegram 配置不全，跳过发送通知")
        return False
    
    api_url = f'{telegram_api_url}/bot{token}/sendMessage'
    notification_data = {
        'chat_id': chat_id,
        'text': message
    }
    
    if thread_id:
        notification_data['message_thread_id'] = thread_id
    
    try:
        response = requests.post(
            api_url, 
            json=notification_data, 
            timeout=30, 
            proxies=proxy_config
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('ok'):
                print(f"✅ Telegram 通知发送成功")
                return True
            else:
                print(f"❌ Telegram API 返回错误: {result.get('description', '未知错误')}")
        else:
            print(f"❌ Telegram 请求失败: HTTP {response.status_code}")
        
        return False
        
    except Exception as error:
        print(f"❌ Telegram 通知发送失败: {error}")
        return False

def recognize_captcha(session, captcha_url):
    """识别验证码图片"""
    if not CAPTCHA_OCR_AVAILABLE:
        print("❌ 验证码识别功能不可用")
        return None
    
    try:
        print(f"🖼️ 正在下载验证码图片: {captcha_url}")
        
        # 下载验证码图片
        response = session.get(captcha_url, proxies=proxy_config, timeout=15)
        
        if response.status_code != 200:
            print(f"❌ 下载验证码图片失败: HTTP {response.status_code}")
            return None
        
        # 使用PIL打开图片
        image = Image.open(BytesIO(response.content))
        
        # 图片预处理（提高OCR识别率）
        # 转为灰度图
        if image.mode != 'L':
            image = image.convert('L')
        
        # 放大图片提高清晰度
        width, height = image.size
        image = image.resize((width * 3, height * 3), Image.Resampling.LANCZOS)
        
        # 使用阈值化提高对比度
        from PIL import ImageEnhance
        enhancer = ImageEnhance.Contrast(image)
        image = enhancer.enhance(2.0)
        
        print("🔍 正在使用OCR识别验证码...")
        
        # 使用pytesseract识别文字
        # 配置参数：只识别数字和字母，针对6位验证码优化
        custom_config = r'--oem 3 --psm 8 -c tessedit_char_whitelist=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        captcha_text = pytesseract.image_to_string(image, config=custom_config).strip()
        
        # 清理识别结果
        captcha_text = re.sub(r'[^a-zA-Z0-9]', '', captcha_text)
        
        if captcha_text and len(captcha_text) == 6:  # 验证码为6位
            print(f"✅ 验证码识别成功: {captcha_text}")
            return captcha_text
        elif captcha_text and len(captcha_text) != 6:
            print(f"⚠️ 验证码识别位数不正确 (期望6位，实际{len(captcha_text)}位): '{captcha_text}'")
            # 如果识别结果接近6位，尝试修正
            if 4 <= len(captcha_text) <= 8:
                print(f"🔧 尝试使用部分识别结果: {captcha_text}")
                return captcha_text
            return None
        else:
            print(f"❌ 验证码识别失败，未识别到有效内容")
            return None
            
    except Exception as error:
        print(f"❌ 验证码识别失败: {error}")
        return None

def create_session():
    """创建会话对象，模拟真实浏览器"""
    session = requests.Session(impersonate="chrome120")
    
    # 模拟真实浏览器的完整请求头
    session.headers.update({
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        'Accept-Language': "zh-CN,zh;q=0.9,en;q=0.8",
        'Accept-Encoding': "gzip, deflate, br",
        'Connection': "keep-alive",
        'Upgrade-Insecure-Requests': "1",
        'Sec-Fetch-Dest': "document",
        'Sec-Fetch-Mode': "navigate",
        'Sec-Fetch-Site': "none",
        'Sec-Fetch-User': "?1",
        'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        'sec-ch-ua-mobile': "?0",
        'sec-ch-ua-platform': '"Windows"',
        'Cache-Control': "max-age=0"
    })
    return session

def get_csrf_token_and_captcha_info(session):
    """获取CSRF token和验证码信息"""
    try:
        response = session.get(LOGIN_URL, proxies=proxy_config, timeout=30)
        if response.status_code == 200:
            result = {'csrf_token': None, 'captcha_url': None, 'has_captcha': False}
            
            # 查找CSRF token - 只检测name=token
            csrf_pattern = r'<input[^>]*name=["\']token["\'][^>]*value=["\']([^"\'>]+)["\']'
            
            match = re.search(csrf_pattern, response.text, re.IGNORECASE)
            if match:
                token = match.group(1)
                result['csrf_token'] = token
                print(f"🔑 获取到CSRF token: {token[:10]}...")
            
            # 查找验证码图片URL (优先使用具体的ID)
            captcha_patterns = [
                r'<img[^>]*id=["\']inputCaptchaImage["\'][^>]*src=["\']([^"\'>]+)["\']',
                r'<img[^>]*src=["\']([^"\'>]+)["\'][^>]*id=["\']inputCaptchaImage["\']'
            ]
            
            for i, pattern in enumerate(captcha_patterns):
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    captcha_url = match.group(1)
                    if not captcha_url.startswith('http'):
                        if captcha_url.startswith('/'):
                            captcha_url = f"https://56idc.net{captcha_url}"
                        else:
                            captcha_url = f"https://56idc.net/{captcha_url}"
                    result['captcha_url'] = captcha_url
                    result['has_captcha'] = True
                    if i < 2:  # 前两个是具体ID的模式
                        print(f"🖼️ 检测到验证码图片 (ID: inputCaptchaImage): {captcha_url}")
                    else:
                        print(f"🖼️ 检测到验证码图片: {captcha_url}")
                    break
            
            # 检查是否存在验证码相关的input字段 (优先使用具体的ID和name)
            captcha_input_patterns = [
                r'<input[^>]*id=["\']inputCaptcha["\']',
                r'<input[^>]*name=["\']code["\']'  # 新增支持name=code
            ]
            
            for i, pattern in enumerate(captcha_input_patterns):
                if re.search(pattern, response.text, re.IGNORECASE):
                    result['has_captcha'] = True
                    if i == 0:  # inputCaptcha ID
                        print("🔍 检测到验证码输入字段 (ID: inputCaptcha)")
                    elif i == 1:  # name=code
                        print("🔍 检测到验证码输入字段 (name: code)")
                    else:
                        print("🔍 检测到验证码输入字段")
                    break
            
            if not result['csrf_token']:
                print("⚠️ 未找到CSRF token")
            
            if result['has_captcha']:
                print("⚠️ 该网站需要验证码，当前脚本无法自动处理")
            else:
                print("✅ 未检测到验证码要求")
            
            return result
        else:
            print(f"❌ 访问登录页面失败: HTTP {response.status_code}")
            return None
    except Exception as error:
        print(f"❌ 获取登录信息失败: {error}")
        return None

def login_account(session, account):
    """登录单个账号，模拟真实用户操作"""
    print(f"\n🔑 开始登录: {account['name']} ({account['username']})")
    
    try:
        # 获取CSRF token和验证码信息
        login_info = get_csrf_token_and_captcha_info(session)
        
        if not login_info:
            print(f"❌ {account['name']} 获取登录信息失败")
            return False
        
        # 如果需要验证码，尝试识别和填写
        captcha_code = None
        if login_info['has_captcha']:
            if not CAPTCHA_OCR_AVAILABLE:
                print(f"❌ {account['name']} 登录失败: 需要验证码但OCR功能不可用")
                return False
            
            if login_info['captcha_url']:
                print(f"🤖 {account['name']} 检测到验证码，尝试自动识别...")
                captcha_code = recognize_captcha(session, login_info['captcha_url'])
                
                if not captcha_code:
                    print(f"❌ {account['name']} 登录失败: 验证码识别失败")
                    return False
            else:
                print(f"❌ {account['name']} 登录失败: 检测到验证码但未找到图片URL")
                return False
        
        # 重新获取登录页面以查找submit按钮
        print("🔍 查找登录submit按钮...")
        login_page_response = session.get(LOGIN_URL, proxies=proxy_config, timeout=30)
        
        if login_page_response.status_code != 200:
            print(f"❌ {account['name']} 获取登录页面失败: HTTP {login_page_response.status_code}")
            return False
        
        # 查找submit按钮和表单action
        submit_patterns = [
            r'<input[^>]*type=["\']submit["\'][^>]*>',
            r'<button[^>]*type=["\']submit["\'][^>]*>.*?</button>',
            r'<button[^>]*[^>]*>.*?登录.*?</button>',
            r'<input[^>]*value=["\'][^"\'>]*登录[^"\'>]*["\'][^>]*>'
        ]
        
        submit_found = False
        for pattern in submit_patterns:
            if re.search(pattern, login_page_response.text, re.IGNORECASE):
                submit_found = True
                print("✅ 找到submit按钮")
                break
        
        if not submit_found:
            print(f"⚠️ 未找到submit按钮，使用默认提交方式")
        
        # 查找表单action（提交URL）- 优先查找name=login-form的表单
        form_action = LOGIN_URL  # 默认使用登录URL
        form_patterns = [
            # 优先查找name=login-form的表单
            r'<form[^>]*name=["\']login-form["\'][^>]*action=["\']([^"\'>]+)["\'][^>]*>',
            r'<form[^>]*action=["\']([^"\'>]+)["\'][^>]*name=["\']login-form["\'][^>]*>',
            # 通用表单检测
            r'<form[^>]*action=["\']([^"\'>]+)["\'][^>]*>',
            r'<form[^>]*method=["\']post["\'][^>]*action=["\']([^"\'>]+)["\']'
        ]
        
        for i, pattern in enumerate(form_patterns):
            match = re.search(pattern, login_page_response.text, re.IGNORECASE)
            if match:
                action_url = match.group(1)
                if action_url and not action_url.startswith('#'):
                    if action_url.startswith('/'):
                        form_action = f"https://56idc.net{action_url}"
                    elif not action_url.startswith('http'):
                        form_action = f"https://56idc.net/{action_url}"
                    else:
                        form_action = action_url
                    
                    if i < 2:  # 前两个是name=login-form的模式
                        print(f"✅ 找到login-form表单提交URL: {form_action}")
                    else:
                        print(f"✅ 找到表单提交URL: {form_action}")
                    break
        
        # 模拟用户填写表单的过程
        print("✍️ 模拟填写登录表单...")
        time.sleep(1)  # 模拟填写用户名的时间
        
        # 准备登录数据
        login_data = {
            "username": account["username"],
            "password": account["password"],
            "email": account["username"],  # 有些网站用email字段
            "login": account["username"],   # 备用字段
        }
        
        # 如果有验证码，添加到登录数据中
        if captcha_code:
            login_data["code"] = captcha_code
            print(f"✍️ 验证码已填入: {captcha_code}")
        
        # 如果有CSRF token，添加到数据中
        if login_info['csrf_token']:
            login_data["token"] = login_info['csrf_token']
        
        time.sleep(1)  # 模拟填写密码的时间
        
        # 设置请求头，模拟真实表单提交
        headers = {
            'Origin': "https://56idc.net",
            'Referer': LOGIN_URL,
            'Content-Type': "application/x-www-form-urlencoded",
            'Sec-Fetch-Dest': "document",
            'Sec-Fetch-Mode': "navigate",
            'Sec-Fetch-Site': "same-origin",
            'Sec-Fetch-User': "?1",
            'Upgrade-Insecure-Requests': "1"
        }
        
        # 模拟用户点击submit按钮
        print("🖱️ 模拟点击submit按钮进行登录...")
        time.sleep(0.5)  # 模拟点击前的短暂停留
        
        # 提交登录表单到正确的URL
        response = session.post(
            form_action,
            data=login_data,
            headers=headers,
            proxies=proxy_config,
            timeout=60,
            allow_redirects=True
        )
        
        # 模拟等待服务器响应
        time.sleep(2)
        
        # 检查登录结果
        if response.status_code == 200:
            # 检查登录成功的标志
            success_indicators = [
                "dashboard", "控制台", "欢迎", "welcome", "logout", "注销",
                "用户中心", "个人中心", "管理面板", "profile"
            ]
            
            response_text = response.text.lower()
            login_success = any(indicator in response_text for indicator in success_indicators)
            
            # 检查登录失败的标志
            error_indicators = [
                "用户名或密码错误", "登录失败", "invalid", "error", "incorrect",
                "用户不存在", "密码错误", "验证失败", "login failed"
            ]
            
            login_failed = any(indicator in response_text for indicator in error_indicators)
            
            if login_success and not login_failed:
                print(f"✅ {account['name']} 登录成功")
                return True
            elif login_failed:
                print(f"❌ {account['name']} 登录失败: 用户名或密码错误")
                return False
            else:
                # 检查是否被重定向到其他页面
                if response.url != LOGIN_URL:
                    print(f"✅ {account['name']} 登录成功 (重定向到: {response.url})")
                    return True
                else:
                    print(f"⚠️ {account['name']} 登录状态不明确")
                    return False
        else:
            print(f"❌ {account['name']} 登录请求失败: HTTP {response.status_code}")
            return False
            
    except Exception as error:
        print(f"❌ {account['name']} 登录异常: {error}")
        return False

def logout_account(session, account):
    """注销账号，模拟点击注销按钮"""
    print(f"😴 模拟用户在管理面板浏览...")
    time.sleep(2)
    
    print(f"😪 模拟点击注销按钮: {account['name']}...")
    
    try:
        # 先获取仪表盘页面，查找注销按钮
        print("🔍 查找注销按钮...")
        dashboard_response = session.get(
            "https://56idc.net/clientarea.php", 
            proxies=proxy_config, 
            timeout=30,
            headers={
                'Sec-Fetch-Dest': "document",
                'Sec-Fetch-Mode': "navigate",
                'Sec-Fetch-Site': "same-origin"
            }
        )
        
        if dashboard_response.status_code == 200:
            # 查找注销按钮的链接
            logout_pattern = r'<[^>]*id=["\']Secondary_Navbar-Account-Logout["\'][^>]*(?:href=["\']([^"\'>]+)["\']|onclick=["\']([^"\'>]+)["\'])?[^>]*>'
            match = re.search(logout_pattern, dashboard_response.text, re.IGNORECASE)
            
            if match:
                logout_url = match.group(1) if match.group(1) else LOGOUT_URL
                if not logout_url.startswith('http'):
                    if logout_url.startswith('/'):
                        logout_url = f"https://56idc.net{logout_url}"
                    else:
                        logout_url = f"https://56idc.net/{logout_url}"
                
                print(f"✅ 找到注销按钮，模拟点击: {logout_url}")
                time.sleep(0.5)
                
                # 模拟点击注销按钮
                response = session.get(
                    logout_url,
                    proxies=proxy_config,
                    timeout=30,
                    headers={
                        'Referer': "https://56idc.net/clientarea.php",
                        'Sec-Fetch-Dest': "document",
                        'Sec-Fetch-Mode': "navigate",
                        'Sec-Fetch-Site': "same-origin",
                        'Sec-Fetch-User': "?1"
                    }
                )
                
                if response.status_code in [200, 302]:
                    print(f"✅ {account['name']} 注销成功")
                    return True
                else:
                    print(f"⚠️ {account['name']} 注销响应异常: HTTP {response.status_code}")
            else:
                print(f"⚠️ 未找到指定的注销按钮 (ID: Secondary_Navbar-Account-Logout)")
                # 尝试默认注销方式
                response = session.get(LOGOUT_URL, proxies=proxy_config, timeout=30)
                if response.status_code in [200, 302]:
                    print(f"✅ {account['name']} 使用默认方式注销成功")
                    return True
        
        print(f"⚠️ {account['name']} 注销失败")
        return False
        
    except Exception as error:
        print(f"❌ {account['name']} 注销异常: {error}")
        return False

def main():
    """主函数"""
    print("🚀 开始多账号登录测试")
    print(f"🎯 目标网站: {LOGIN_URL}")
    
    login_results = []
    
    for i, account in enumerate(ACCOUNTS, 1):
        print(f"\n{'='*50}")
        print(f"处理第 {i}/{len(ACCOUNTS)} 个账号")
        
        # 为每个账号创建独立的会话
        session = create_session()
        
        # 尝试登录
        login_success = login_account(session, account)
        
        if login_success:
            # 模拟用户登录后的停留时间
            print(f"😴 模拟用户使用服务中...")
            time.sleep(3)  # 模拟用户在系统中的停留时间
            
            # 注销账号
            logout_account(session, account)
            
            login_results.append({
                'account': account['name'],
                'status': '成功'
            })
        else:
            login_results.append({
                'account': account['name'],
                'status': '失败'
            })
        
        # 模拟不同用户操作间的间隔时间
        if i < len(ACCOUNTS):
            print(f"⏳ 等待 5 秒后处理下一个账号...")
            time.sleep(5)  # 增加间隔时间，模拟真实用户操作
    
    # 输出汇总结果
    print(f"\n{'='*50}")
    print("📊 登录测试汇总:")
    print(f"总计: {len(ACCOUNTS)} 个账号")
    
    success_count = sum(1 for result in login_results if result['status'] == '成功')
    fail_count = len(login_results) - success_count
    
    print(f"✅ 成功: {success_count} 个")
    print(f"❌ 失败: {fail_count} 个")
    
    print("\n详细结果:")
    for result in login_results:
        status_icon = "✅" if result['status'] == '成功' else "❌"
        print(f"  {status_icon} {result['account']}: {result['status']}")
    
    # 发送 Telegram 通知
    if telegram_bot_token and chat_id:
        summary_message = f"56idc.net 多账号登录汇总：\n\n📊 总计: {len(ACCOUNTS)} 个账号\n✅ 成功: {success_count} 个\n❌ 失败: {fail_count} 个"
        
        if success_count > 0:
            success_accounts = [result['account'] for result in login_results if result['status'] == '成功']
            summary_message += f"\n\n✅ 成功登录的账号：\n" + "\n".join([f"{i}. {acc}" for i, acc in enumerate(success_accounts, 1)])
        
        if fail_count > 0:
            failed_accounts = [result['account'] for result in login_results if result['status'] == '失败']
            summary_message += f"\n\n❌ 登录失败的账号：\n" + "\n".join([f"{i}. {acc}" for i, acc in enumerate(failed_accounts, 1)])
        
        send_telegram_notification(telegram_bot_token, chat_id, summary_message)

if __name__ == "__main__":
    main()