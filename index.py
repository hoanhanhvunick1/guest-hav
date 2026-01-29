import hmac
import hashlib
import requests
import string
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
import base64
import time
from datetime import datetime
import threading
from flask import Flask, request, jsonify
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ========== WEB SERVER CONFIG ==========
WEB_SERVER_URL = "http://sg-sgp05.altr.cc:25403"

class WebSaver:
    def __init__(self, server_url=WEB_SERVER_URL):
        self.server_url = server_url
        self.session = requests.Session()
        self.session.timeout = 30
    
    def save_account(self, name, password, uid, account_id="", region="VN", account_type="normal"):
        try:
            account_data = {
                "name": str(name),
                "password": str(password),
                "uid": str(uid),
                "account_id": str(account_id),
                "region": str(region),
                "type": account_type,
                "timestamp": datetime.now().isoformat()
            }
            
            response = self.session.post(
                f"{self.server_url}/api/save_account",
                json=account_data,
                timeout=30,
                verify=False
            )
            
            return response.status_code == 200
        except Exception as e:
            print(f"Save error: {e}")
            return False

WEB_SAVER = WebSaver()

# Configurations
hex_key = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
key = bytes.fromhex(hex_key)
GARENA = "QllfU0FKRUViX0FIQU1FRA=="

# Global counters
SUCCESS_COUNTER = 0
LOCK = threading.Lock()

# Helper functions (giữ nguyên phần helper functions của bạn)
def generate_custom_password(prefix):
    garena_decoded = base64.b64decode(GARENA).decode('utf-8')
    characters = string.ascii_uppercase + string.digits
    random_part1 = ''.join(random.choice(characters) for _ in range(5))
    random_part2 = ''.join(random.choice(characters) for _ in range(5))
    return f"{prefix}_{random_part1}_{garena_decoded}_{random_part2}"

def EnC_Vr(N):
    if N < 0: 
        return b''
    H = []
    while True:
        BesTo = N & 0x7F 
        N >>= 7
        if N: 
            BesTo |= 0x80
        H.append(BesTo)
        if not N: 
            break
    return bytes(H)

def CrEaTe_VarianT(field_number, value):
    field_header = (field_number << 3) | 0
    return EnC_Vr(field_header) + EnC_Vr(value)

def CrEaTe_LenGTh(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value

def CrEaTe_ProTo(fields):
    packet = bytearray()    
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))           
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(CrEaTe_LenGTh(field, value))           
    return packet

def E_AEs(Pc):
    Z = bytes.fromhex(Pc)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    K = AES.new(key , AES.MODE_CBC , iv)
    R = K.encrypt(pad(Z , AES.block_size))
    return R

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def generate_random_name(base_name):
    exponent_digits = {'0': '⁰', '1': '¹', '2': '²', '3': '³', '4': '⁴', '5': '⁵', '6': '⁶', '7': '⁷', '8': '⁸', '9': '⁹'}
    number = random.randint(1, 99999)
    number_str = f"{number:05d}"
    exponent_str = ''.join(exponent_digits[digit] for digit in number_str)
    return f"{base_name[:7]}{exponent_str}"

def encode_open_id(open_id):
    keystream = [0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37,
                 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30]
    encoded = ""
    for i in range(len(open_id)):
        orig_byte = ord(open_id[i])
        key_byte = keystream[i % len(keystream)]
        result_byte = orig_byte ^ key_byte
        encoded += chr(result_byte)
    return encoded

def decode_jwt_token(jwt_token):
    try:
        parts = jwt_token.split('.')
        if len(parts) >= 2:
            payload_part = parts[1]
            padding = 4 - len(payload_part) % 4
            if padding != 4:
                payload_part += '=' * padding
            decoded = base64.urlsafe_b64decode(payload_part)
            data = json.loads(decoded)
            account_id = data.get('account_id') or data.get('external_id')
            if account_id:
                return str(account_id)
    except:
        pass
    return "N/A"

# ========== ACTIVATION LOGIC FOR VIETNAM ==========
class VietnamActivator:
    def __init__(self):
        self.key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        self.iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 30
        
    def guest_token_vn(self, uid, password):
        """Lấy token guest cho server Vietnam"""
        try:
            url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
            data = {
                "uid": str(uid),
                "password": str(password),
                "response_type": "token",
                "client_type": "2",
                "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
                "client_id": "100067",
            }
            
            headers = {
                "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept-Encoding": "gzip",
                "Connection": "Keep-Alive"
            }
            
            response = self.session.post(url, data=data, headers=headers, timeout=20)
            
            if response.status_code == 200:
                data_json = response.json()
                return data_json.get('access_token'), data_json.get('open_id')
            else:
                print(f"Guest token failed: {response.status_code}")
                return None, None
                
        except Exception as e:
            print(f"Guest token error: {e}")
            return None, None
    
    def major_login_vn(self, access_token, open_id):
        """Đăng nhập chính vào server VN"""
        try:
            url = "https://loginbp.ggblueshark.com/MajorLogin"
            
            # Tạo payload cho Vietnam
            payload = {
                1: "Free Fire Vietnam",
                2: access_token,
                3: open_id,
                5: 102000007,  # App ID cho Vietnam
                6: 4,
                7: 1,
                13: 1,
                14: open_id,  # Không encode cho Vietnam
                15: "vi",  # Ngôn ngữ Vietnamese
                16: 1,
                17: 1
            }
            
            payload_bytes = CrEaTe_ProTo(payload)
            encrypted_payload = E_AEs(payload_bytes.hex())
            
            headers = {
                "Accept-Encoding": "gzip",
                "Authorization": "Bearer",
                "Connection": "Keep-Alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Expect": "100-continue",
                "Host": "loginbp.ggblueshark.com",
                "ReleaseVersion": "OB52",
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
                "X-GA": "v1 1",
                "X-Unity-Version": "2018.4."
            }
            
            response = self.session.post(
                url,
                headers=headers,
                data=encrypted_payload,
                timeout=20
            )
            
            if response.status_code == 200 and len(response.text) > 10:
                # Kiểm tra có JWT token không
                jwt_start = response.text.find("eyJ")
                if jwt_start != -1:
                    return True, response.text[jwt_start:jwt_start + 150]
            
            return False, None
            
        except Exception as e:
            print(f"MajorLogin error: {e}")
            return False, None
    
    def get_login_data_vn(self, jwt_token, access_token, open_id):
        """Gửi request kích hoạt cuối cùng"""
        try:
            url = "https://clientbp.ggblueshark.com/GetLoginData"
            
            # Tạo payload GetLoginData cho Vietnam
            from datetime import datetime
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Base payload (cần điều chỉnh cho Vietnam)
            base_payload = bytes.fromhex(
                '1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131342e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033'
            )
            
            # Replace với thông tin thực tế
            base_payload = base_payload.replace(b"2025-07-30 11:02:51", now.encode())
            base_payload = base_payload.replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", access_token.encode())
            base_payload = base_payload.replace(b"996a629dbcdb3964be6b6978f5d814db", open_id.encode())
            
            payload_hex = base_payload.hex()
            encrypted_payload = encrypt_api(payload_hex)
            
            headers = {
                'Expect': '100-continue',
                'Authorization': f'Bearer {jwt_token}',
                'X-Unity-Version': '2018.4.11f1',
                'X-GA': 'v1 1',
                'ReleaseVersion': 'OB52',
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
                'Host': 'clientbp.ggblueshark.com',
                'Connection': 'close',
                'Accept-Encoding': 'gzip, deflate, br',
            }
            
            response = self.session.post(
                url,
                headers=headers,
                data=bytes.fromhex(encrypted_payload),
                timeout=20
            )
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"GetLoginData error: {e}")
            return False
    
    def activate_account_vn(self, uid, password):
        """Kích hoạt tài khoản Vietnam"""
        print(f"🔧 Attempting to activate account UID: {uid}")
        
        # 1. Lấy guest token
        access_token, open_id = self.guest_token_vn(uid, password)
        if not access_token or not open_id:
            print(f"❌ Failed to get guest token for {uid}")
            return False
        
        # 2. MajorLogin
        login_success, jwt_token = self.major_login_vn(access_token, open_id)
        if not login_success or not jwt_token:
            print(f"❌ MajorLogin failed for {uid}")
            return False
        
        print(f"✅ MajorLogin successful for {uid}")
        
        # 3. GetLoginData (activation)
        activation_success = self.get_login_data_vn(jwt_token, access_token, open_id)
        
        if activation_success:
            print(f"🎉 Account {uid} successfully activated in Vietnam!")
            return True
        else:
            print(f"❌ GetLoginData failed for {uid}")
            return False

VIETNAM_ACTIVATOR = VietnamActivator()

# ========== MODIFIED ACCOUNT CREATION WITH ACTIVATION ==========
def create_and_activate_account(name_prefix, pass_prefix):
    """Tạo account và kích hoạt, chỉ lưu nếu activation thành công"""
    max_attempts = 3  # Số lần thử tạo account mới nếu activation thất bại
    
    for attempt in range(max_attempts):
        try:
            print(f"🔄 Attempt {attempt + 1}/{max_attempts} to create and activate account")
            
            # 1. Tạo password
            password = generate_custom_password(pass_prefix)
            
            # 2. Tạo guest account
            data = f"password={password}&client_type=2&source=2&app_id=100067"
            message = data.encode('utf-8')
            signature = hmac.new(key, message, hashlib.sha256).hexdigest()
            
            headers = {
                "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
                "Authorization": "Signature " + signature,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept-Encoding": "gzip",
                "Connection": "Keep-Alive"
            }
            
            response = requests.post(
                "https://100067.connect.garena.com/oauth/guest/register",
                headers=headers, 
                data=data, 
                timeout=30, 
                verify=False
            )
            
            if response.status_code != 200:
                continue
                
            uid = response.json().get('uid')
            if not uid:
                continue
            
            # 3. Lấy token
            body = {
                "uid": uid,
                "password": password,
                "response_type": "token",
                "client_type": "2",
                "client_secret": key,
                "client_id": "100067"
            }
            
            response = requests.post(
                "https://100067.connect.garena.com/oauth/guest/token/grant",
                headers=headers,
                data=body,
                timeout=30,
                verify=False
            )
            
            if response.status_code != 200:
                continue
                
            open_id = response.json().get('open_id')
            access_token = response.json().get("access_token")
            if not open_id or not access_token:
                continue
            
            # 4. Tạo name
            name = generate_random_name(name_prefix)
            
            # 5. MajorRegister (tạo account trong game)
            payload = {
                1: name,
                2: access_token,
                3: open_id,
                5: 102000007,  # App ID Vietnam
                6: 4,
                7: 1,
                13: 1,
                14: open_id,  # Không encode cho VN
                15: "vi",  # Vietnam
                16: 1,
                17: 1
            }
            
            payload_bytes = CrEaTe_ProTo(payload)
            encrypted_payload = E_AEs(payload_bytes.hex())
            
            headers = {
                "Accept-Encoding": "gzip",
                "Authorization": "Bearer",   
                "Connection": "Keep-Alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Expect": "100-continue",
                "Host": "loginbp.ggblueshark.com",
                "ReleaseVersion": "OB52",
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
                "X-GA": "v1 1",
                "X-Unity-Version": "2018.4."
            }
            
            response = requests.post(
                "https://loginbp.ggblueshark.com/MajorRegister",
                headers=headers,
                data=encrypted_payload,
                verify=False,
                timeout=30
            )
            
            if response.status_code != 200:
                continue
            
            # 6. Lấy account_id từ JWT
            account_id = "N/A"
            jwt_token = ""
            if len(response.text) > 10:
                jwt_start = response.text.find("eyJ")
                if jwt_start != -1:
                    jwt_token = response.text[jwt_start:jwt_start + 150]
                    account_id = decode_jwt_token(jwt_token)
            
            # 7. QUAN TRỌNG: Kích hoạt account trên server Vietnam
            print(f"🔧 Account created: {name} | UID: {uid}")
            print(f"🔄 Attempting activation for Vietnam server...")
            
            activation_success = VIETNAM_ACTIVATOR.activate_account_vn(uid, password)
            
            if activation_success:
                # 8. CHỈ LƯU KHI ACTIVATION THÀNH CÔNG
                account_data = {
                    "uid": uid,
                    "password": password,
                    "name": name,
                    "account_id": account_id,
                    "jwt_token": jwt_token[:100] if jwt_token else "",
                    "region": "VN",
                    "status": "active"
                }
                
                print(f"✅ Activation successful! Account ready for Vietnam server")
                return account_data
            else:
                print(f"❌ Activation failed. Discarding account {uid}")
                # Không lưu, tiếp tục vòng lặp để tạo account mới
                continue
                
        except Exception as e:
            print(f"Error in create_and_activate_account (attempt {attempt + 1}): {e}")
            continue
    
    print(f"⚠️ Failed to create activated account after {max_attempts} attempts")
    return None

def worker(name_prefix, pass_prefix, total_accounts, thread_id):
    global SUCCESS_COUNTER
    
    accounts_created = 0
    while True:
        with LOCK:
            if SUCCESS_COUNTER >= total_accounts:
                break
        
        # Tạo và kích hoạt account
        account = create_and_activate_account(name_prefix, pass_prefix)
        
        if account:
            # CHỈ LƯU KHI ACTIVATION THÀNH CÔNG
            success = WEB_SAVER.save_account(
                name=account["name"],
                password=account["password"],
                uid=account["uid"],
                account_id=account["account_id"],
                region="VN",  # Vietnam
                account_type="active"  # Đánh dấu là đã active
            )
            
            with LOCK:
                SUCCESS_COUNTER += 1
                accounts_created += 1
            
            print(f"[Thread {thread_id}] ✅ Account {SUCCESS_COUNTER}: {account['name']} | UID: {account['uid']} | Active: YES | Saved: {success}")
        else:
            print(f"[Thread {thread_id}] ❌ Failed to create activated account, trying again...")
        
        time.sleep(random.uniform(1, 2))  # Delay ngắn
    
    print(f"[Thread {thread_id}] Finished: {accounts_created} activated accounts created")

@app.route('/create', methods=['GET'])
def create_accounts():
    global SUCCESS_COUNTER
    
    # Get parameters
    name = request.args.get('name', 'hav')
    password = request.args.get('pass', 'hav')
    count = request.args.get('count', '100')
    thread_count = request.args.get('thread', '2')
    
    # Validate
    try:
        account_count = int(count)
        threads = int(thread_count)
        if account_count <= 0 or threads <= 0:
            return jsonify({"error": "Parameters must be positive numbers"}), 400
    except ValueError:
        return jsonify({"error": "Invalid parameters. Use numbers for count and thread"}), 400
    
    # Limit
    if account_count > 5000:
        return jsonify({"error": "Maximum 5000 accounts per request"}), 400
    if threads > 5:
        threads = 5
    
    # Reset counter
    SUCCESS_COUNTER = 0
    
    print(f"🚀 Starting generation with ACTIVATION: {account_count} accounts for Vietnam")
    print(f"📝 Name prefix: {name}")
    print(f"🔑 Password prefix: {password}")
    print(f"🧵 Threads: {threads}")
    print(f"🌍 Region: VN (Vietnam only)")
    print(f"⚡ Activation: REQUIRED before saving")
    print(f"💾 Saving only activated accounts to: {WEB_SERVER_URL}")
    
    # Create threads
    start_time = time.time()
    thread_list = []
    
    for i in range(threads):
        t = threading.Thread(
            target=worker, 
            args=(name, password, account_count, i+1),
            name=f"Worker-{i+1}"
        )
        t.daemon = True
        t.start()
        thread_list.append(t)
    
    # Wait for completion
    timeout = 280
    wait_start = time.time()
    
    while any(t.is_alive() for t in thread_list):
        time.sleep(2)
        
        if time.time() - wait_start > timeout:
            print("⏰ Timeout reached, stopping threads")
            break
            
        with LOCK:
            if SUCCESS_COUNTER >= account_count:
                break
    
    # Calculate stats
    end_time = time.time()
    elapsed = end_time - start_time
    
    result = {
        "status": "completed",
        "accounts_created": SUCCESS_COUNTER,
        "target_accounts": account_count,
        "success_rate": f"{(SUCCESS_COUNTER/account_count*100):.1f}%" if account_count > 0 else "0%",
        "elapsed_time": f"{elapsed:.2f} seconds",
        "speed": f"{SUCCESS_COUNTER/elapsed:.2f} accounts/second" if elapsed > 0 else "0",
        "name_prefix": name,
        "password_prefix": password,
        "threads_used": threads,
        "region": "VN (Vietnam)",
        "activation": "REQUIRED - only activated accounts are saved",
        "web_server": WEB_SERVER_URL,
        "note": "Accounts are activated on Vietnam server before saving"
    }
    
    return jsonify(result)

@app.route('/')
def home():
    return jsonify({
        "service": "SAJEEB Account Generator - VN ONLY WITH ACTIVATION",
        "version": "2.0",
        "endpoint": "/create",
        "parameters": {
            "name": "Account name prefix (default: hav)",
            "pass": "Password prefix (default: hav)",
            "count": "Number of accounts to create (default: 100)",
            "thread": "Number of threads (default: 2, max: 5)"
        },
        "features": {
            "region": "Vietnam (VN) only",
            "activation": "REQUIRED - accounts are activated on Vietnam server",
            "filter": "Only activated accounts are saved",
            "retry": "3 attempts per account creation"
        },
        "example": "/create?name=hav&pass=hav&count=1000&thread=3",
        "storage": f"Only activated accounts saved to: {WEB_SERVER_URL}"
    })

@app.route('/test-activation', methods=['GET'])
def test_activation():
    """Test endpoint để kiểm tra activation"""
    try:
        # Tạo một account test
        print("🧪 Testing account creation and activation...")
        account = create_and_activate_account("test", "test")
        
        if account:
            # Thử lưu để kiểm tra
            save_result = WEB_SAVER.save_account(
                name=account["name"],
                password=account["password"],
                uid=account["uid"],
                account_id=account["account_id"],
                region="VN",
                account_type="active"
            )
            
            return jsonify({
                "status": "success",
                "activation": "passed",
                "account": {
                    "name": account["name"],
                    "uid": account["uid"],
                    "password": account["password"][:10] + "...",
                    "status": "activated"
                },
                "save_to_server": save_result
            })
        else:
            return jsonify({
                "status": "failed", 
                "message": "Could not create and activate test account"
            })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=3000)
