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

app = Flask(__name__)

# ========== WEB SERVER CONFIG ==========
WEB_SERVER_URL = "http://2.56.246.119:30304/"

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
GARENA = "QllfSEFWRFBSWkFJX1ZVWA=="

# Global counters
SUCCESS_COUNTER = 0
LOCK = threading.Lock()

# Helper functions
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

def create_single_account(name_prefix, pass_prefix):
    try:
        # 1. Generate password
        password = generate_custom_password(pass_prefix)
        
        # 2. Create guest account
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
            return None
            
        uid = response.json().get('uid')
        if not uid:
            return None
        
        # 3. Get token
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
            return None
            
        open_id = response.json().get('open_id')
        access_token = response.json().get("access_token")
        if not open_id or not access_token:
            return None
        
        # 4. Generate name and encode open_id
        name = generate_random_name(name_prefix)
        encoded_open_id = encode_open_id(open_id)
        
        # 5. MajorRegister
        payload = {
            1: name,
            2: access_token,
            3: open_id,
            5: 102000007,
            6: 4,
            7: 1,
            13: 1,
            14: encoded_open_id,
            15: "vi",  # Vietnam only
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
            return None
        
        # 6. Get account_id from JWT
        account_id = "N/A"
        jwt_token = ""
        if len(response.text) > 10:
            jwt_start = response.text.find("eyJ")
            if jwt_start != -1:
                jwt_token = response.text[jwt_start:jwt_start + 150]  # Take first 150 chars
                account_id = decode_jwt_token(jwt_token)
        
        # Return account data if successful
        return {
            "uid": uid,
            "password": password,
            "name": name,
            "account_id": account_id,
            "jwt_token": jwt_token[:100] if jwt_token else "",
            "region": "VN",
            "status": "success"
        }
        
    except Exception as e:
        print(f"Error in create_single_account: {e}")
        return None

def worker(name_prefix, pass_prefix, total_accounts, thread_id):
    global SUCCESS_COUNTER
    
    accounts_created = 0
    while True:
        with LOCK:
            if SUCCESS_COUNTER >= total_accounts:
                break
        
        account = create_single_account(name_prefix, pass_prefix)
        if account:
            # Save to SG server ONLY if account created successfully
            success = WEB_SAVER.save_account(
                name=account["name"],
                password=account["password"],
                uid=account["uid"],
                account_id=account["account_id"],
                region="VN",  # Always Vietnam
                account_type="normal"
            )
            
            with LOCK:
                SUCCESS_COUNTER += 1
                accounts_created += 1
            
            print(f"[Thread {thread_id}] Account {SUCCESS_COUNTER}: {account['name']} | UID: {account['uid']} | Saved to SG: {success}")
        else:
            print(f"[Thread {thread_id}] Failed to create account")
        
        time.sleep(random.uniform(1, 3))  # Random delay to avoid detection
    
    print(f"[Thread {thread_id}] Finished: {accounts_created} accounts created")

@app.route('/create', methods=['GET'])
def create_accounts():
    global SUCCESS_COUNTER
    
    # Get parameters with defaults
    name = request.args.get('name', 'hav')
    password = request.args.get('pass', 'hav')
    count = request.args.get('count', '100')
    thread_count = request.args.get('thread', '2')
    
    # Validate parameters
    try:
        account_count = int(count)
        threads = int(thread_count)
        if account_count <= 0 or threads <= 0:
            return jsonify({"error": "Parameters must be positive numbers"}), 400
    except ValueError:
        return jsonify({"error": "Invalid parameters. Use numbers for count and thread"}), 400
    
    # Limit for Vercel
    if account_count > 5000:
        return jsonify({"error": "Maximum 5000 accounts per request"}), 400
    if threads > 1000:
        return jsonify({"warning": "Threads limited to 5", "threads_used": 5})
        threads = 1000
    
    # Reset counter
    SUCCESS_COUNTER = 0
    
    print(f"🚀 Starting generation: {account_count} accounts for Vietnam region")
    print(f"📝 Name prefix: {name}")
    print(f"🔑 Password prefix: {password}")
    print(f"🧵 Threads: {threads}")
    print(f"🌍 Region: VN (Vietnam only)")
    print(f"💾 Saving to: {WEB_SERVER_URL}")
    
    # Create threads
    start_time = time.time()
    thread_list = []
    
    for i in range(threads):
        t = threading.Thread(
            target=worker, 
            args=(name, password, account_count, i+1)
        )
        t.daemon = True
        t.start()
        thread_list.append(t)
    
    # Wait for completion with timeout (300 seconds for Vercel)
    timeout = 280  # Vercel timeout is 300s
    wait_start = time.time()
    
    while any(t.is_alive() for t in thread_list):
        time.sleep(2)
        
        # Check timeout
        if time.time() - wait_start > timeout:
            print("⏰ Timeout reached, stopping threads")
            break
            
        # Check if target reached
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
        "web_server": WEB_SERVER_URL,
        "note": "All accounts saved to SG server only"
    }
    
    return jsonify(result)

@app.route('/')
def home():
    return jsonify({
        "service": "SAJEEB Account Generator - VN ONLY",
        "version": "1.0",
        "endpoint": "/create",
        "parameters": {
            "name": "Account name prefix (default: hav)",
            "pass": "Password prefix (default: hav)",
            "count": "Number of accounts to create (default: 100)",
            "thread": "Number of threads (default: 2, max: 5)"
        },
        "example": "/create?name=hav&pass=hav&count=1000&thread=20",
        "region": "Vietnam (VN) only",
        "storage": f"Accounts saved to: {WEB_SERVER_URL}"
    })

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "service": "account-generator"})

@app.route('/test', methods=['GET'])
def test():
    """Test endpoint to check if server is working"""
    try:
        # Test create 1 account
        account = create_single_account("test", "test")
        if account:
            return jsonify({
                "status": "success",
                "test_account": {
                    "name": account["name"],
                    "uid": account["uid"],
                    "password": account["password"][:10] + "..."
                }
            })
        else:
            return jsonify({"status": "failed", "message": "Could not create test account"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=3000)


