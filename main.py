import random
import time
import ctypes
import threading
import tls_client
import hashlib
import websocket
import base64
import json
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from concurrent.futures import ThreadPoolExecutor, as_completed
from logmagix import Logger, Home
from functools import wraps
import requests.exceptions
from pystyle import Colorate, Colors, Center

with open('config.json') as f:
    config = json.load(f)

DEBUG = config['debug']

log = Logger(prefix=None)

originalInfo = log.info
originalWarning = log.warning
originalFailure = log.failure
originalDebug = log.debug

log.info = lambda msg: print(màu(f"[Hoang Gia Kiet] {msg}"))
log.warning = lambda msg: print(màu(f"[Warning] {msg}"))
log.failure = lambda msg: print(màu(f"[Failure] {msg}"))
log.debug = lambda msg: print(màu(f"[Debug] {msg}")) if DEBUG else None


outputFolder = "output"
if not os.path.exists(outputFolder):
    os.makedirs(outputFolder)


def debug(funcOrMessage, *args, **kwargs) -> callable:
    if callable(funcOrMessage):
        @wraps(funcOrMessage)
        def wrapper(*args, **kwargs):
            result = funcOrMessage(*args, **kwargs)
            if DEBUG:
                log.debug(f"{funcOrMessage.__name__} returned: {result}")
            return result
        return wrapper
    else:
        if DEBUG:
            log.debug(f"Debug: {funcOrMessage}")

def debugResponse(response) -> None:
    debug(response.headers)
    try:
        debug(response.text)
    except:
        debug(response.content)
    debug(response.status_code)

màu = [
    Colors.DynamicMIX([Colors.cyan, Colors.white, Colors.pink])
]

mauu = random.choice(màu)
def màu(text: str) -> str:
    if Colorate and Colors:
        try:
            return Colorate.Horizontal(mauu, text)
        except Exception:
            return text
    return text

def retryWithRateLimit(maxRetries=5, baseDelay=1.0):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(maxRetries + 1):
                try:
                    result = func(*args, **kwargs)
                    
                    if hasattr(result, 'status_code'):
                        if result.status_code == 429: 
                            if attempt < maxRetries:
                                retryAfter = result.headers.get('retry-after')
                                if retryAfter:
                                    try:
                                        waitTime = float(retryAfter)
                                        log.warning(f"Rate limited, đợi {waitTime}s thử lại")
                                        time.sleep(waitTime)
                                        continue
                                    except ValueError:
                                        pass
                                try:
                                    responseData = result.json()
                                    if 'retry_after' in responseData:
                                        waitTime = responseData['retry_after']
                                        log.warning(f"Rate limited, đợi {waitTime}s thử lại")
                                        time.sleep(waitTime)
                                        continue
                                except:
                                    pass
                                log.warning(f"Rate limited, đợi {baseDelay}s thử lại")
                                time.sleep(baseDelay)
                                continue
                            else:
                                log.failure(f"Đã đạt số lần thử lại tối đa cho giới hạn tốc độ. {func.__name__}")
                                return result
                        elif result.status_code in [401, 403]:
                            return result
                    
                    return result
                    
                except (requests.exceptions.RequestException, 
                        websocket.WebSocketException,
                        ConnectionError, 
                        TimeoutError) as e:
                    if attempt < maxRetries:
                        log.warning(f"Lỗi mạng ở {func.__name__}: {str(e)[:100]}...")
                        time.sleep(baseDelay)
                        continue
                    else:
                        log.failure(f"Đã đạt số lần thử lại tối đa cho {func.__name__}: {str(e)[:100]}...")
                        raise e
                except Exception as e:
                    log.failure(f"Lỗi trong {func.__name__}: {str(e)[:100]}...")
                    raise e
            
            return None
        return wrapper
    return decorator

class Miscellaneous:
    @debug
    def randomizeUserAgent(self) -> tuple[str, str, str, str]:
        platforms = {
            "Windows NT 10.0; Win64; x64": "Windows",
            "Windows NT 10.0; WOW64": "Windows",
            "Macintosh; Intel Mac OS X 10_15_7": "Mac OS X",
            "Macintosh; Intel Mac OS X 11_2_3": "Mac OS X",
            "X11; Linux x86_64": "Linux",
            "X11; Linux i686": "Linux",
            "X11; Ubuntu; Linux x86_64": "Linux",
        }

        browsers = [
            ("Chrome", f"{random.randint(128, 140)}.0.{random.randint(1000, 4999)}.0"),
            ("Firefox", f"{random.randint(80, 115)}.0"),
            ("Safari", f"{random.randint(13, 16)}.{random.randint(0, 3)}"),
            ("Edge", f"{random.randint(90, 140)}.0.{random.randint(1000, 4999)}.0"),
        ]

        webkitVersion = f"{random.randint(500, 600)}.{random.randint(0, 99)}"
        platformString = random.choice(list(platforms.keys()))
        platformOs = platforms[platformString]
        browserName, browserVersion = random.choice(browsers)

        if browserName == "Safari":
            userAgent = (
                f"Mozilla/5.0 ({platformString}) AppleWebKit/{webkitVersion} (KHTML, like Gecko) "
                f"Version/{browserVersion} Safari/{webkitVersion}"
            )
        elif browserName == "Firefox":
            userAgent = f"Mozilla/5.0 ({platformString}; rv:{browserVersion}) Gecko/20100101 Firefox/{browserVersion}"
        else:
            userAgent = (
                f"Mozilla/5.0 ({platformString}) AppleWebKit/{webkitVersion} (KHTML, like Gecko) "
                f"{browserName}/{browserVersion} Safari/{webkitVersion}"
            )

        return userAgent, browserName, browserVersion, platformOs

    def encodePublicKey(self, pubKey: rsa.RSAPublicKey) -> str:
        return base64.b64encode(pubKey.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode('utf-8')
    
    def generateNonceProof(self, encryptedNonceB64: str, privKey: rsa.RSAPrivateKey) -> str:
        encNonceBytes = base64.b64decode(encryptedNonceB64)
        
        decNonce = privKey.decrypt(
            encNonceBytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        proofBytes = hashlib.sha256(decNonce).digest()
        proofB64 = base64.urlsafe_b64encode(proofBytes).rstrip(b"=").decode()
        
        return proofB64
    
    def decryptData(self, encryptedDataB64: str, privKey: rsa.RSAPrivateKey) -> bytes | None:
        if not encryptedDataB64:
            return None
        
        payload = base64.b64decode(encryptedDataB64)
        return privKey.decrypt(
            payload,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def parseTokenLine(self, line: str) -> tuple[str, str | None, str]:
        parts = [p for p in line.strip().split(":") if p]
        if not parts:
            raise ValueError("Token đang trống")

        for idx, part in enumerate(parts):
            if len(part) == 72:
                token = part
                identifier = ":".join(parts[:idx]) or None
                return line.strip(), identifier, token

        raise ValueError("Không tìm thấy token hợp lệ có 72 ký tự")

    def maskToken(self, token: str) -> str:
        if len(token) < 8:
            return token
        start = random.randint(0, len(token) - 8)
        return token[:start] + '*' * 8 + token[start + 8:]
    
    class Title:
        def __init__(self) -> None:
            self.running = False
            self.total = 0

        def startTitleUpdates(self, startTime) -> None:
            self.running = True
            def updater():
                while self.running:
                    self.updateTitle(startTime)
                    time.sleep(0.5)
            threading.Thread(target=updater, daemon=True).start()

        def stopTitleUpdates(self) -> None:
            self.running = False

        def updateTitle(self, startTime) -> None: 
            try:
                elapsedTime = round(time.time() - startTime, 2)
                title = f'HoangGiaKiet | Total: {self.total} | Time Elapsed: {elapsedTime}s'

                sanitizedTitle = ''.join(c if c.isprintable() else '?' for c in title)
                ctypes.windll.kernel32.SetConsoleTitleW(sanitizedTitle)
            except Exception as e:
                pass
        def incrementTotal(self):
            self.total += 1

class KietLaBo:
    def __init__(self, misc: Miscellaneous) -> None:
        self.misc = misc
        self.userAgent, self.browserName, self.browserVersion, self.osName = self.misc.randomizeUserAgent()

        self.session = tls_client.Session("chrome_131", random_tls_extension_order=True)
        self.session.headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'origin': 'https://discord.com',
            'referer': 'https://discord.com/channels/@me',
            'sec-ch-ua': f'"{self.browserName}";v="{self.browserVersion.split(".")[0]}", "Not_A Brand";v="99", "Chromium";v="{self.browserVersion.split(".")[0]}"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': f'"{self.osName}"',
            'user-agent': self.userAgent,
            'x-debug-options': 'bugReporterEnabled',
            'x-discord-locale': 'en-US',
            'x-discord-timezone': 'Asia/Tokyo',
            'x-super-properties': self.generateSuperPropreties(
                self.userAgent, self.browserName, self.browserVersion, self.osName
            )
        }

    @debug
    def generateSuperPropreties(self, userAgent, browserName, browserVersion, osName) -> str:
        payload = {
            "os": osName,
            "browser": browserName,
            "device": "",
            "system_locale": "en-US",
            "browser_user_agent": userAgent,
            "browser_version": browserVersion,
            "os_version": "",
            "referrer": "",
            "referring_domain": "",
            "referrer_current": "",
            "referring_domain_current": "",
            "release_channel": "stable",
            "client_build_number": 380213, 
            "client_event_source": None
            }
        
        return base64.b64encode(json.dumps(payload).encode()).decode()
    
    @debug
    @retryWithRateLimit()
    def createHandshake(self, token: str, fingerprint: str) -> bool:
        self.session.headers['authorization'] = token

        response = self.session.post(
            "https://discord.com/api/v9/users/@me/remote-auth", 
            json={'fingerprint': fingerprint},
        )

        debugResponse(response)

        if response.status_code == 200:
            token = response.json().get('handshake_token')

            response =  self.session.post(
                "https://discord.com/api/v9/users/@me/remote-auth/finish", 
                json={'handshake_token': token}
            )

            debugResponse(response)
            
            if response.status_code == 204:
                return True
            
        elif response.status_code == 401:
            return 401
        else:
            log.failure(f"Lỗi khi tạo handshake: {response.text}, {response.status_code}")
        
        return False
    
    @debug
    @retryWithRateLimit()
    def logout(self, token: str) -> bool:
        self.session.headers['authorization'] = token
     
        response = self.session.post(
            'https://discord.com/api/v9/auth/logout',
            json={'provider': None, 'voip_provider': None}
        )

        debugResponse(response)

        if response.status_code == 204:
            return True
        else:
            log.failure(f"Lỗi khi đăng xuất: {response.text}, {response.status_code}")
        
        return False
    
    @debug
    @retryWithRateLimit()
    def getUserInfo(self, token: str) -> dict | None:
        self.session.headers['authorization'] = token
        
        response = self.session.get('https://discord.com/api/v9/users/@me')
        
        debugResponse(response)
        
        if response.status_code == 200:
            userData = response.json()
            return {
                'name': userData.get('global_name') or userData.get('username'),
                'username': userData.get('username'),
                'uid': userData.get('id'),
                'dob': userData.get('date_of_birth'),
                'locale': userData.get('locale')
            }
        else:
            log.failure(f"Lỗi khi get info: {response.text}, {response.status_code}")
            return None
    
    @debug
    @retryWithRateLimit()
    def cloneToken(self, token: str) -> str | None:
        try:
            ws = websocket.create_connection(
                "wss://remote-auth-gateway.discord.gg/?v=2",
                header=[
                    f"Authorization: {token}",
                    "Origin: https://discord.com"
                ]
            )

            helloPayload = ws.recv()
            debug(f"Received Hello: {helloPayload}")

            privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            publicKey = privateKey.public_key()
            encryptionKey = self.misc.encodePublicKey(publicKey)
            
            ws.send(json.dumps({"op": "init", "encoded_public_key": encryptionKey}))
            
            noncePayloadStr = ws.recv()
            debug(f"Received Nonce Payload: {noncePayloadStr}")
            noncePayload = json.loads(noncePayloadStr)
            encryptedNonceB64 = noncePayload.get("encrypted_nonce")

            if not encryptedNonceB64:
                log.failure("Ko lấy được nonce mã hóa")
                ws.close()
                return None

            nonceProof = self.misc.generateNonceProof(encryptedNonceB64, privateKey)
            
            ws.send(json.dumps({"op": "nonce_proof", "proof": nonceProof}))
            
            fingerprintPayloadStr = ws.recv()
            debug(f"Đã thu thập được dấu vân tay: {fingerprintPayloadStr}")
            fingerprintPayload = json.loads(fingerprintPayloadStr)
            fingerprint = fingerprintPayload.get("fingerprint")
            
            if fingerprint:
                handshakeSuccess = self.createHandshake(token, fingerprint)
                if not handshakeSuccess:
                    log.failure("Quá trình tạo xác thực đã thất bại sau khi nhận được dấu vân tay.")
                    ws.close()
                    return None
                elif handshakeSuccess == 401:
                    return 401
                
                userPayloadStr = ws.recv()
                debug(f"Đã nhận được dữ liệu người dùng: {userPayloadStr}")
                userPayload = json.loads(userPayloadStr)
                encryptedUserPayload = userPayload.get("encrypted_user_payload")
                
                if encryptedUserPayload:
                  
                    decryptedUserInfo = self.misc.decryptData(encryptedUserPayload, privateKey)
                    debug(f"Thông tin người dùng đã được giải mã: {decryptedUserInfo}")
                else:
                    log.warning("Không nhận được dữ liệu người dùng được mã hóa (có thể không sao).")
                
                ticketPayloadStr = ws.recv()
                debug(f"Đã nhận dữ liệu ticket: {ticketPayloadStr}")
                ticketPayload = json.loads(ticketPayloadStr)
                ticket = ticketPayload.get("ticket")
                
                ws.close() 

                if ticket:
                    for attempt in range(5):
                        response = self.session.post(
                            "https://discord.com/api/v9/users/@me/remote-auth/login", 
                            json={"ticket": ticket}
                        )

                        debugResponse(response)
                        
                        if response.status_code == 200:
                            encryptedTokenB64 = response.json().get("encrypted_token")
                            if encryptedTokenB64:
                                 newTokenBytes = self.misc.decryptData(encryptedTokenB64, privateKey)
                                 if newTokenBytes:
                                     return newTokenBytes.decode('utf-8')
                                 else:
                                     log.failure("Không thể giải mã token new.")
                            else:
                                log.failure("Phản hồi không chứa 'encrypted_token'.")
                            break
                        elif response.status_code == 429: 
                            if attempt < 4: 
                                retryAfter = response.headers.get('retry-after')
                                waitTime = 1.0
                                
                                if retryAfter:
                                    try:
                                        waitTime = float(retryAfter)
                                    except ValueError:
                                        pass
                                else:
                                    try:
                                        responseData = response.json()
                                        if 'retry_after' in responseData:
                                            waitTime = responseData['retry_after']
                                    except:
                                        pass
                                time.sleep(waitTime)
                                continue
                            else:
                                break
                        else:
                             break

                else:
                    log.failure("ko nhận được ticket.")
            else:
                log.failure("Không nhận được dấu vân tay.")
            
            ws.close() 
            return None
        except websocket.WebSocketException as e:
            log.failure(f"Lỗi WebSocket: {e}")
            return None
        except json.JSONDecodeError as e:
            log.failure(f"Không thể giải mã JSON từ websocket.: {e}")
            return None
        except Exception as e:
            if "Ciphertext length must be equal to key size" in str(e):
                 log.failure(f"RSA Decryption error: {e}. Check received data format.")
            else:
                 log.failure(f"An unknown error occurred in cloneToken: {e}")
            try:
                if ws and ws.connected:
                    ws.close()
            except: 
                pass
            return None

def BoMayLaHoangGiaKiet(originalLine: str, misc: Miscellaneous, fileLock: threading.Lock, titleUpdater: Miscellaneous.Title, totalTokens: int) -> bool:
    startTime = time.time()
    maxRetries = 5
    
    for attempt in range(maxRetries + 1):
        try:
            rawLine, _, token = misc.parseTokenLine(originalLine)
            tokenChanger = KietLaBo(misc)

            newToken = tokenChanger.cloneToken(token)

            if newToken == 401:
                log.failure(f"Token không hợp lệ: {token[:30]}...")
                with fileLock:
                    with open(f"{outputFolder}/invalid.txt", "a", encoding="utf-8") as f:
                        f.write(f"{rawLine}\n")
                return False

            elif newToken:
                if tokenChanger.logout(token):
                    checkInfo = tokenChanger.getUserInfo(newToken)
                    checkStatus = "Live" if checkInfo else "Dead"
                    infoDisplay = f"{checkInfo['name']} - {checkInfo['username']}" if checkInfo else "N/A"
                    maskedToken = misc.maskToken(newToken)
                    log.info(f"[STT: {titleUpdater.total + 1}/{totalTokens}] [Check Token: {checkStatus}] [Info: {infoDisplay}]")
                    log.info(f"Change Token Successfully: {maskedToken}")

                    titleUpdater.incrementTotal()
                    newLine = rawLine.replace(token, newToken, 1)

                    with fileLock:
                        with open(f"{outputFolder}/tokennew.txt", "a", encoding="utf-8") as f:
                            f.write(f"{newLine}\n")
                        with open("input/tokens.txt", "r", encoding="utf-8") as f:
                            tokens = [line.strip() for line in f if line.strip()]
                        if rawLine in tokens:
                            tokens.remove(rawLine)
                            with open("input/tokens.txt", "w", encoding="utf-8") as f:
                                f.write('\n'.join(tokens) + '\n')

                    return True
                else:
                    if attempt < maxRetries:
                        log.warning(f"Đăng xuất không thành công, đang thử lại...")
                        time.sleep(1.0)
                        continue
                    else:
                        log.failure(f"Không thể đăng xuất token gốc sau khi {maxRetries} thử: {token[:30]}...")
                        with fileLock:
                            with open(f"{outputFolder}/failed.txt", "a", encoding="utf-8") as f:
                                f.write(f"{rawLine}\n")
            else:
                if attempt < maxRetries:
                    log.warning(f"Không thể sao chép token, đang thử lại...")
                    time.sleep(1.0)
                    continue
                else:
                    log.failure(f"Không thể sao chép token sau {maxRetries} thử: {token[:30]}...")
                    with fileLock:
                        with open(f"{outputFolder}/failed.txt", "a", encoding="utf-8") as f:
                            f.write(f"{rawLine}\n")

        except Exception as e:
            if attempt < maxRetries:
                log.warning(f"Lỗi khi cập nhật token, đang thử lại...: {str(e)[:100]}...")
                time.sleep(1.0)
                continue
            else:
                log.failure(f"Lỗi khi cập nhật token sau {maxRetries} lần thử trong dòng: {originalLine[:30]}... | {e}")
                with fileLock:
                    with open(f"{outputFolder}/failed.txt", "a", encoding="utf-8") as f:
                        f.write(f"{rawLine}\n")

    return False

def main() -> None:
    try:
        startTime = time.time()
        misc = Miscellaneous()
        print(màu("""
                                                                                
  ▄▄▄▄▄▄▄                                 ▄   ▄▄▄▄                              
 █▀▀██▀▀▀▀                                ▀██████▀ █▄                           
    ██         ▄▄           ▄               ██     ██          ▄        ▄▄      
    ██   ▄███▄ ██ ▄█▀ ▄█▀█▄ ████▄ ▄██▀█     ██     ████▄ ▄▀▀█▄ ████▄ ▄████ ▄█▀█▄
    ██   ██ ██ ████   ██▄█▀ ██ ██ ▀███▄     ██     ██ ██ ▄█▀██ ██ ██ ██ ██ ██▄█▀
    ▀██▄▄▀███▀▄██ ▀█▄▄▀█▄▄▄▄██ ▀██▄▄██▀     ▀█████▄██ ██▄▀█▄██▄██ ▀█▄▀████▄▀█▄▄▄
                                                                        ██      
                                                                      ▀▀▀       

    Developed by Hoang Gia Kiet - Tool Reset Token cũ thành Token mới
    Facebook: https://web.facebook.com/quangthang.8507
    GitHub: https://github.com/giakietdev/discordtokenchange
    Zalo: 0382073843
       
                                                                                                                                      
                                                                                                   
"""))
        with open("input/tokens.txt", 'r', encoding="utf-8") as f:
            rawLines = [line.strip() for line in f if line.strip()]

        if not rawLines:
            log.warning("Thêm token vào input/tokens.txt đi thằng ngu ơi")
            return
        parsedLines = []
        for line in rawLines:
            try:
                misc.parseTokenLine(line)
                parsedLines.append(line)
            except ValueError as e:
                log.warning(f"Bỏ qua dòng: {line[:30]}... | Vì: {e}")

        if not parsedLines:
            log.warning("Ko có token nào sống để change token :)))")
            return

        threadCount = config['threads']
        fileLock = threading.Lock()
        titleUpdater = misc.Title()
        titleUpdater.startTitleUpdates(startTime)

        with ThreadPoolExecutor(max_workers=threadCount) as executor:
            futuresMap = {
                executor.submit(BoMayLaHoangGiaKiet, line, misc, fileLock, titleUpdater, len(parsedLines)): line
                for line in parsedLines
            }

            for future in as_completed(futuresMap):
                line = futuresMap[future]
                try:
                    future.result()
                except Exception as e:
                    log.failure(f"Lỗi: {line[:30]}... | {e}")
        
        log.info("Change Full Token Successfully. Kiểm tra output và lên phím 36 hoặc bất kỳ phím nào để thoát")
        input("")
        try:
            outputPath = os.path.abspath(outputFolder)
            os.startfile(outputPath)
            log.info(f"Opened output folder: {outputPath}")
        except Exception as e:
            log.warning(f"Failed to open output folder: {e}")

        titleUpdater.stopTitleUpdates()

    except KeyboardInterrupt:
        log.info("Exit")
    except Exception as e:
        pass

if __name__ == "__main__":
    main()