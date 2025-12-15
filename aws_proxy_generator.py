# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import boto3
import time
import threading
import os
import webbrowser
import random
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import requests
import json

try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:   
    HAS_PIL = False

# ==================== HE THONG ACTIVE KEY ONLINE ====================
class OnlineKeyValidator:
    API_URL = "https://raw.githubusercontent.com/tranhoanganh2002/aws-proxy-keys/refs/heads/main/allowed_keys.json"
    CACHE_FILE = ". key_cache. dat"
    CACHE_TIMEOUT = 300
    
    def __init__(self):
        self.last_check = 0
        self.cached_keys = []
    
    @staticmethod
    def hash_key(access_key):
        return hashlib.sha256(access_key.encode()).hexdigest()
    
    def get_allowed_keys(self):
        current_time = time.time()
        if current_time - self. last_check < self.CACHE_TIMEOUT and self.cached_keys:
            return self.cached_keys
        try:
            response = requests.get(self.API_URL, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.cached_keys = data.get('allowed_keys', [])
                self.last_check = current_time
                self._save_cache()
                return self.cached_keys
            else:
                return self._load_cache()
        except:
            return self._load_cache()
    
    def _save_cache(self):
        try:
            data = json.dumps({'keys': self.cached_keys, 'time': self.last_check})
            encoded = base64.b64encode(data.encode()).decode()
            with open(self.CACHE_FILE, 'w', encoding='utf-8') as f:
                f.write(encoded)
        except:  
            pass
    
    def _load_cache(self):
        try:
            if os. path.exists(self.CACHE_FILE):
                with open(self.CACHE_FILE, 'r', encoding='utf-8') as f:
                    encoded = f.read()
                    data = json.loads(base64.b64decode(encoded).decode())
                    self.cached_keys = data.get('keys', [])
                    self. last_check = data.get('time', 0)
                    return self.cached_keys
        except:
            pass
        return []
    
    def is_valid(self, access_key):
        if not access_key or len(access_key) < 16:
            return False
        key_hash = self.hash_key(access_key)
        allowed_keys = self.get_allowed_keys()
        return key_hash in allowed_keys
    
    def check_aws_credentials(self, access_key, secret_key):
        try:
            sts = boto3.client('sts', aws_access_key_id=access_key, aws_secret_access_key=secret_key)
            sts.get_caller_identity()
            return True
        except:  
            return False

# ==================== QUAN LY SO LAN DOI IP ====================
class IPChangeCounter:
    COUNTER_FILE = ".ip_change_counter.json"
    
    def __init__(self):
        self.counters = self._load_counters()
    
    def _load_counters(self):
        try:
            if os. path.exists(self.COUNTER_FILE):
                with open(self.COUNTER_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except:
            pass
        return {}
    
    def _save_counters(self):
        try:
            with open(self.COUNTER_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.counters, f, indent=2)
        except: 
            pass
    
    def get_count(self, access_key):
        key_hash = hashlib.sha256(access_key.encode()).hexdigest()[:16]
        return self.counters.get(key_hash, 0)
    
    def increment(self, access_key, count=1):
        key_hash = hashlib.sha256(access_key.encode()).hexdigest()[:16]
        self.counters[key_hash] = self.counters.get(key_hash, 0) + count
        self._save_counters()
    
    def reset(self, access_key):
        key_hash = hashlib.sha256(access_key.encode()).hexdigest()[:16]
        self.counters[key_hash] = 0
        self._save_counters()

# ==================== DONG BO LEN GITHUB ====================
class UsageReporter:
    GITHUB_TOKEN = "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"
    GITHUB_USERNAME = "tranhoanganh2002"
    REPO_NAME = "aws-proxy-keys"
    STATS_FILE = "ip_usage_stats.json"
    
    @staticmethod
    def report_ip_change(access_key, count):
        try:
            key_hash = hashlib.sha256(access_key.encode()).hexdigest()[:16]
            
            url = f"https://api.github.com/repos/{UsageReporter.GITHUB_USERNAME}/{UsageReporter.REPO_NAME}/contents/{UsageReporter.STATS_FILE}"
            headers = {
                'Authorization': f'token {UsageReporter.GITHUB_TOKEN}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                sha = response.json().get('sha', '')
                content = base64.b64decode(response. json()['content']).decode()
                stats = json.loads(content)
            else:
                sha = ''
                stats = {}
            
            stats[key_hash] = {
                'total_ip_changes': count,
                'last_update': time.strftime('%Y-%m-%d %H:%M:%S'),
                'key_prefix': access_key[:8] + '...'
            }
            
            data_upload = {
                'message': f'Update usage:  {count} IP changes',
                'content': base64.b64encode(json. dumps(stats, indent=2).encode()).decode(),
                'branch': 'main'
            }
            
            if sha:
                data_upload['sha'] = sha
            
            requests.put(url, headers=headers, json=data_upload, timeout=10)
            return True
        except:
            return False

# ==================== TOOL CHINH ====================
class AWSProxyGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("TrnHA - AWS Proxy Tool")
        self.root.geometry("750x850")
        self.root.resizable(False, False)
        self.root.configure(bg='#0d1117')
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#0d1117', borderwidth=0)
        style.configure('TNotebook.Tab', 
                       background='#161b22', 
                       foreground='#58a6ff', 
                       padding=[20, 10], 
                       font=('Segoe UI', 10, 'bold'))
        style.map('TNotebook.Tab', 
                 background=[('selected', '#1f6feb')], 
                 foreground=[('selected', '#ffffff')])
        
        self. ami_cache = {}
        self.proxy_tag = "AnhEmToolProxy"
        self.instance_checkboxes = {}
        self.show_all_vps = tk.BooleanVar(value=True)
        self.proxy_results = []
        self.access_key_validated = False
        self.key_validator = OnlineKeyValidator()
        self.ip_counter = IPChangeCounter()
        
        self.create_widgets()
    
    def validate_access_key(self, access_key, secret_key):
        if self.access_key_validated:
            return True
        
        if not self.key_validator.is_valid(access_key):
            messagebox.showerror("ACCESS KEY CHUA KICH HOAT", 
                "Access Key nay chua duoc kich hoat!\n\n" +
                "Vui long lien he admin de active:\n\n" +
                "ADMIN:  Tran Hoang Anh\n" +
                "Zalo: 0984790581\n\n" +
                "Gui Access Key cua ban de duoc active!")
            return False
        
        if not self.key_validator.check_aws_credentials(access_key, secret_key):
            messagebox.showerror("SAI THONG TIN AWS", 
                "Access Key hoac Secret Key khong dung!\n\n" +
                "Vui long kiem tra lai thong tin.")
            return False
        
        self.access_key_validated = True
        messagebox.showinfo("XAC THUC THANH CONG", 
            "Access Key da duoc kich hoat!\n\n" +
            "Ban co the su dung tool.")
        return True
    
    def create_widgets(self):
        main = tk.Frame(self.root, bg='#0d1117', padx=15, pady=15)
        main.pack(fill=tk.BOTH, expand=True)
        
        hdr = tk.Frame(main, bg='#161b22', bd=2, relief='solid')
        hdr.pack(fill=tk.X, pady=(0, 10))
        
        hdr_content = tk.Frame(hdr, bg='#161b22', padx=15, pady=12)
        hdr_content. pack(fill=tk.X)
        
        left_frame = tk.Frame(hdr_content, bg='#161b22')
        left_frame.pack(side=tk.LEFT, fill=tk. BOTH, expand=True)
        
        tk.Label(left_frame, 
                text="AWS PROXY CHAT", 
                bg='#161b22', 
                fg='#58a6ff', 
                font=('Segoe UI', 20, 'bold')).pack(anchor='w')
        
        info_frame = tk.Frame(left_frame, bg='#161b22')
        info_frame. pack(anchor='w', pady=(8, 0))
        
        tk.Label(info_frame, 
                text="ADMIN: T. H.A", 
                bg='#161b22', 
                fg='#f0883e', 
                font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT, padx=(0, 20))
        
        tk.Label(info_frame, 
                text="Vui long xoa 1 VPS san trong ACC, dung 'Tai DS' de xoa", 
                bg='#161b22', 
                fg='#f85149', 
                font=('Segoe UI', 9)).pack(side=tk.LEFT)
        
        right_frame = tk.Frame(hdr_content, bg='#161b22')
        right_frame.pack(side=tk.RIGHT, padx=(10, 0))
        
        zalo_btn = tk.Button(right_frame, 
                            text="NHOM MUA ACC", 
                            bg='#1f6feb', 
                            fg='white', 
                            font=('Segoe UI', 11, 'bold'), 
                            command=lambda:  webbrowser.open('https://zalo.me/g/ikicdv949'),
                            bd=0, 
                            cursor='hand2', 
                            padx=20, 
                            pady=10,
                            relief='raised')
        zalo_btn.pack()
        
        def on_enter(e):
            zalo_btn.config(bg='#1158c7')
        def on_leave(e):
            zalo_btn.config(bg='#1f6feb')
        zalo_btn.bind("<Enter>", on_enter)
        zalo_btn.bind("<Leave>", on_leave)
        
        tk.Frame(main, height=2, bg='#30363d').pack(fill=tk.X, pady=10)
        
        tabs = ttk.Notebook(main)
        t1 = tk.Frame(tabs, bg='#0d1117')
        t2 = tk.Frame(tabs, bg='#0d1117')
        t3 = tk.Frame(tabs, bg='#0d1117')
        tabs.add(t1, text='TAO PROXY')
        tabs.add(t2, text='QUAN LY IP')
        tabs.add(t3, text='CHECK LIVE')
        tabs.pack(expand=1, fill='both')
        
        self.create_tab_create(t1)
        self.create_tab_manage(t2)
        self.create_tab_check(t3)
        
        status_frame = tk.Frame(self.root, bg='#161b22', bd=1, relief='solid')
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status = tk.Label(status_frame, 
                              text="San sang", 
                              bg='#161b22', 
                              fg='#58a6ff', 
                              anchor='w', 
                              font=('Segoe UI', 10, 'bold'),
                              padx=10,
                              pady=8)
        self.status.pack(fill=tk.X)
    
    def create_tab_create(self, p):
        cf = tk.LabelFrame(p, 
                          text="AWS CREDENTIALS", 
                          bg='#0d1117', 
                          fg='#58a6ff', 
                          font=('Segoe UI', 11, 'bold'), 
                          bd=2, 
                          relief='solid')
        cf.pack(fill=tk.X, padx=10, pady=10)
        
        r1 = tk.Frame(cf, bg='#0d1117')
        r1.pack(fill=tk.X, padx=12, pady=8)
        tk.Label(r1, 
                text="Access Key:", 
                bg='#0d1117', 
                fg='#8b949e', 
                font=('Segoe UI', 10), 
                width=12, 
                anchor='w').pack(side=tk.LEFT)
        self.ak = tk.Entry(r1, 
                          bg='#161b22', 
                          fg='#c9d1d9', 
                          insertbackground='#58a6ff', 
                          font=('Consolas', 10), 
                          bd=1, 
                          relief='solid')
        self.ak.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        
        r2 = tk.Frame(cf, bg='#0d1117')
        r2.pack(fill=tk.X, padx=12, pady=8)
        tk.Label(r2, 
                text="Secret Key:", 
                bg='#0d1117', 
                fg='#8b949e', 
                font=('Segoe UI', 10), 
                width=12, 
                anchor='w').pack(side=tk.LEFT)
        self.sk = tk. Entry(r2, 
                          bg='#161b22', 
                          fg='#c9d1d9', 
                          insertbackground='#58a6ff', 
                          show='*', 
                          font=('Consolas', 10), 
                          bd=1, 
                          relief='solid')
        self.sk.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        
        r3 = tk.Frame(cf, bg='#0d1117')
        r3.pack(fill=tk.X, padx=12, pady=8)
        tk.Label(r3, 
                text="Region:", 
                bg='#0d1117', 
                fg='#8b949e', 
                font=('Segoe UI', 10), 
                width=12, 
                anchor='w').pack(side=tk.LEFT)
        self.reg = ttk.Combobox(r3, 
                               values=['ap-northeast-1 (Tokyo)', 
                                      'ap-southeast-1 (Singapore)', 
                                      'us-east-1 (Virginia)', 
                                      'us-west-2 (Oregon)', 
                                      'eu-west-1 (Ireland)'], 
                               font=('Segoe UI', 9), 
                               width=22)
        self.reg.current(0)
        self.reg.pack(side=tk.LEFT, padx=(0, 8))
        
        self.chk_btn = tk.Button(r3, 
                                text="CHECK", 
                                bg='#238636', 
                                fg='white', 
                                font=('Segoe UI', 9, 'bold'), 
                                command=self.check_limit, 
                                bd=0, 
                                cursor='hand2', 
                                padx=15, 
                                pady=6)
        self.chk_btn.pack(side=tk.LEFT)
        
        self.lim_lbl = tk.Label(cf, 
                               text="", 
                               bg='#0d1117', 
                               fg='#f0883e', 
                               font=('Segoe UI', 10, 'bold'))
        self.lim_lbl.pack(pady=8)
        
        pf = tk.LabelFrame(p, 
                          text="CAU HINH", 
                          bg='#0d1117', 
                          fg='#58a6ff', 
                          font=('Segoe UI', 11, 'bold'), 
                          bd=2, 
                          relief='solid')
        pf.pack(fill=tk.X, padx=10, pady=10)
        
        r4 = tk.Frame(pf, bg='#0d1117')
        r4.pack(fill=tk.X, padx=12, pady=10)
        
        tk.Label(r4, 
                text="So luong:", 
                bg='#0d1117', 
                fg='#8b949e', 
                font=('Segoe UI', 10)).pack(side=tk.LEFT)
        self.qty = tk.Entry(r4, 
                           width=8, 
                           bg='#161b22', 
                           fg='#c9d1d9', 
                           insertbackground='#58a6ff', 
                           font=('Segoe UI', 11), 
                           bd=1, 
                           relief='solid', 
                           justify='center')
        self.qty.insert(0, "1")
        self.qty.pack(side=tk.LEFT, padx=8)
        
        tk.Label(r4, 
                text="Format:", 
                bg='#0d1117', 
                fg='#8b949e', 
                font=('Segoe UI', 10)).pack(side=tk.LEFT, padx=(20, 8))
        self.fmt = ttk.Combobox(r4, 
                               width=22, 
                               values=['IP: PORT: USER: PASS', 
                                      'USER:PASS@IP:PORT', 
                                      'http://USER:PASS@IP:PORT'], 
                               font=('Segoe UI', 9), 
                               state='readonly')
        self.fmt.current(0)
        self.fmt.pack(side=tk.LEFT)
        
        self.cr_btn = tk.Button(p, 
                               text="TAO PROXY NGAY", 
                               bg='#1f6feb', 
                               fg='white', 
                               font=('Segoe UI', 13, 'bold'), 
                               command=lambda: threading.Thread(target=self.create_proxy, daemon=True).start(), 
                               bd=0, 
                               cursor='hand2', 
                               pady=12)
        self.cr_btn.pack(fill=tk.X, padx=10, pady=10)
        
        of = tk.LabelFrame(p, 
                          text="KET QUA", 
                          bg='#0d1117', 
                          fg='#58a6ff', 
                          font=('Segoe UI', 11, 'bold'), 
                          bd=2, 
                          relief='solid')
        of.pack(fill=tk. BOTH, expand=True, padx=10, pady=10)
        
        self.out = scrolledtext.ScrolledText(of, 
                                            height=8, 
                                            bg='#161b22', 
                                            fg='#58a6ff', 
                                            insertbackground='#58a6ff', 
                                            wrap=tk.WORD, 
                                            font=('Consolas', 10), 
                                            bd=0)
        self.out.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        
        tk.Button(of, 
                 text="COPY TAT CA", 
                 bg='#238636', 
                 fg='white', 
                 command=self.copy_out, 
                 font=('Segoe UI', 10, 'bold'), 
                 bd=0, 
                 cursor='hand2', 
                 pady=8).pack(fill=tk.X, padx=8, pady=8)
    
    def create_tab_manage(self, p):
        cf = tk.Frame(p, bg='#0d1117')
        cf.pack(fill=tk.X, padx=10, pady=10)
        
        self. ld_btn = tk.Button(cf, 
                               text="TAI DANH SACH", 
                               bg='#1f6feb', 
                               fg='white', 
                               font=('Segoe UI', 9, 'bold'), 
                               command=lambda: threading.Thread(target=self.load_vps, daemon=True).start(), 
                               bd=0, 
                               cursor='hand2', 
                               padx=15, 
                               pady=8)
        self.ld_btn.pack(side=tk. LEFT, padx=3)
        
        tk.Button(cf, 
                 text="CHON TAT CA", 
                 bg='#30363d', 
                 fg='white', 
                 font=('Segoe UI', 9, 'bold'), 
                 command=self.sel_all, 
                 bd=0, 
                 cursor='hand2', 
                 padx=12, 
                 pady=8).pack(side=tk.LEFT, padx=3)
        
        tk.Button(cf, 
                 text="BO CHON", 
                 bg='#30363d', 
                 fg='white', 
                 font=('Segoe UI', 9, 'bold'), 
                 command=self.desel_all, 
                 bd=0, 
                 cursor='hand2', 
                 padx=12, 
                 pady=8).pack(side=tk.LEFT, padx=3)
        
        self.cnt_lbl = tk.Label(cf, 
                               text="", 
                               bg='#0d1117', 
                               fg='#f0883e', 
                               font=('Segoe UI', 10, 'bold'))
        self.cnt_lbl.pack(side=tk.RIGHT)
        
        tk. Checkbutton(cf, 
                      text="Hien tat ca", 
                      variable=self.show_all_vps, 
                      bg='#0d1117', 
                      fg='#8b949e', 
                      selectcolor='#1f6feb', 
                      font=('Segoe UI', 9), 
                      bd=0).pack(side=tk.RIGHT, padx=10)
        
        lf = tk.LabelFrame(p, 
                          text="DANH SACH VPS", 
                          bg='#0d1117', 
                          fg='#58a6ff', 
                          font=('Segoe UI', 11, 'bold'), 
                          bd=2, 
                          relief='solid')
        lf.pack(fill=tk. X, padx=10, pady=10)
        
        can = tk.Canvas(lf, bg='#0d1117', highlightthickness=0, bd=0, height=280)
        scr = tk.Scrollbar(lf, orient="vertical", command=can.yview)
        self.vps_frm = tk.Frame(can, bg='#0d1117')
        self.vps_frm.bind("<Configure>", lambda e: can. configure(scrollregion=can. bbox("all")))
        can.create_window((0, 0), window=self.vps_frm, anchor="nw")
        can.configure(yscrollcommand=scr.set)
        can.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        scr.pack(side="right", fill="y")
        
        af = tk.Frame(p, bg='#0d1117')
        af.pack(fill=tk.X, padx=10, pady=10)
        
        buttons = [
            ("GAN TAG", '#9a6700', self.tag_vps),
            ("DOI IP", '#bc4c00', self.renew_ips),
            ("HIEN PROXY", '#1f6feb', self.show_prox),
            ("XOA VPS", '#da3633', self.delete_vps)
        ]
        
        for text, color, cmd in buttons: 
            tk.Button(af, 
                     text=text, 
                     bg=color, 
                     fg='white', 
                     font=('Segoe UI', 10, 'bold'), 
                     command=lambda c=cmd: threading.Thread(target=c, daemon=True).start(), 
                     bd=0, 
                     cursor='hand2', 
                     pady=10).pack(fill=tk.X, pady=2)
        
        of = tk.LabelFrame(p, 
                          text="KET QUA", 
                          bg='#0d1117', 
                          fg='#58a6ff', 
                          font=('Segoe UI', 11, 'bold'), 
                          bd=2, 
                          relief='solid')
        of.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.out_m = scrolledtext.ScrolledText(of, 
                                              height=10, 
                                              bg='#161b22', 
                                              fg='#58a6ff', 
                                              insertbackground='#58a6ff', 
                                              wrap=tk.WORD, 
                                              font=('Consolas', 9), 
                                              bd=0)
        self.out_m.pack(fill=tk. BOTH, expand=True, padx=8, pady=8)
        
        tk.Button(of, 
                 text="COPY", 
                 bg='#238636', 
                 fg='white', 
                 command=self.copy_m, 
                 font=('Segoe UI', 10, 'bold'), 
                 bd=0, 
                 cursor='hand2', 
                 pady=8).pack(fill=tk.X, padx=8, pady=8)
    
    def create_tab_check(self, p):
        inf = tk.LabelFrame(p, 
                           text="NHAP PROXY", 
                           bg='#0d1117', 
                           fg='#58a6ff', 
                           font=('Segoe UI', 11, 'bold'), 
                           bd=2, 
                           relief='solid')
        inf.pack(fill=tk. BOTH, expand=True, padx=10, pady=10)
        
        self.chk_in = scrolledtext.ScrolledText(inf, 
                                               height=10, 
                                               bg='#161b22', 
                                               fg='#c9d1d9', 
                                               insertbackground='#58a6ff', 
                                               wrap=tk.WORD, 
                                               font=('Consolas', 10), 
                                               bd=0)
        self.chk_in.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.chk_in.insert(tk.END, "# IP:PORT:USER:PASS\n")
        
        bf = tk.Frame(p, bg='#0d1117')
        bf.pack(pady=10)
        
        self.chk2_btn = tk.Button(bf, 
                                 text="CHECK NGAY", 
                                 bg='#1f6feb', 
                                 fg='white', 
                                 font=('Segoe UI', 12, 'bold'), 
                                 command=lambda: threading. Thread(target=self.check_prox, daemon=True).start(), 
                                 bd=0, 
                                 cursor='hand2', 
                                 width=15, 
                                 pady=10)
        self.chk2_btn.pack(side=tk.LEFT, padx=5)
        
        tk.Button(bf, 
                 text="XOA", 
                 bg='#da3633', 
                 fg='white', 
                 font=('Segoe UI', 12, 'bold'), 
                 command=lambda: self.chk_in.delete(1.0, tk.END), 
                 bd=0, 
                 cursor='hand2', 
                 width=10, 
                 pady=10).pack(side=tk.LEFT, padx=5)
        
        rf = tk.LabelFrame(p, 
                          text="KET QUA", 
                          bg='#0d1117', 
                          fg='#58a6ff', 
                          font=('Segoe UI', 11, 'bold'), 
                          bd=2, 
                          relief='solid')
        rf.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.chk_out = scrolledtext. ScrolledText(rf, 
                                                 height=10, 
                                                 bg='#161b22', 
                                                 fg='#c9d1d9', 
                                                 insertbackground='#58a6ff', 
                                                 wrap=tk.WORD, 
                                                 font=('Consolas', 9), 
                                                 bd=0)
        self.chk_out.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        
        tk.Button(rf, 
                 text="COPY LIVE", 
                 bg='#238636', 
                 fg='white', 
                 command=self.copy_chk, 
                 font=('Segoe UI', 10, 'bold'), 
                 bd=0, 
                 cursor='hand2', 
                 pady=8).pack(fill=tk.X, padx=8, pady=8)
    
    def create_proxy(self):
        try:
            ak, sk, reg = self.ak. get().strip(), self.sk.get().strip(), self.reg.get().split()[0]
            qty, fi = int(self.qty.get()), self.fmt.current()
            
            if not ak or not sk: 
                return messagebox.showerror("Loi", "Vui long nhap day du thong tin!")
            
            if not self.validate_access_key(ak, sk):
                return
            
            ec2 = boto3.client('ec2', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=reg)
            r = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'pending']}])
            cnt = sum(len(rv['Instances']) for rv in r['Reservations'])
            
            try:
                sq = boto3.client('service-quotas', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=reg)
                qr = sq.get_service_quota(ServiceCode='ec2', QuotaCode='L-1216C47A')
                lim = int(qr['Quota']['Value'])
            except:
                lim = 20
            
            avail = lim - cnt
            
            if avail < qty:
                return messagebox.showerror("Het Limit", 
                    f"Khong du limit!\n\n" +
                    f"Dang chay:  {cnt}\n" +
                    f"Limit: {lim}\n" +
                    f"Con lai: {avail}\n" +
                    f"Can tao: {qty}\n\n" +
                    f"Vui long xoa VPS cu hoac giam so luong!")
            
            self.out.delete(1.0, tk.END)
            self.out.insert(tk.END, f"Bat dau tao {qty} proxy.. .\n\n")
            self.cr_btn.config(state='disabled', text="DANG TAO...")
            self.upd(f"Tao {qty} proxy...")
            self.proxy_results = []
            
            if reg not in self.ami_cache:
                imgs = ec2.describe_images(
                    Filters=[
                        {'Name': 'name', 'Values': ['al2023-ami-*-x86_64']},
                        {'Name': 'state', 'Values': ['available']}
                    ],
                    Owners=['amazon']
                )
                if not imgs['Images']:
                    raise Exception("Khong tim thay AMI")
                ami = sorted(imgs['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]
                self.ami_cache[reg] = ami['ImageId']
            
            amid = self.ami_cache[reg]
            
            with ThreadPoolExecutor(max_workers=min(qty, 10)) as ex:
                fs = [ex.submit(self. create_single_with_retry, i, ak, sk, reg, fi, amid) for i in range(qty)]
                done = 0
                for f in as_completed(fs):
                    r = f.result()
                    done += 1
                    self. upd(f"Hoan thanh {done}/{qty}...")
                    
                    if r['ok']:
                        self.proxy_results.append(r['px'])
                        self.out. insert(tk.END, f"[{done}] OK:  {r['px']}\n")
                    else:
                        self.out.insert(tk. END, f"[{done}] FAIL: {r. get('err', 'Loi')}\n")
                    
                    self.out.see(tk.END)
                    self.root.update()
            
            self.out.insert(tk.END, f"\n{'='*50}\n")
            
            if self.proxy_results:
                self.out.insert(tk.END, f"THANH CONG:  {len(self.proxy_results)}/{qty} proxy\n")
                self. upd("Tao proxy hoan tat!")
                messagebox.showinfo("Thanh Cong", f"Da tao {len(self.proxy_results)} proxy!")
            else:
                self. out.insert(tk.END, f"THAT BAI: Khong tao duoc proxy nao!\n")
                self. out.insert(tk.END, f"\nKiem tra:\n")
                self.out. insert(tk.END, f"- Limit AWS\n")
                self.out. insert(tk.END, f"- Region co ho tro t2. micro\n")
                self.out.insert(tk.END, f"- Thu region khac")
                messagebox.showerror("Loi", "Khong tao duoc proxy!")
                
        except Exception as e: 
            self.out.delete(1.0, tk.END)
            self.out.insert(tk.END, f"LOI: {e}")
            messagebox.showerror("Loi", str(e))
        finally:
            self.cr_btn.config(state='normal', text="TAO PROXY NGAY")
    
    def create_single_with_retry(self, idx, ak, sk, reg, fi, amid):
        for attempt in range(3):
            result = self.create_single(idx, ak, sk, reg, fi, amid, attempt)
            if result['ok']:
                return result
            time.sleep(random.uniform(2, 5))
        return {'ok': False, 'err':  'Het 3 lan thu'}
    
    def create_single(self, idx, ak, sk, reg, fi, amid, attempt=0):
        ec2 = None
        sgid = None
        kn = None
        
        try: 
            ec2 = boto3.client('ec2', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=reg)
            ts = int(time.time() * 1000) + idx + (attempt * 1000)
            sgn, kn = f'proxy-sg-{ts}', f'proxy-key-{ts}'
            
            sg = ec2.create_security_group(GroupName=sgn, Description='Proxy SG')
            sgid = sg['GroupId']
            
            ec2.authorize_security_group_ingress(
                GroupId=sgid,
                IpPermissions=[
                    {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges':  [{'CidrIp':  '0.0.0.0/0'}]},
                    {'IpProtocol': 'tcp', 'FromPort': 3128, 'ToPort': 3128, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
                ]
            )
            
            ec2.create_key_pair(KeyName=kn)
            
            ud = """#!/bin/bash
sudo dnf install -y squid httpd-tools
sudo htpasswd -bc /etc/squid/passwd a 1
sudo bash -c 'cat > /etc/squid/squid.conf <<EOF
http_port 3128
auth_param basic program /usr/lib64/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic realm proxy
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
EOF'
sudo systemctl enable --now squid
"""
            
            insts = ec2.run_instances(
                ImageId=amid,
                InstanceType='t2.micro',
                MinCount=1,
                MaxCount=1,
                KeyName=kn,
                SecurityGroupIds=[sgid],
                UserData=ud,
                TagSpecifications=[{
                    'ResourceType': 'instance',
                    'Tags': [
                        {'Key': 'ProxyTool', 'Value': 'AnhEmToolProxy'},
                        {'Key': 'Name', 'Value': f'Proxy-{ts}'}
                    ]
                }]
            )
            
            iid = insts['Instances'][0]['InstanceId']
            
            for _ in range(40):
                inf = ec2.describe_instances(InstanceIds=[iid])
                if inf['Reservations'][0]['Instances'][0]['State']['Name'] == 'running': 
                    break
                time. sleep(2)
            
            inf = ec2.describe_instances(InstanceIds=[iid])
            ip = inf['Reservations'][0]['Instances'][0]. get('PublicIpAddress')
            
            if not ip:
                raise Exception("Khong lay duoc IP")
            
            time.sleep(60)
            
            return {'ok': True, 'px':  self.fmt_px(ip, fi)}
            
        except Exception as e:
            if ec2:
                try:
                    if sgid:
                        ec2.delete_security_group(GroupId=sgid)
                except:
                    pass
                try:
                    if kn:
                        ec2.delete_key_pair(KeyName=kn)
                except:
                    pass
            
            err_msg = str(e)
            if 'InstanceLimitExceeded' in err_msg:
                return {'ok':  False, 'err': 'Het limit'}
            elif 'Duplicate' in err_msg:
                return {'ok': False, 'err': 'Trung ten'}
            else:
                return {'ok': False, 'err': err_msg[: 30]}
    
    def fmt_px(self, ip, fi):
        port, user, password = "3128", "a", "1"
        if fi == 0:
            return f"{ip}:{port}:{user}:{password}"
        elif fi == 1:
            return f"{user}:{password}@{ip}:{port}"
        else:
            return f"http://{user}:{password}@{ip}:{port}"
    
    def copy_out(self):
        if self.proxy_results:
            self.root.clipboard_clear()
            self.root.clipboard_append('\n'.join(self.proxy_results))
            messagebox.showinfo("Thanh Cong", f"Da copy {len(self.proxy_results)} proxy!")
        else:
            messagebox.showwarning("Canh Bao", "Khong co proxy de copy!")
    
    def upd(self, txt):
        self.status. config(text=txt)
        self.root.update()
    
    def load_vps(self):
        try:
            ak, sk, reg = self.ak.get().strip(), self.sk.get().strip(), self.reg.get().split()[0]
            if not ak or not sk:
                return messagebox.showerror("Loi", "Nhap day du thong tin!")
            
            if not self.validate_access_key(ak, sk):
                return
            
            self. ld_btn.config(state='disabled', text="DANG TAI...")
            self.upd("Dang tai danh sach...")
            
            insts = self.get_vps(ak, sk, reg, self.show_all_vps. get())
            
            for w in self.vps_frm.winfo_children():
                w.destroy()
            self.instance_checkboxes. clear()
            
            if not insts: 
                tk.Label(self.vps_frm,
                        text="Khong co VPS! ",
                        bg='#0d1117',
                        fg='#f85149',
                        font=('Segoe UI', 12, 'bold')).pack(pady=20)
                self.cnt_lbl.config(text="0 VPS")
            else:
                for ins in insts:
                    iid = ins['instance_id']
                    ip = ins['public_ip'] if ins['public_ip'] else "Stopped"
                    st = ins['state']
                    tag = ins. get('has_proxy_tag', False)
                    
                    fr = tk.Frame(self.vps_frm, bg='#161b22', bd=1, relief='solid')
                    fr.pack(fill=tk.X, padx=5, pady=3)
                    
                    var = tk.BooleanVar(value=True)
                    self.instance_checkboxes[iid] = {
                        'var': var,
                        'instance':  ins,
                        'access_key': ak,
                        'secret_key': sk,
                        'region': reg
                    }
                    
                    tk.Checkbutton(fr,
                                  variable=var,
                                  bg='#161b22',
                                  selectcolor='#1f6feb',
                                  bd=0).pack(side=tk.LEFT, padx=5)
                    
                    tk.Label(fr,
                            text='TAG' if tag else 'NO',
                            bg='#161b22',
                            font=('Segoe UI', 10)).pack(side=tk.LEFT, padx=3)
                    
                    status_text = 'RUN' if st == 'running' else 'STOP'
                    status_color = '#3fb950' if st == 'running' else '#f85149'
                    tk.Label(fr,
                            text=status_text,
                            bg='#161b22',
                            fg=status_color,
                            font=('Segoe UI', 9, 'bold')).pack(side=tk.LEFT, padx=5)
                    
                    tk.Label(fr,
                            text=f"{ip}",
                            bg='#161b22',
                            fg='#58a6ff',
                            font=('Consolas', 10, 'bold'),
                            width=18).pack(side=tk.LEFT, padx=5)
                    
                    tk.Label(fr,
                            text=f"{iid[: 10]}...",
                            bg='#161b22',
                            fg='#8b949e',
                            font=('Consolas', 8)).pack(side=tk.LEFT, padx=3)
                
                self.cnt_lbl.config(text=f"{len(insts)} VPS")
            
            self.upd("Tai danh sach hoan tat!")
        except Exception as e:
            messagebox.showerror("Loi", str(e))
        finally:
            self.ld_btn.config(state='normal', text="TAI DANH SACH")
    
    def get_vps(self, ak, sk, reg, all=False):
        try:
            ec2 = boto3.client('ec2', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=reg)
            
            if all:
                filters = [{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}]
            else: 
                filters = [
                    {'Name': 'tag:ProxyTool', 'Values': [self.proxy_tag]},
                    {'Name':  'instance-state-name', 'Values': ['running', 'stopped']}
                ]
            
            r = ec2.describe_instances(Filters=filters)
            res = []
            
            for rv in r['Reservations']: 
                for i in rv['Instances']:
                    has_tag = False
                    if 'Tags' in i: 
                        for t in i['Tags']:
                            if t['Key'] == 'ProxyTool' and t['Value'] == self. proxy_tag:
                                has_tag = True
                                break
                    
                    res.append({
                        'instance_id': i['InstanceId'],
                        'state': i['State']['Name'],
                        'public_ip': i.get('PublicIpAddress'),
                        'has_proxy_tag': has_tag
                    })
            
            return res
        except: 
            return []
    
    def tag_vps(self):
        try:
            sel = [{'id': iid, 'ak': d['access_key'], 'sk': d['secret_key'], 'reg': d['region']}
                   for iid, d in self.instance_checkboxes.items() if d['var'].get()]
            
            if not sel: 
                return messagebox.showwarning("Canh Bao", "Vui long chon VPS!")
            
            if not messagebox.askyesno("Xac Nhan", f"Gan tag cho {len(sel)} VPS?"):
                return
            
            self.out_m.delete(1.0, tk.END)
            self.out_m.insert(tk.END, "Dang gan tag.. .\n\n")
            self.upd("Dang gan tag...")
            ok = 0
            
            for i, s in enumerate(sel, 1):
                try:
                    ec2 = boto3.client('ec2',
                                      aws_access_key_id=s['ak'],
                                      aws_secret_access_key=s['sk'],
                                      region_name=s['reg'])
                    ec2.create_tags(
                        Resources=[s['id']],
                        Tags=[{'Key': 'ProxyTool', 'Value': self.proxy_tag}]
                    )
                    ok += 1
                    self.out_m.insert(tk.END, f"[{i}] {s['id'][: 10]}...  OK\n")
                except: 
                    self.out_m.insert(tk.END, f"[{i}] {s['id'][:10]}...  FAIL\n")
                self.out_m.see(tk.END)
                self.root.update()
            
            self.out_m. insert(tk.END, f"\n{'='*50}\n")
            self.out_m.insert(tk.END, f"Thanh cong: {ok}/{len(sel)} VPS")
            
            self.upd("Gan tag hoan tat!")
            messagebox.showinfo("Thanh Cong", f"Da gan tag {ok}/{len(sel)} VPS!")
        except Exception as e:
            messagebox.showerror("Loi", str(e))
    
    def sel_all(self):
        for d in self.instance_checkboxes.values():
            d['var'].set(True)
    
    def desel_all(self):
        for d in self.instance_checkboxes.values():
            d['var'].set(False)
    
    def show_prox(self):
        try:
            fi = self.fmt. current()
            
            sel = []
            for iid, d in self.instance_checkboxes. items():
                if d['var'].get():
                    ip = d['instance'].get('public_ip')
                    state = d['instance'].get('state')
                    
                    if ip and ip != "Stopped" and state == 'running': 
                        proxy = self.fmt_px(ip, fi)
                        sel.append(proxy)
            
            self.out_m.delete(1.0, tk.END)
            
            if sel:
                self. out_m.insert(tk. END, f"CO {len(sel)} PROXY:\n\n")
                for px in sel:
                    self. out_m.insert(tk. END, f"{px}\n")
                self. out_m.insert(tk.END, f"\n{'='*50}\n")
                self.out_m.insert(tk.END, f"TONG:  {len(sel)} proxy")
                messagebox.showinfo("Thanh Cong", f"Co {len(sel)} proxy!")
            else:
                self.out_m.insert(tk.END, "KHONG CO VPS DANG CHAY!\n\n")
                self.out_m.insert(tk.END, "LY DO CO THE:\n")
                self.out_m. insert(tk.END, "1.  Chua chon VPS nao\n")
                self.out_m.insert(tk.END, "2. VPS dang STOP (chua RUN)\n")
                self. out_m.insert(tk. END, "3. VPS chua co IP public\n\n")
                self.out_m.insert(tk.END, "CACH SUA:\n")
                self.out_m.insert(tk.END, "- Chon VPS co trang thai 'RUN'\n")
                self. out_m.insert(tk. END, "- Hoac click 'DOI IP' de start VPS")
                messagebox.showwarning("Canh Bao", "Khong co VPS dang chay!")
        except Exception as e:
            self.out_m.delete(1.0, tk.END)
            self.out_m.insert(tk.END, f"LOI: {e}")
            messagebox.showerror("Loi", str(e))
    
    def renew_ips(self):
        try:
            ak = self.ak.get().strip()
            fi = self.fmt.current()
            sel = [{'id': iid, 'ak': d['access_key'], 'sk': d['secret_key'], 'reg': d['region']}
                   for iid, d in self.instance_checkboxes.items() if d['var'].get()]
            
            if not sel:
                return messagebox. showwarning("Canh Bao", "Vui long chon VPS!")
            
            if not messagebox.askyesno("Xac Nhan", f"Doi IP cho {len(sel)} VPS?"):
                return
            
            current_count = self.ip_counter.get_count(ak)
            
            self.out_m.delete(1.0, tk.END)
            self.out_m.insert(tk.END, f"SO LAN DOI IP: {current_count}\n")
            self.out_m.insert(tk.END, f"Dang doi {len(sel)} VPS.. .\n\n")
            self.upd("Dang doi IP...")
            
            new = []
            with ThreadPoolExecutor(max_workers=10) as ex:
                fs = [ex.submit(self.renew_single, s['id'], s['ak'], s['sk'], s['reg'], fi, i+1, len(sel)) for i, s in enumerate(sel)]
                for f in as_completed(fs):
                    r = f.result()
                    if r['ok']:
                        new.append(r['px'])
                    self.out_m.see(tk.END)
                    self.root.update()
            
            if new:
                self.ip_counter.increment(ak, len(new))
                new_count = self.ip_counter.get_count(ak)
                
                threading.Thread(
                    target=UsageReporter.report_ip_change,
                    args=(ak, new_count),
                    daemon=True
                ).start()
                
                self.out_m.insert(tk.END, f"\n{'='*50}\n")
                self.out_m.insert(tk.END, f"DANH SACH IP MOI:\n\n")
                for px in new:
                    self.out_m.insert(tk.END, f"{px}\n")
                self.out_m.insert(tk.END, f"\n{'='*50}\n")
                self.out_m.insert(tk.END, f"Thanh cong: {len(new)}/{len(sel)}\n")
                self.out_m.insert(tk.END, f"TONG SO LAN DOI IP: {new_count}")
                
                self.upd(f"Doi IP xong!  Tong:  {new_count}")
                messagebox. showinfo("Thanh Cong",
                                  f"Da doi {len(new)} IP!\n\n" +
                                  f"Tong so lan doi IP: {new_count}")
            else:
                self.out_m. insert(tk.END, "\nKhong doi duoc!")
                messagebox.showerror("Loi", "Khong doi duoc IP!")
        except Exception as e: 
            self.out_m. delete(1.0, tk. END)
            self.out_m.insert(tk.END, f"LOI: {e}")
            messagebox.showerror("Loi", str(e))
    
    def renew_single(self, iid, ak, sk, reg, fi, idx, total):
        try:
            self.upd(f"Doi IP {idx}/{total}...")
            
            ec2 = boto3.client('ec2', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=reg)
            
            ec2.stop_instances(InstanceIds=[iid])
            ec2.get_waiter('instance_stopped').wait(InstanceIds=[iid])
            
            ec2.start_instances(InstanceIds=[iid])
            ec2.get_waiter('instance_running').wait(InstanceIds=[iid])
            
            inf = ec2.describe_instances(InstanceIds=[iid])
            nip = inf['Reservations'][0]['Instances'][0]. get('PublicIpAddress')
            
            if not nip:
                raise Exception("Khong lay duoc IP")
            
            self.out_m.insert(tk.END, f"[{idx}] {iid[: 10]}... OK:  {nip}\n")
            return {'ok': True, 'px': self.fmt_px(nip, fi)}
        except:
            self.out_m.insert(tk.END, f"[{idx}] {iid[:10]}... FAIL\n")
            return {'ok': False}
    
    def delete_vps(self):
        try:
            sel = [{'id':  iid, 'ak': d['access_key'], 'sk': d['secret_key'], 'reg': d['region']}
                   for iid, d in self.instance_checkboxes.items() if d['var'].get()]
            
            if not sel:
                return messagebox. showwarning("Canh Bao", "Vui long chon VPS!")
            
            if not messagebox.askyesno("XAC NHAN XOA", f"XOA VINH VIEN {len(sel)} VPS?"):
                return
            
            if not messagebox.askyesno("LAN CUOI", "KHONG THE KHOI PHUC.  Tiep tuc? "):
                return
            
            self.cr_btn.config(state='disabled', text="DANG XOA VPS...")
            
            self.out_m.delete(1.0, tk.END)
            self.out_m.insert(tk.END, "Dang xoa.. .\n\n")
            self.upd("Dang xoa VPS...")
            
            ok = 0
            for i, s in enumerate(sel, 1):
                self.upd(f"Xoa {i}/{len(sel)}...")
                self.out_m.insert(tk.END, f"[{i}] {s['id'][: 10]}... ")
                self.out_m. see(tk.END)
                self.root.update()
                
                try:
                    ec2 = boto3.client('ec2',
                                      aws_access_key_id=s['ak'],
                                      aws_secret_access_key=s['sk'],
                                      region_name=s['reg'])
                    ec2.terminate_instances(InstanceIds=[s['id']])
                    ok += 1
                    self. out_m.insert(tk. END, "OK\n")
                except: 
                    self.out_m.insert(tk.END, "FAIL\n")
                self.out_m.see(tk.END)
                self.root.update()
            
            self.out_m.insert(tk.END, f"\n{'='*50}\n")
            self.out_m.insert(tk.END, f"Da xoa {ok}/{len(sel)} VPS\n")
            self.out_m.insert(tk.END, f"\nCho 20s truoc khi tao proxy moi.. .\n")
            self.out_m.see(tk.END)
            
            for countdown in range(20, 0, -1):
                self.upd(f"Doi {countdown}s...")
                self.cr_btn.config(text=f"CHO {countdown}S...")
                self.root.update()
                time.sleep(1)
            
            self.cr_btn.config(state='normal', text="TAO PROXY NGAY")
            self.upd("Xoa hoan tat!  Co the tao proxy.")
            
            messagebox.showinfo("Ket Qua",
                              f"Da xoa {ok}/{len(sel)} VPS\n\n" +
                              f"Co the tao proxy moi bay gio!")
        except Exception as e: 
            self.cr_btn.config(state='normal', text="TAO PROXY NGAY")
            messagebox.showerror("Loi", str(e))
    
    def check_prox(self):
        try:
            txt = self.chk_in.get(1.0, tk.END)
            pxs = [l.strip() for l in txt.split('\n') if l.strip() and not l.strip().startswith('#')]
            
            if not pxs: 
                return messagebox.showwarning("Canh Bao", "Vui long nhap proxy!")
            
            self.chk_out.delete(1.0, tk.END)
            self.chk_out.insert(tk.END, f"Dang check {len(pxs)} proxy...\n\n")
            self.chk2_btn.config(state='disabled', text="DANG CHECK...")
            self.upd(f
