import json
import requests
import sys
import os
import psycopg2
import threading
from collections import defaultdict
from datetime import date
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote, urlparse, parse_qs

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.inspector import analyze_request
from analyzer.request_types import ParsedRequest

traffic_cache = defaultdict(lambda: {'bytes_in': 0, 'bytes_out': 0, 'requests': 0})
cache_lock = threading.Lock()
last_flush_time = time.time()

def get_db_connection():
    return psycopg2.connect(
        dbname=os.environ.get('DB_NAME', 'waf_db'),
        user=os.environ.get('DB_USER', 'waf_user'),
        password=os.environ.get('DB_PASSWORD', 'secretpassword'),
        host=os.environ.get('DB_HOST', 'db'),
        port=os.environ.get('DB_PORT', '5432')
    )
    
def get_site_info_from_db(domain):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT target_ip, is_protected, traffic_limit_mb 
            FROM accounts_protectedsite 
            WHERE domain = %s
        """, (domain,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        if result:
            return result[0], result[1], result[2]
        return None, False, 0
    except Exception as e:
        print(f"Ошибка подключения к БД: {e}")
        return None, False, 0

def update_traffic_stats_db(domain, bytes_in, bytes_out):
    print(f"[TRAFFIC] Updating stats for {domain}: in={bytes_in}, out={bytes_out}")
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM accounts_protectedsite WHERE domain = %s", (domain,))
        site_row = cur.fetchone()
        if not site_row:
            print(f"[TRAFFIC] Site not found for domain: {domain}")
            return
        site_id = site_row[0]
        today = date.today()
        cur.execute("""
            INSERT INTO accounts_trafficstats (site_id, date, bytes_in, bytes_out)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (site_id, date) 
            DO UPDATE SET 
                bytes_in = accounts_trafficstats.bytes_in + EXCLUDED.bytes_in,
                bytes_out = accounts_trafficstats.bytes_out + EXCLUDED.bytes_out
        """, (site_id, today, bytes_in, bytes_out))
        conn.commit()
        print(f"[TRAFFIC] Successfully updated stats for {domain}")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Traffic stats error: {e}")

def check_traffic_limit(domain, limit_mb):
    if limit_mb <= 0:
        return True
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT COALESCE(SUM(t.bytes_in + t.bytes_out), 0) / (1024.0 * 1024) as used_mb
            FROM accounts_protectedsite s
            LEFT JOIN accounts_trafficstats t 
                ON t.site_id = s.id 
                AND t.date >= date_trunc('month', CURRENT_DATE)
            WHERE s.domain = %s
            GROUP BY s.id
        """, (domain,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        used_mb = result[0] if result else 0
        return used_mb < limit_mb
    except Exception as e:
        print(f"Check limit error: {e}")
        return True
        
def log_request(ip_address, method, path, status_code, was_blocked, user_agent, domain=None, rule_name=None):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        site_id = None
        if domain:
            cur.execute("SELECT id FROM accounts_protectedsite WHERE domain = %s", (domain,))
            site_row = cur.fetchone()
            site_id = site_row[0] if site_row else None
        rule_id = None
        if rule_name:
            clean_rule_name = rule_name
            if rule_name.startswith('DB_RULE_'):
                clean_rule_name = rule_name[8:]
            cur.execute("SELECT id FROM accounts_wafrule WHERE name = %s", (clean_rule_name,))
            rule_row = cur.fetchone()
            rule_id = rule_row[0] if rule_row else None
        cur.execute("""
            INSERT INTO accounts_requestlog 
            (ip_address, method, path, status_code, was_blocked, user_agent, site_id, rule_triggered_id, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (ip_address, method, path, status_code, was_blocked, user_agent, site_id, rule_id))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Ошибка записи лога: {e}")

def flush_traffic_cache():
    global last_flush_time, traffic_cache
    while True:
        time.sleep(60)
        with cache_lock:
            for domain, stats in list(traffic_cache.items()):
                if stats['bytes_in'] > 0 or stats['bytes_out'] > 0:
                    update_traffic_stats_db(domain, stats['bytes_in'], stats['bytes_out'])
                    stats['bytes_in'] = 0
                    stats['bytes_out'] = 0
                    stats['requests'] = 0

flush_thread = threading.Thread(target=flush_traffic_cache, daemon=True)
flush_thread.start()

class WAFProxy(BaseHTTPRequestHandler):
    
    def do_GET(self):
        self._handle_any_request('GET')
    def do_POST(self):
        self._handle_any_request('POST')
    def do_PUT(self):
        self._handle_any_request('PUT')
    def do_DELETE(self):
        self._handle_any_request('DELETE')
    def do_PATCH(self):
        self._handle_any_request('PATCH')
    def do_OPTIONS(self):
        self._handle_any_request('OPTIONS')
    def do_HEAD(self):
        self._handle_any_request('HEAD')
        
    def _handle_any_request(self, method):
        host_header = self.headers.get('Host', '')
        domain = host_header.split(':')[0] 
        client_ip = self.client_address[0]
        user_agent = self.headers.get('User-Agent', '')
        
        if not domain:
            self.send_error(400, "Missing Host header")
            return
            
        target_ip, is_protected, traffic_limit_mb = get_site_info_from_db(domain)
        
        if not target_ip:
            self.send_error(404, f"Domain '{domain}' is not registered")
            return
            
        if not check_traffic_limit(domain, traffic_limit_mb):
            print(f"ЛИМИТ ПРЕВЫШЕН [{domain}]")
            self.send_response(429)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Traffic limit exceeded"}).encode())
            return
        
        # Читаем тело запроса
        content_length = int(self.headers.get('Content-Length', 0))
        raw_body = self.rfile.read(content_length) if content_length > 0 else None
        bytes_in = content_length
        
        # Проксируем запрос (получаем статус и тело ответа)
        status_code, response_content = self._proxy_to_backend(method, raw_body, f"http://{target_ip}")
        
        # Обновляем статистику трафика
        bytes_out = len(response_content) if response_content else 0
        with cache_lock:
            stats = traffic_cache[domain]
            stats['bytes_in'] += bytes_in
            stats['bytes_out'] += bytes_out
            stats['requests'] += 1
        
        # Логируем запрос
        log_request(client_ip, method, self.path, status_code, False, user_agent, domain)
        
        print(f"[STATS] {domain}: +{bytes_in} in, +{bytes_out} out")

    def _proxy_to_backend(self, method, raw_body, target_url):
        if '/socket.io/' in self.path:
            self.send_response(200)
            self.end_headers()
            return 200, b''
        
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ['content-length']}
        try:
            response = requests.request(
                method=method,
                url=target_url + self.path,
                headers=headers,
                data=raw_body,
                timeout=10
            )
            self.send_response(response.status_code)
            excluded_headers = ['content-length', 'transfer-encoding', 'connection', 'date', 'server']
            for k, v in response.headers.items():
                if k.lower() not in excluded_headers:
                    self.send_header(k, v)
            self.send_header('Content-Length', str(len(response.content)))
            self.end_headers()
            self.wfile.write(response.content)
            return response.status_code, response.content
        except Exception as e:
            print(f"Proxy Error: {e}")
            self.send_error(502, f"Proxy error: {str(e)}")
            return 502, b''

if __name__ == '__main__':
    server = ThreadingHTTPServer(('0.0.0.0', 8080), WAFProxy)
    print("WAF с QoS запущен!")
    server.serve_forever()
