import json
import requests
import sys
import os
import psycopg2
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote, urlparse, parse_qs

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.inspector import analyze_request
from analyzer.request_types import ParsedRequest

#JUICE_SHOP = "http://juice-shop:3000"

def get_target_ip_from_db(domain):
    """Возвращает (target_ip, is_protected) для домена"""
    try:
        conn = psycopg2.connect(
            dbname=os.environ.get('DB_NAME', 'waf_db'),
            user=os.environ.get('DB_USER', 'waf_user'),
            password=os.environ.get('DB_PASSWORD', 'secretpassword'),
            host=os.environ.get('DB_HOST', 'db'),
            port=os.environ.get('DB_PORT', '5432')
        )
        cur = conn.cursor()
        
        cur.execute("SELECT target_ip, is_protected FROM accounts_protectedsite WHERE domain = %s", (domain,))
        result = cur.fetchone()
        
        cur.close()
        conn.close()
        
        if result:
            return result[0], result[1]  # target_ip, is_protected
        return None, False
    except Exception as e:
        print(f"Ошибка подключения к БД: {e}")
        return None, False

def log_request(ip_address, method, path, status_code, was_blocked, user_agent, domain=None, rule_name=None):
    """Запись лога в таблицу accounts_requestlog"""
    try:
        conn = psycopg2.connect(
            dbname=os.environ.get('DB_NAME', 'waf_db'),
            user=os.environ.get('DB_USER', 'waf_user'),
            password=os.environ.get('DB_PASSWORD', 'secretpassword'),
            host=os.environ.get('DB_HOST', 'db'),
            port=os.environ.get('DB_PORT', '5432')
        )
        cur = conn.cursor()
        
        # Получаем site_id по domain (если передан)
        site_id = None
        if domain:
            cur.execute("SELECT id FROM accounts_protectedsite WHERE domain = %s", (domain,))
            site_row = cur.fetchone()
            site_id = site_row[0] if site_row else None
        
        # Получаем rule_id по имени правила
        rule_id = None
        if rule_name:
            # Убираем префикс DB_RULE_ если он есть
            clean_rule_name = rule_name
            if rule_name.startswith('DB_RULE_'):
                clean_rule_name = rule_name[8:]  # Убираем "DB_RULE_"
            
            # Ищем правило по имени
            cur.execute("SELECT id FROM accounts_wafrule WHERE name = %s", (clean_rule_name,))
            rule_row = cur.fetchone()
            rule_id = rule_row[0] if rule_row else None
            
            # Если не нашли, возможно rule_name это ID?
            if not rule_id and rule_name.isdigit():
                cur.execute("SELECT id FROM accounts_wafrule WHERE id = %s", (rule_name,))
                rule_row = cur.fetchone()
                rule_id = rule_row[0] if rule_row else None
        
        # Вставляем лог
        cur.execute("""
            INSERT INTO accounts_requestlog 
            (ip_address, method, path, status_code, was_blocked, user_agent, site_id, rule_triggered_id, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (ip_address, method, path, status_code, was_blocked, user_agent, site_id, rule_id))
        
        conn.commit()
        cur.close()
        conn.close()
        print(f"[LOG] {ip_address} - {method} {path} - {status_code} (blocked={was_blocked}, rule_id={rule_id})")
    except Exception as e:
        print(f"Ошибка записи лога: {e}")

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
            
        target_ip, is_protected = get_target_ip_from_db(domain)
        
        if not target_ip:
            self.send_error(404, f"Domain '{domain}' is not registered in WAF or protection is disabled.")
            return
        if not is_protected:
        # Режим только логирования: пропускаем всё, но логируем
            
            parsed_url = urlparse(self.path)
            body = None
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                raw_body = self.rfile.read(content_length).decode('utf-8')
                try:
                    body = json.loads(raw_body)
                except:
                    body = raw_body    
    
            request_to_analyze = ParsedRequest(
                method=method,
                path=parsed_url.path,
                query_params={k: v[0] for k, v in parse_qs(parsed_url.query).items()},
                headers=dict(self.headers),
                body=body
            )

            result = analyze_request(request_to_analyze)
        
            if not result.is_safe:
                print(f"[MIRROR MODE] Domain '{domain}' has protection disabled, logging only")
                log_request(
                    ip_address=client_ip,
                    method=method,
                    path=self.path,
                    status_code=200,
                    was_blocked=False,
                    user_agent=user_agent,
                    domain=domain,
                    rule_name=result.reason  
                )
            return   
        target_url = f"http://{target_ip}"

        parsed_url = urlparse(self.path)
        body = None
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            raw_body = self.rfile.read(content_length).decode('utf-8')
            try:
                body = json.loads(raw_body)
            except:
                body = raw_body

        request_to_analyze = ParsedRequest(
            method=method,
            path=parsed_url.path,
            query_params={k: v[0] for k, v in parse_qs(parsed_url.query).items()},
            headers=dict(self.headers),
            body=body
        )

        result = analyze_request(request_to_analyze)
        
        if not result.is_safe:
            print(f"БЛОКИРОВКА [{domain}]: {result.reason} ({result.details})")
            log_request(
                ip_address=client_ip,
                method=method,
                path=self.path,
                status_code=403,
                was_blocked=True,
                user_agent=user_agent,
                domain=domain,
                rule_name=result.reason  # Сохраняем имя сработавшего правила
            )
            self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": "Security Block",
                "type": result.reason,
                "details": result.details
            }).encode())
            return

        self._proxy_to_backend(method, body if isinstance(body, str) else json.dumps(body) if body else None, target_url)

    def _proxy_to_backend(self, method, body_str, target_url):
        if '/socket.io/' in self.path:
            self.send_response(200)
            self.end_headers()
            return

        headers = {k: v for k, v in self.headers.items() if k.lower() not in ['content-length']}
        try:
            response = requests.request(
                method=method,
                url=target_url + self.path,
                headers=headers,
                data=body_str.encode('utf-8') if body_str else None,
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
            
        except BrokenPipeError:
            pass
        except ConnectionResetError:
            pass
        except Exception as e:
            print(f"Proxy Error for {target_url}: {e}")

if __name__ == '__main__':
    server = ThreadingHTTPServer(('0.0.0.0', 8080), WAFProxy)
    print("WAF со сквозным анализом запущен!")
    server.serve_forever()
