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
    try:
        conn = psycopg2.connect(
            dbname=os.environ.get('DB_NAME', 'waf_db'),
            user=os.environ.get('DB_USER', 'waf_user'),
            password=os.environ.get('DB_PASSWORD', 'secretpassword'),
            host=os.environ.get('DB_HOST', 'db'),
            port=os.environ.get('DB_PORT', '5432')
        )
        cur = conn.cursor()
        
        cur.execute("SELECT target_ip FROM accounts_protectedsite WHERE domain = %s AND is_protected = True", (domain,))
        result = cur.fetchone()
        
        cur.close()
        conn.close()
        
        if result:
            return result[0] 
        return None
    except Exception as e:
        print(f"Ошибка подключения к БД: {e}")
        return None


class WAFProxy(BaseHTTPRequestHandler):
    
    def do_GET(self):
        self._handle_any_request('GET')

    def do_POST(self):
        self._handle_any_request('POST')

    def _handle_any_request(self, method):
        host_header = self.headers.get('Host', '')
        domain = host_header.split(':')[0] 
        
        if not domain:
            self.send_error(400, "Missing Host header")
            return
            
        target_ip = get_target_ip_from_db(domain)
        
        if not target_ip:
            self.send_error(404, f"Domain '{domain}' is not registered in WAF or protection is disabled.")
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
            print(f"❌ БЛОКИРОВКА [{domain}]: {result.reason} ({result.details})")
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
    print("🛡️ WAF со сквозным анализом запущен!")
    server.serve_forever()