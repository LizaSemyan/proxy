import socket
import threading
from urllib.parse import urlparse, parse_qs
import ssl
import tempfile
import os
import subprocess
import sqlite3
import json
from datetime import datetime
import gzip
import zlib
import select
import errno

class HTTPProxy:
    def __init__(self, host='0.0.0.0', port=8080, db_path='/app/data/requests.db'):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.db_path = db_path
        self.certs_dir = 'certs'
        os.makedirs(self.certs_dir, exist_ok=True)
        if not os.path.exists(os.path.join(self.certs_dir, 'ca.key')) or not os.path.exists(os.path.join(self.certs_dir, 'ca.crt')):
            self.generate_ca()
        self.init_db()

    def generate_ca(self):
        key_path = os.path.join(self.certs_dir, 'ca.key')
        cert_path = os.path.join(self.certs_dir, 'ca.crt')

        subprocess.run([
            'openssl', 'genrsa', '-out', key_path, '4096'
        ], check=True)
        
        subprocess.run([
            'openssl', 'req', '-new', '-x509', '-days', '365',
            '-key', key_path, '-out', cert_path,
            '-subj', '/CN=MITM Proxy Root CA/O=MITM Proxy/OU=Security',
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
            '-addext', 'subjectKeyIdentifier=hash'
        ], check=True)

    def init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    method TEXT,
                    path TEXT,
                    get_params TEXT,
                    headers TEXT,
                    cookies TEXT,
                    body TEXT,
                    post_params TEXT,
                    timestamp DATETIME
                );
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS responses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id INTEGER,
                    status_code INTEGER,
                    message TEXT,
                    headers TEXT,
                    body TEXT,
                    timestamp DATETIME,
                    FOREIGN KEY(request_id) REFERENCES requests(id)
                );
            ''')

            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error initializing database: {e}")

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Proxy server running on {self.host}:{self.port}")

        while True:
            client_socket, addr = self.server_socket.accept()
            threading.Thread(
                target=self.handle_client,
                args=(client_socket,)
            ).start()

    def handle_client(self, client_socket):
        try:
            request = client_socket.recv(4096).decode()
            print(f"Received request:\n{request}")

            if not request:
                return

            first_line = request.split('\r\n')[0]

            if first_line.startswith('CONNECT'):
                self.handle_https(client_socket, request)
            else:
                self.handle_http(client_socket, request)

        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()

    def handle_https(self, client_socket, request):
        print("Handling HTTPS request")
        host_port = request.split('\r\n')[0].split()[1]
        host, port = host_port.split(':') if ':' in host_port else (host_port, '443')
        port = int(port)

        parsed_request = self.parse_request(request)
        request_id = self.save_request(
            parsed_request['method'], 
            parsed_request['path'], 
            parsed_request['get_params'],
            parsed_request['headers'],
            parsed_request['cookies'],
            parsed_request['body'],
            parsed_request['post_params']
        )

        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        key, cert = self.generate_cert(host)
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as cert_file, \
            tempfile.NamedTemporaryFile(mode='wb', delete=False) as key_file:
            
            cert_file.write(cert)
            key_file.write(key)
            cert_file.flush()
            key_file.flush()
            
            try:
                client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                client_context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
                client_context.verify_mode = ssl.CERT_NONE

                client_context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384')
                
                client_context.minimum_version = ssl.TLSVersion.TLSv1_2
                client_context.maximum_version = ssl.TLSVersion.TLSv1_3
                
                ssl_client = client_context.wrap_socket(
                    client_socket,
                    server_side=True,
                    do_handshake_on_connect=False
                )
                
                try:
                    ssl_client.do_handshake()
                except ssl.SSLWantReadError:
                    pass
                except Exception as e:
                    print(f"Handshake error: {e}")
                    return

                server_socket = socket.create_connection((host, port), timeout=10)
                server_context = ssl.create_default_context()
                ssl_server = server_context.wrap_socket(
                    server_socket,
                    server_hostname=host,
                    do_handshake_on_connect=True
                )
            
                print(f"Tunnel established {ssl_client.version()} -> {ssl_server.version()}")
                self.bidirectional_forward(ssl_client, ssl_server)

                self.save_response(
                    request_id=request_id,
                    status_code=200,
                    message="Connection Established",
                    headers={},
                    body=""
                )
                
            except Exception as e:
                print(f"HTTPS error: {repr(e)}")
            finally:
                os.unlink(cert_file.name)
                os.unlink(key_file.name)

    def handle_http(self, client_socket, request):
        first_line = request.split('\r\n')[0]
        method, url, protocol = first_line.split()

        parsed = urlparse(url)
        host = parsed.netloc.split(':')[0]
        port = int(parsed.netloc.split(':')[1]) if ':' in parsed.netloc else 80

        path = parsed.path if parsed.path else '/'
        modified_request = self.modify_request(request, host, path)
        print(f"Modified request:\n{modified_request}")

        parsed_request = self.parse_request(request)

        response = self.forward_request(host, port, modified_request)
        request_id = self.save_request(
            parsed_request['method'], 
            parsed_request['path'], 
            parsed_request['get_params'],
            parsed_request['headers'],
            parsed_request['cookies'],
            parsed_request['body'],
            parsed_request['post_params']
        )

        client_socket.sendall(response)

        parsed_response = self.parse_response(response.decode())
        self.save_response(request_id, parsed_response['status_code'], parsed_response['message'],
                            parsed_response['headers'], parsed_response['body'])


    def generate_cert(self, hostname):
        os.makedirs('temp_certs', exist_ok=True)
        prefix = f"temp_certs/{hostname.replace('*', '_')}"

        ca_cert = os.path.join(self.certs_dir, 'ca.crt')
        ca_key = os.path.join(self.certs_dir, 'ca.key')
        
        subprocess.run([
            'openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', f'{prefix}.key', '-out', f'{prefix}.csr',
            '-subj', f'/CN={hostname}',
            '-addext', 'subjectAltName=DNS:' + hostname,
            '-addext', 'keyUsage=digitalSignature,keyEncipherment',
            '-addext', 'extendedKeyUsage=serverAuth',
            '-addext', 'basicConstraints=CA:FALSE'
        ], check=True)


        with open(f'{prefix}.ext', 'w') as f:
            f.write(f"""authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:{hostname}""")
        
        subprocess.run([
            'openssl', 'x509', '-req', '-in', f'{prefix}.csr',
            '-CA', ca_cert, '-CAkey', ca_key, '-CAcreateserial',
            '-out', f'{prefix}.crt', '-days', '1',
            '-extfile', f'{prefix}.ext',
            '-sha256'
        ], check=True)
        
        with open(f'{prefix}.crt', 'rb') as f:
            cert = f.read()
        with open(f'{prefix}.key', 'rb') as f:
            key = f.read()
        
        for ext in ['.key', '.csr', '.crt', '.ext']:
            try:
                os.unlink(f'{prefix}{ext}')
            except:
                pass
        
        return key, cert

    def modify_request(self, request, host, path):
        lines = request.split('\r\n')
        lines[0] = f"{lines[0].split()[0]} {path} {lines[0].split()[2]}"
        
        new_lines = []
        for line in lines:
            if not line.startswith('Proxy-Connection'):
                new_lines.append(line)
        
        if not any(line.startswith('Connection:') for line in new_lines[1:]):
            new_lines.insert(1, 'Connection: close')
        
        return '\r\n'.join(new_lines)

    def forward_request(self, host, port, request):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.connect((host, port))
            server_socket.sendall(request.encode())
            
            response = b''
            while True:
                data = server_socket.recv(4096)
                if not data:
                    break
                response += data
            
            return response
        
    def bidirectional_forward(self, src, dst):
        timeout = 60
        sockets = [src, dst]
        buffer = b''
        response_buffer = b''
        request_saved = False
        response_saved = False
        
        try:
            while True:
                rlist, _, xlist = select.select(sockets, [], sockets, timeout)
                
                if xlist:
                    break
                    
                for sock in rlist:
                    try:
                        data = sock.recv(65536)
                        if not data:
                            return
                            
                        if sock is src:
                            dst.sendall(data)
                            if not request_saved:
                                buffer += data
                                if b'\r\n\r\n' in buffer:
                                    try:
                                        text = buffer.decode(errors="replace")
                                        parsed = self.parse_request(text)
                                        request_id = self.save_request(
                                            parsed['method'], 
                                            parsed['path'], 
                                            parsed['get_params'],
                                            parsed['headers'],
                                            parsed['cookies'],
                                            parsed['body'],
                                            parsed['post_params']
                                        )

                                        request_saved = True
                                    except Exception as e:
                                        print(f"[!] Error parsing HTTPS request: {e}")
                        else:
                            src.sendall(data)
                            if request_saved and not response_saved:
                                response_buffer += data
                                if b'\r\n\r\n' in response_buffer:
                                    try:
                                        text = response_buffer.decode(errors="replace")
                                        parsed_response = self.parse_response(text)

                                        self.save_response(
                                            request_id=request_id,
                                            status_code=parsed_response['status_code'],
                                            message=parsed_response['message'],
                                            headers=parsed_response['headers'],
                                            body=parsed_response['body']
                                        )

                                        response_saved = True
                                    except Exception as e:
                                        print(f"[!] Error parsing HTTPS response: {e}")
                            
                    except ssl.SSLWantReadError:
                        continue
                    except ssl.SSLEOFError:
                        return
                    except ConnectionResetError:
                        return
                    except socket.error as e:
                        if e.errno != errno.EAGAIN:
                            raise
                        continue
                        
        except Exception as e:
            print(f"Tunnel error: {repr(e)}")
        finally:
            try:
                src.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                dst.shutdown(socket.SHUT_RDWR)
            except:
                pass
            src.close()
            dst.close()
    
    def save_request(self, method, path, get_params, headers, cookies, body, post_params):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO requests (method, path, get_params, headers, cookies, body, post_params, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (method, path, json.dumps(get_params), json.dumps(headers), json.dumps(cookies), body, json.dumps(post_params), datetime.now()))
            conn.commit()
            request_id = cursor.lastrowid 

            conn.close()

            return request_id
        
        except Exception as e:
            print(f"Error saving request: {e}")
            return None

    def save_response(self, request_id, status_code, message, headers, body):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO responses (request_id, status_code, message, headers, body, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (request_id, status_code, message, json.dumps(headers), body, datetime.now()))
            conn.commit()
            conn.close()

        except Exception as e:
            print(f"Error saving request: {e}")

    def parse_request(self, request):
        lines = request.split('\r\n')
        first_line = lines[0]
        method, url, protocol = first_line.split()
        parsed_url = urlparse(url)
        
        get_params = parse_qs(parsed_url.query)
        headers = {}
        cookies = {}
        body = ''
        post_params = {}
        
        i = 1
        while i < len(lines):
            line = lines[i]
            i += 1
            if line == '':
                break 
            if ':' in line:
                header, value = line.split(':', 1)
                headers[header.strip()] = value.strip()
                if header.lower() == 'cookie':
                    cookies = self.parse_cookies(value.strip())

        body = '\r\n'.join(lines[i:]).strip()

        if headers.get('Content-Type') == 'application/x-www-form-urlencoded':
            post_params = parse_qs(body)
        
        return {
            "method": method,
            "path": parsed_url.path,
            "get_params": get_params,
            "headers": headers,
            "cookies": cookies,
            "body": body,
            "post_params": post_params
        }

    def parse_response(self, response):
        lines = response.split('\r\n')
        first_line = lines[0]
        protocol, status_code, message = first_line.split(' ', 2)
        
        headers = {}
        body = ''
        
        for line in lines[1:]:
            if not line:
                continue
            if ':' in line:
                header, value = line.split(":", 1)
                headers[header.strip()] = value.strip()

        body_start = response.find("\r\n\r\n")
        if body_start != -1:
            body = response[body_start + 4:]
        else:
            body = ''

        if 'Content-Encoding' in headers:
            encoding = headers['Content-Encoding']
            if encoding == 'gzip':
                body = gzip.decompress(body).decode('utf-8')
            elif encoding == 'deflate':
                body = zlib.decompress(body).decode('utf-8')
        
        return {
            "status_code": int(status_code),
            "message": message,
            "headers": headers,
            "body": body
        }

    def parse_cookies(self, cookie_str):
        cookies = {}
        for cookie in cookie_str.split(';'):
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()
        return cookies
    

if __name__ == '__main__':
    proxy = HTTPProxy()
    proxy.start()