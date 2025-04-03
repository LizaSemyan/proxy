import socket
import threading
from urllib.parse import urlparse
import ssl
import tempfile
import os
import subprocess

class HTTPProxy:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.certs_dir = 'certs'
        os.makedirs(self.certs_dir, exist_ok=True)
        if not os.path.exists(os.path.join(self.certs_dir, 'ca.key')) or not os.path.exists(os.path.join(self.certs_dir, 'ca.crt')):
            self.generate_ca()

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

        # Отправляем подтверждение CONNECT
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

                # Критически важные настройки для Firefox
                client_context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384')
                
                client_context.minimum_version = ssl.TLSVersion.TLSv1_2
                client_context.maximum_version = ssl.TLSVersion.TLSv1_3
                
                # Обертка клиентского сокета
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

                # Подключение к целевому серверу
                server_socket = socket.create_connection((host, port), timeout=10)
                server_context = ssl.create_default_context()
                ssl_server = server_context.wrap_socket(
                    server_socket,
                    server_hostname=host,
                    do_handshake_on_connect=True
                )
            
                print(f"Tunnel established {ssl_client.version()} -> {ssl_server.version()}")
                self.bidirectional_forward(ssl_client, ssl_server)
                
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

        response = self.forward_request(host, port, modified_request)
        client_socket.sendall(response)

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
        import select
        import errno
        
        timeout = 60
        sockets = [src, dst]
        
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
                        else:
                            src.sendall(data)
                            
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

if __name__ == '__main__':
    proxy = HTTPProxy()
    proxy.start()