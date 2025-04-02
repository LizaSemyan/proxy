import socket
import threading
from urllib.parse import urlparse

class HTTPProxy:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

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
            method, url, protocol = first_line.split()
            
            parsed = urlparse(url)
            host = parsed.netloc.split(':')[0]
            port = int(parsed.netloc.split(':')[1]) if ':' in parsed.netloc else 80

            path = parsed.path if parsed.path else '/'
            modified_request = self.modify_request(request, host, path)
            print(f"Modified request:\n{modified_request}")

            response = self.forward_request(host, port, modified_request)
            client_socket.sendall(response)

        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()

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

if __name__ == '__main__':
    proxy = HTTPProxy()
    proxy.start()