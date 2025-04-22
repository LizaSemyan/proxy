from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import sqlite3
import json
import requests
import urllib.parse

app = FastAPI()

DATABASE_PATH = "/app/data/requests.db"

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.get("/requests")
def list_requests():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM requests")
    requests = cursor.fetchall()

    conn.close()

    requests_list = [dict(request) for request in requests]

    for req in requests_list:
        req['headers'] = json.loads(req['headers']) if req['headers'] else {}
        req['cookies'] = json.loads(req['cookies']) if req['cookies'] else {}
        req['get_params'] = json.loads(req['get_params']) if req['get_params'] else {}
        req['post_params'] = json.loads(req['post_params']) if req['post_params'] else {}

    return requests_list

@app.get("/requests/{id}")
def get_request_detail(id: int):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT * FROM requests WHERE id = ?
    ''', (id,))
    request = cursor.fetchone()

    cursor.execute("SELECT * FROM responses WHERE request_id = ?", (id,))
    response = cursor.fetchone()

    if not request:
        return f"Request with id {id} not found."
    
    conn.close()

    request_headers = json.loads(request["headers"])
    request_cookies = json.loads(request["cookies"])
    request_get_params = json.loads(request["get_params"])
    request_post_params = json.loads(request["post_params"])

    formatted_request = {
        "method": request['method'],
        "path": request['path'],
        "get_params": request_get_params,
        "headers": request_headers,
        "cookies": request_cookies,
        "body": request["body"],
        "post_params": request_post_params,
        "timestamp": request['timestamp']
    }

    formatted_response = "No response found for this request."
    if response:
        response_headers = json.loads(response["headers"])
        formatted_response = {
            "status_code": response['status_code'],
            "message": response['message'],
            "headers": response_headers,
            "body": response['body']
        }

    return {
        "request": formatted_request,
        "response": formatted_response
    }


@app.post("/repeat/{id}")
def repeat_request(id: int):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT * FROM requests WHERE id = ?
    ''', (id,))
    request = cursor.fetchone()

    conn.close()

    if not request:
        return f"Request with id {id} not found."

    method = request['method']
    path = request['path']
    get_params = json.loads(request['get_params']) if request['get_params'] else {}
    post_params = json.loads(request['post_params']) if request['post_params'] else {}
    headers = json.loads(request['headers']) if request['headers'] else {}
    cookies = json.loads(request['cookies']) if request['cookies'] else {}
    body = request['body'] if request['body'] else None

    headers.pop('Host', None)
    headers.pop('Proxy-Connection', None)
    headers.pop('Cookie', None)

    host = json.loads(request['headers']).get('Host')

    if not host:
        raise HTTPException(status_code=400, detail="Missing Host header in the original request")
    
    query_string = '&'.join(
        f"{key}={value}" if isinstance(value, str) else '&'.join(f"{key}={v}" for v in value)
        for key, value in get_params.items()
    )

    url = f"http://{host}{path}"
    if query_string:
        url += '?' + query_string

    if post_params and headers.get('Content-Type') == 'application/x-www-form-urlencoded':
        body = '&'.join(
            f"{key}={value}" if isinstance(value, str) else '&'.join(f"{key}={v}" for v in value)
            for key, value in post_params.items()
        )

    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, cookies=cookies)
        elif method == 'POST':
            response = requests.post(url, headers=headers, cookies=cookies, data=body)
        elif method == 'PUT':
            response = requests.put(url, headers=headers, cookies=cookies, data=body)
        elif method == 'DELETE':
            response = requests.delete(url, headers=headers, cookies=cookies)
        else:
            raise HTTPException(status_code=400, detail="Unsupported method")

        formatted_response = {
            "status_code": response.status_code,
            "message": response.reason,
            "headers": dict(response.headers),
            "body": response.text
        }
        return formatted_response, url, headers, cookies

    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/{id}")
def scan_request(id: int):
    XSS_PAYLOAD = "vulnerable'\"><img src onerror=alert()>"

    def encode_params(params):
        return urllib.parse.urlencode(params, doseq=True)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM requests WHERE id = ?", (id,))
    request = cursor.fetchone()
    conn.close()

    if not request:
        return f"Request with id {id} not found."

    method = request['method']
    path = request['path']
    get_params = json.loads(request['get_params']) if request['get_params'] else {}
    post_params = json.loads(request['post_params']) if request['post_params'] else {}
    headers = json.loads(request['headers']) if request['headers'] else {}
    cookies = json.loads(request['cookies']) if request['cookies'] else {}

    headers.pop('Host', None)
    headers.pop('Proxy-Connection', None)
    headers.pop('Cookie', None)

    host = json.loads(request['headers']).get('Host')
    if not host:
        raise HTTPException(status_code=400, detail="Missing Host header")

    url_base = f"http://{host}{path}"

    vulnerable_params = []

    def send_and_check(modified_get, modified_post=None):
        url = url_base
        if modified_get:
            url += '?' + encode_params(modified_get)

        body = None
        if modified_post:
            body = encode_params(modified_post)

        try:
            if method == 'GET':
                print(f"[!] GET: {url}")
                resp = requests.get(url, headers=headers, cookies=cookies)
            elif method == 'POST':
                print(f"[!] POST: {url} BODY: {body}")
                resp = requests.post(url, headers=headers, cookies=cookies, data=body)
            else:
                return False

            if XSS_PAYLOAD in resp.text:
                return True
        except Exception as e:
            print(f"[!] Error during request: {e}")
            return False

        return False

    for key in get_params:
        modified = dict(get_params)
        modified[key] = [XSS_PAYLOAD]
        if send_and_check(modified):
            vulnerable_params.append(f"GET::{key}")

    if method == 'POST':
        for key in post_params:
            modified = dict(post_params)
            modified[key] = [XSS_PAYLOAD]
            if send_and_check(get_params, modified):
                vulnerable_params.append(f"POST::{key}")

    return {
        "target": url_base,
        "vulnerable_params": vulnerable_params if vulnerable_params else "No XSS found"
    }