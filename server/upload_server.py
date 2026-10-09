#!/usr/bin/env python3
# 宠伴学园 · 应用服务（账号/云端数据/全局素材/图片上传）纯标准库实现
# V2：新增管理员白名单（全局素材/图片仅管理员可改）+ 账号改密接口
import os, uuid, time, json, hashlib, secrets, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

BASE = '/var/www/petapp'
UPLOAD_DIR = BASE + '/uploads'
DATA_DIR = BASE + '/data'
GLOBAL_FILE = BASE + '/global.json'
TOKEN = 'cbxy-upload-8c1f'
MAX_UPLOAD = 10 * 1024 * 1024   # 单图 10MB
MAX_BODY = 4 * 1024 * 1024      # JSON 请求体 4MB
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
DEFAULT_ADMINS = ['admin']     # 管理员白名单（存于 global.json，客户端不可改）
LOCK = threading.Lock()


def ukey(u):
    return hashlib.sha256(u.encode('utf-8')).hexdigest()


def upath(u):
    return os.path.join(DATA_DIR, ukey(u) + '.json')


def valid_user(u):
    return 2 <= len(u) <= 20 and all(c.isalnum() or c == '_' or '\u4e00' <= c <= '\u9fa5' for c in u)


def load_user(u):
    try:
        with open(upath(u), 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def save_user(u, obj):
    with open(upath(u), 'w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False)


def load_global():
    try:
        with open(GLOBAL_FILE, 'r', encoding='utf-8') as f:
            g = json.load(f)
    except Exception:
        g = {}
    if not isinstance(g, dict):
        g = {}
    if not isinstance(g.get('admins'), list) or not g['admins']:
        g['admins'] = list(DEFAULT_ADMINS)
    g.setdefault('assets', {})
    g.setdefault('customSpecies', [])
    g.setdefault('customNames', {})
    return g


def save_global(g):
    with open(GLOBAL_FILE, 'w', encoding='utf-8') as f:
        json.dump(g, f, ensure_ascii=False)


def hash_pwd(salt, pwd):
    return hashlib.sha256((salt + pwd).encode('utf-8')).hexdigest()


def ensure_admin():
    """确保管理员账号存在（用户名 admin / 默认密码 admin，登录后请尽快修改）"""
    if not load_user('admin'):
        salt = secrets.token_hex(8)
        save_user('admin', {'user': 'admin', 'salt': salt, 'hash': hash_pwd(salt, 'admin'), 'token': '', 'data': None})
        print('admin account created (username: admin, default password: admin)')


class Handler(BaseHTTPRequestHandler):
    timeout = 60
    protocol_version = 'HTTP/1.1'

    def _json(self, code, obj):
        body = json.dumps(obj).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_token(self):
        if self.headers.get('X-Upload-Token') != TOKEN:
            self._json(403, {'error': 'forbidden'})
            return False
        return True

    def _body(self):
        try:
            n = int(self.headers.get('Content-Length') or 0)
            if n <= 0 or n > MAX_BODY:
                return None
            return json.loads(self.rfile.read(n).decode('utf-8'))
        except Exception:
            return None

    def _query(self, key):
        if '?' not in self.path:
            return ''
        for kv in self.path.split('?', 1)[1].split('&'):
            if kv.startswith(key + '='):
                return kv[len(key) + 1:].lower()
        return ''

    def _query_raw(self, key):
        """不转小写、带 URL 解码的取参（用于用户名/令牌）"""
        if '?' not in self.path:
            return ''
        for kv in self.path.split('?', 1)[1].split('&'):
            if kv.startswith(key + '='):
                return unquote(kv[len(key) + 1:])
        return ''

    def _is_admin(self, b=None):
        """校验请求携带的账号凭据（body 或 query 中的 u+token）是否为管理员"""
        u, tok = '', ''
        if isinstance(b, dict):
            u, tok = str(b.get('u') or ''), str(b.get('token') or '')
        if not u or not tok:
            u, tok = self._query_raw('u'), self._query_raw('token')
        if not u or not tok:
            return False
        rec = load_user(u)
        return bool(rec and rec.get('token') == tok and u in load_global().get('admins', []))

    # ---------- GET ----------
    def do_GET(self):
        try:
            if self.path.startswith('/api/upload'):
                if not self._check_token():
                    return
                if not self._is_admin():
                    return self._json(403, {'error': 'not_admin'})
                files = []
                total = 0
                for name in os.listdir(UPLOAD_DIR):
                    path = os.path.join(UPLOAD_DIR, name)
                    if os.path.isfile(path):
                        st = os.stat(path)
                        files.append({'name': name, 'size': st.st_size, 'mtime': int(st.st_mtime)})
                        total += st.st_size
                files.sort(key=lambda x: -x['size'])
                return self._json(200, {'files': files, 'count': len(files), 'bytes': total})
            if self.path.startswith('/api/global'):
                if not self._check_token():
                    return
                return self._json(200, load_global())
            return self._json(404, {'error': 'not found'})
        except Exception as e:
            try:
                self._json(500, {'error': str(e)})
            except Exception:
                pass

    # ---------- POST ----------
    def do_POST(self):
        try:
            if self.path.startswith('/api/upload'):
                return self._upload()
            if self.path.startswith('/api/auth/register'):
                return self._register()
            if self.path.startswith('/api/auth/login'):
                return self._login()
            if self.path.startswith('/api/auth/password'):
                return self._change_pwd()
            if self.path.startswith('/api/data/'):
                return self._data()
            if self.path.startswith('/api/global/save'):
                return self._global_save()
            return self._json(404, {'error': 'not found'})
        except Exception as e:
            try:
                self._json(500, {'error': str(e)})
            except Exception:
                pass

    def _register(self):
        if not self._check_token():
            return
        b = self._body() or {}
        u, p = str(b.get('u') or ''), str(b.get('p') or '')
        if not valid_user(u) or len(p) < 4:
            return self._json(400, {'error': 'bad params'})
        with LOCK:
            if load_user(u):
                return self._json(409, {'error': 'exists'})
            salt = secrets.token_hex(8)
            tok = secrets.token_hex(16)
            save_user(u, {'user': u, 'salt': salt, 'hash': hash_pwd(salt, p), 'token': tok, 'data': None})
        self._json(200, {'ok': True, 'token': tok})

    def _login(self):
        if not self._check_token():
            return
        b = self._body() or {}
        u, p = str(b.get('u') or ''), str(b.get('p') or '')
        with LOCK:
            rec = load_user(u)
            if not rec:
                return self._json(401, {'error': 'no_user'})
            if rec.get('hash') != hash_pwd(rec.get('salt', ''), p):
                return self._json(401, {'error': 'bad_pwd'})
            tok = secrets.token_hex(16)
            rec['token'] = tok
            save_user(u, rec)
        self._json(200, {'ok': True, 'token': tok})

    def _change_pwd(self):
        """修改账号登录密码（需旧密码验证）"""
        if not self._check_token():
            return
        b = self._body() or {}
        u, tok = str(b.get('u') or ''), str(b.get('token') or '')
        old, new = str(b.get('oldPwd') or ''), str(b.get('newPwd') or '')
        if len(new) < 4:
            return self._json(400, {'error': 'bad params'})
        with LOCK:
            rec = load_user(u)
            if not rec or rec.get('token') != tok:
                return self._json(401, {'error': 'bad_token'})
            if rec.get('hash') != hash_pwd(rec.get('salt', ''), old):
                return self._json(401, {'error': 'bad_old'})
            rec['hash'] = hash_pwd(rec['salt'], new)
            save_user(u, rec)
        self._json(200, {'ok': True})

    def _data(self):
        if not self._check_token():
            return
        b = self._body() or {}
        u, tok = str(b.get('u') or ''), str(b.get('token') or '')
        action = self.path.rstrip('/').rsplit('/', 1)[-1]
        with LOCK:
            rec = load_user(u)
            if not rec or rec.get('token') != tok:
                return self._json(401, {'error': 'bad_token'})
            if action == 'get':
                return self._json(200, {'ok': True, 'data': rec.get('data')})
            if action == 'save':
                d = b.get('data')
                if not isinstance(d, dict):
                    return self._json(400, {'error': 'bad data'})
                rec['data'] = d
                save_user(u, rec)
                return self._json(200, {'ok': True})
            if action == 'reset':
                rec['data'] = None
                save_user(u, rec)
                return self._json(200, {'ok': True})
        return self._json(404, {'error': 'not found'})

    def _global_save(self):
        if not self._check_token():
            return
        b = self._body() or {}
        if not self._is_admin(b):
            return self._json(403, {'error': 'not_admin'})
        with LOCK:
            g = load_global()
            if isinstance(b.get('assets'), dict):
                g['assets'] = b['assets']
            if isinstance(b.get('customSpecies'), list):
                g['customSpecies'] = b['customSpecies']
            if isinstance(b.get('customNames'), dict):
                g['customNames'] = b['customNames']
            save_global(g)
        self._json(200, {'ok': True})

    def _drain(self):
        """排空未读取的请求体，避免提前返回错误响应时连接错位"""
        try:
            n = int(self.headers.get('Content-Length') or 0)
            if n > 0:
                self.rfile.read(min(n, MAX_UPLOAD + 1024))
        except Exception:
            pass

    def _upload(self):
        if not self._check_token():
            self._drain()
            return
        if not self._is_admin():
            self._drain()
            return self._json(403, {'error': 'not_admin'})
        ext = self._query('ext')
        if ext not in ALLOWED_EXT:
            return self._json(400, {'error': 'bad ext'})
        length = int(self.headers.get('Content-Length') or 0)
        if length <= 0 or length > MAX_UPLOAD:
            return self._json(400, {'error': 'bad size'})
        data = self.rfile.read(length)
        if len(data) != length:
            return self._json(400, {'error': 'read error'})
        name = '%d_%s.%s' % (int(time.time() * 1000), uuid.uuid4().hex[:8], ext)
        with open(os.path.join(UPLOAD_DIR, name), 'wb') as f:
            f.write(data)
        self._json(200, {'url': '/uploads/' + name})

    # ---------- DELETE ----------
    def do_DELETE(self):
        try:
            if not self.path.startswith('/api/upload'):
                return self._json(404, {'error': 'not found'})
            if not self._check_token():
                return
            if not self._is_admin():
                return self._json(403, {'error': 'not_admin'})
            name = self._query('name')
            safe = name.replace('.', '').replace('_', '')
            if not name or '/' in name or '..' in name or not safe.isalnum():
                return self._json(400, {'error': 'bad name'})
            path = os.path.join(UPLOAD_DIR, name)
            if os.path.isfile(path):
                os.remove(path)
                return self._json(200, {'ok': True})
            return self._json(404, {'error': 'not found'})
        except Exception as e:
            try:
                self._json(500, {'error': str(e)})
            except Exception:
                pass

    def log_message(self, fmt, *args):
        pass


if __name__ == '__main__':
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)
    ensure_admin()
    print('app server listening on 127.0.0.1:9001')
    ThreadingHTTPServer(('127.0.0.1', 9001), Handler).serve_forever()
