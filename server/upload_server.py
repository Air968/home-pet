#!/usr/bin/env python3
# 宠伴学园 · 应用服务（账号/云端数据/全局素材/图片上传 + 静态文件）纯标准库实现
# V3.1：原子写入 + 速率限制 + 安全头 + 健壮错误处理 + 输入验证 + 本地静态服务
import os, uuid, time, json, hashlib, secrets, threading, tempfile, mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote
from collections import defaultdict

# 路径配置：生产用默认值，本地通过环境变量覆盖
BASE = os.environ.get('PETAPP_BASE', '/var/www/petapp')
UPLOAD_DIR = os.environ.get('PETAPP_UPLOAD', BASE + '/uploads')
DATA_DIR = os.environ.get('PETAPP_DATA', BASE + '/data')
GLOBAL_FILE = BASE + '/global.json'
# 静态文件目录（前端 index.html 所在目录），生产由 nginx 提供时此项无效
STATIC_DIR = os.environ.get('PETAPP_STATIC', os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOKEN = 'cbxy-upload-8c1f'
MAX_UPLOAD = 10 * 1024 * 1024   # 单图 10MB
MAX_BODY = 4 * 1024 * 1024      # JSON 请求体 4MB
MAX_DATA_SIZE = 2 * 1024 * 1024 # 单用户存档上限 2MB
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
DEFAULT_ADMINS = ['admin']     # 管理员白名单（存于 global.json，客户端不可改）
LOCK = threading.Lock()

# 速率限制：每 IP 每分钟最多 RATE_LIMIT 次认证请求
RATE_LIMIT = 10
RATE_WINDOW = 60
_rate_buckets = defaultdict(list)
_rate_lock = threading.Lock()


def _rate_check(ip):
    """检查 IP 是否超过认证请求速率限制，返回 True 表示允许"""
    now = time.time()
    with _rate_lock:
        bucket = _rate_buckets[ip]
        # 清理过期记录
        cutoff = now - RATE_WINDOW
        while bucket and bucket[0] < cutoff:
            bucket.pop(0)
        if len(bucket) >= RATE_LIMIT:
            return False
        bucket.append(now)
        return True


def ukey(u):
    """用户名 → SHA256 文件名（防止用户名含特殊字符导致路径问题）"""
    return hashlib.sha256(u.encode('utf-8')).hexdigest()


def upath(u):
    return os.path.join(DATA_DIR, ukey(u) + '.json')


def valid_user(u):
    """用户名校验：2-20 字符，允许字母数字下划线和中文"""
    return 2 <= len(u) <= 20 and all(
        c.isalnum() or c == '_' or '\u4e00' <= c <= '\u9fa5' for c in u
    )


def _atomic_write(path, data, mode='w', encoding='utf-8'):
    """原子写入：先写临时文件再 rename，避免崩溃导致数据损坏"""
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, suffix='.tmp')
    try:
        with os.fdopen(fd, mode, encoding=encoding if 'b' not in mode else None) as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_user(u):
    try:
        with open(upath(u), 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def save_user(u, obj):
    """原子写入用户数据"""
    data = json.dumps(obj, ensure_ascii=False)
    _atomic_write(upath(u), data)


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
    """原子写入全局配置"""
    data = json.dumps(g, ensure_ascii=False)
    _atomic_write(GLOBAL_FILE, data)


def hash_pwd(salt, pwd):
    return hashlib.sha256((salt + pwd).encode('utf-8')).hexdigest()


def ensure_admin():
    """确保管理员账号存在（用户名 admin / 默认密码 admin，登录后请尽快修改）"""
    if not load_user('admin'):
        salt = secrets.token_hex(8)
        save_user('admin', {
            'user': 'admin',
            'salt': salt,
            'hash': hash_pwd(salt, 'admin'),
            'token': '',
            'data': None
        })
        print('admin account created (username: admin, default password: admin)')


class Handler(BaseHTTPRequestHandler):
    timeout = 60
    protocol_version = 'HTTP/1.1'
    server_version = 'PetApp/3.0'

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _security_headers(self):
        """安全响应头"""
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cache-Control', 'no-store')

    def _check_token(self):
        if self.headers.get('X-Upload-Token') != TOKEN:
            self._json(403, {'error': 'forbidden'})
            return False
        return True

    def _body(self):
        """读取并解析 JSON 请求体，超限返回 None"""
        try:
            n = int(self.headers.get('Content-Length') or 0)
            if n <= 0 or n > MAX_BODY:
                return None
            return json.loads(self.rfile.read(n).decode('utf-8'))
        except Exception:
            return None

    def _query(self, key):
        """取查询参数（转小写，用于扩展名等）"""
        if '?' not in self.path:
            return ''
        for kv in self.path.split('?', 1)[1].split('&'):
            if kv.startswith(key + '='):
                return kv[len(key) + 1:].lower()
        return ''

    def _query_raw(self, key):
        """取查询参数（原始大小写 + URL 解码，用于用户名/令牌）"""
        if '?' not in self.path:
            return ''
        for kv in self.path.split('?', 1)[1].split('&'):
            if kv.startswith(key + '='):
                return unquote(kv[len(key) + 1:])
        return ''

    def _client_ip(self):
        """获取客户端 IP（考虑反代）"""
        fwd = self.headers.get('X-Forwarded-For', '')
        if fwd:
            return fwd.split(',')[0].strip()
        return self.client_address[0] if self.client_address else 'unknown'

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
            # 非接口请求 → 提供静态文件 / 上传的图片
            return self._serve_static()
        except Exception:
            self._json(500, {'error': 'internal_error'})

    def _serve_static(self):
        """提供静态文件（index.html 等）和 /uploads/ 图片，方便本地开发单端口运行"""
        path = self.path.split('?', 1)[0]
        if path == '/':
            path = '/index.html'
        # /uploads/* 从上传目录提供
        if path.startswith('/uploads/'):
            rel = path[len('/uploads/'):]
            fpath = os.path.normpath(os.path.join(UPLOAD_DIR, rel))
            base = os.path.normpath(UPLOAD_DIR)
        else:
            rel = path.lstrip('/')
            fpath = os.path.normpath(os.path.join(STATIC_DIR, rel))
            base = os.path.normpath(STATIC_DIR)
        # 防目录穿越
        if not fpath.startswith(base) or '..' in rel or not os.path.isfile(fpath):
            return self._json(404, {'error': 'not found'})
        ctype = mimetypes.guess_type(fpath)[0] or 'application/octet-stream'
        try:
            with open(fpath, 'rb') as f:
                data = f.read()
            self.send_response(200)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            self.wfile.write(data)
        except OSError:
            self._json(404, {'error': 'not found'})

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
        except Exception:
            self._json(500, {'error': 'internal_error'})

    def _register(self):
        if not self._check_token():
            return
        if not _rate_check(self._client_ip()):
            return self._json(429, {'error': 'rate_limit'})
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
        if not _rate_check(self._client_ip()):
            return self._json(429, {'error': 'rate_limit'})
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
                # 限制存档大小，防止恶意写入超大数据
                data_str = json.dumps(d, ensure_ascii=False)
                if len(data_str.encode('utf-8')) > MAX_DATA_SIZE:
                    return self._json(413, {'error': 'data_too_large'})
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
        except Exception:
            self._json(500, {'error': 'internal_error'})

    def log_message(self, fmt, *args):
        pass


if __name__ == '__main__':
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)
    ensure_admin()
    HOST = os.environ.get('PETAPP_HOST', '0.0.0.0')
    PORT = int(os.environ.get('PETAPP_PORT', '9001'))
    print('app server listening on %s:%d (static: %s)' % (HOST, PORT, STATIC_DIR))
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
