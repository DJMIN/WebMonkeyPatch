import base64
import hashlib
import json
from abc import ABC, abstractmethod
from multiprocessing import Process

import flask
import requests
import requests.utils
from flask import current_app, redirect, request

from twisted.internet import reactor
from twisted.web import proxy, resource, server, static

app = flask.Flask(__name__)
app.config["SESSION_COOKIE_HTTPONLY"] = True

DEV = False
PORT = 8111
WEB_URL_MIX = '192.168.20.70:8008'
WEB_URL_FRONTDEN_DEV = '127.0.0.1:'
# if DEV:
HOST_DOCSYSTEM = '192.168.20.90'
PORT_DOCSYSTEM = 8080
# else:
#     HOST_DOCSYSTEM = '192.168.20.90'
#     PORT_DOCSYSTEM = 8080
WEB_URL_DOCSYSTEM = f'{HOST_DOCSYSTEM}:{PORT_DOCSYSTEM}'
WEB_URL_GUACAMOLE = '192.168.20.90:8080'
HOST_IPS = '192.168.0.172'
PORT_IPS = 30852
WEB_URL_IPS = f'{HOST_IPS}:{PORT_IPS}'
HOST_CGI = '192.168.10.61'
PORT_CGI = 80
WEB_URL_CGI = f'{HOST_CGI}:{PORT_CGI}'
# HOST_YBCK = 'test.com'
HOST_YBCK = '192.168.20.208'
PORT_YBCK = 12333
WEB_URL_YBCK = f'{HOST_YBCK}:{PORT_YBCK}'
HOST_YBK = '192.168.20.221'
PORT_YBK = 8000
WEB_URL_YBK = f'{HOST_YBK}:{PORT_YBK}'


def get_md5(src, upper=False):
    md5_tool = hashlib.md5()
    md5_tool.update(src.encode(encoding='utf_8'))

    if upper:
        return md5_tool.hexdigest().upper()
    else:
        return md5_tool.hexdigest()


# 代理抽象基类
class BaseLoginProxy(ABC):

    @classmethod
    def format_logindata(cls, content):
        """格式化登录接口的token数据传给settoken接口调用，base64编码URL传参数data
        例如：x.x.x.x/settoken?

        Args:
            content ([type]): [description]

        Returns:
            [type]: [description]
        """
        return b""

    @classmethod
    @abstractmethod
    def get_home_page_url(cls, data):
        """生成302跳转到子系统登录后主页的URL"""
        raise NotImplementedError

    @classmethod
    def gen_go_to_set_token_url(cls, system, data):
        """生成302跳转到子系统登录后主页的HTTP返回包"""
        return f"/papi/settoken?system={system}&data={data}"

    @classmethod
    def gen_go_to_home_page_302_resp(cls, data=None):
        """生成302跳转到子系统登录后主页的HTTP返回包"""
        return redirect(cls.get_home_page_url(data), code=302)

    @classmethod
    def gen_go_to_home_page_url_resp(cls, data=None):
        """生成302跳转到子系统登录后主页的HTTP返回包"""
        return cls.get_home_page_url(data)

    @abstractmethod
    def login(self, username: str) -> flask.Response:
        """调用子系统登录接口的HTTP返回包"""
        raise NotImplementedError

    @staticmethod
    def get_username(token) -> str:
        if DEV:
            return 'admin'
        res = requests.post(f'http://{WEB_URL_MIX}/api/checktoken', json={'token': token}).json()
        print(res)
        return res.get('data', {}).get('username')

    @classmethod
    def make_token(cls, username, password) -> str:
        res = requests.post(f'http://{WEB_URL_MIX}/api/login',
                            data={'username': username, "password": password})
        print(res.content)
        cookie = requests.utils.dict_from_cookiejar(res.cookies)
        token = requests.post(
            f'http://{WEB_URL_MIX}/api/maketoken', cookies=cookie).json().get('data', {}).get('token', '')
        print(token)
        return token

    @classmethod
    def add_cookie(cls, old_resp, new_resp):
        cookies = old_resp.headers.get('Set-Cookie')
        print(22222, cls.__name__,  cookies)
        if cookies:
            new_resp.headers.add('Set-Cookie', cookies)
        return new_resp


##########
#  TODO 需要自行实现的子类
class ProxyDocSystem(BaseLoginProxy):
    @classmethod
    def get_home_page_url(cls, data):
        return '/DocSystem/web/projects.html'

    def login(self, username):
        user_table = {
            'admin1': "admin@guide",
            'admin2': "admin@guide",
            'admin3': "admin@guide",
            'admin4': "admin@guide",
            'admin5': "admin@guide",
        }
        password = user_table.get(username)
        return requests.get("http://{}/DocSystem/User/login.do?userName={}&pwd={}".format(
            WEB_URL_DOCSYSTEM,
            username,
            get_md5(password),
        ))


class ProxyCGI(BaseLoginProxy):
    @classmethod
    def get_home_page_url(cls, data):
        return '/cgi-bin/luci/'

    # @classmethod
    # def add_cookie(cls, old_resp, new_resp):
    #     return old_resp.content

    def login(self, username):
        username = "root"
        user_table = {'root': "123qwe"}
        password = user_table.get(username)
        res = requests.post("http://{}/cgi-bin/luci".format(
            WEB_URL_CGI
        ), allow_redirects=False, headers={
            "User-Agent": request.headers['User-Agent']
        }, data={
            'luci_username': username,
            'luci_password': password,
        })
        return res


class ProxyYBCK(BaseLoginProxy):
    @classmethod
    def get_home_page_url(cls, data):
        # return 'http://test.com:12333/index.php/jobs'
        return '/index.php/jobs'

    def login(self, username):
        username = "admin"
        user_table = {'admin': "super_s3cure_password"}
        password = user_table.get(username)
        res = requests.post("http://{}/index.php/login/check".format(
            WEB_URL_YBCK
        ), headers={
            "User-Agent": request.headers['User-Agent']
        }, data={
            'username': username,
            'password': password,
        })
        return res


class ProxyGuacamole(BaseLoginProxy):
    @classmethod
    def get_home_page_url(cls, data):
        return WEB_URL_GUACAMOLE

    def login(self, username):
        raise NotImplementedError


class ProxyIPS(BaseLoginProxy):
    @classmethod
    def format_logindata(cls, content):
        res = json.loads(content.decode())
        print(res)
        return json.dumps({'ip-search-authority': json.dumps({
            "token": res['token'],
            "username": res['username'],
            "user_type": {3: 'admin'}.get(res['user_type'], 'user'),
        })}).replace(' ', '').encode()

    @classmethod
    def get_home_page_url(cls, data=''):
        return cls.gen_go_to_set_token_url('ips', data)

    @staticmethod
    def get_fin_page_url():
        return f'/search'

    def login(self, username):
        user_table = {'admin': "admin"}
        password = user_table.get(username)
        print(WEB_URL_IPS)
        res = requests.post("http://{}/api/v1/users/login/".format(
            WEB_URL_IPS,
        ), headers={
            "User-Agent": request.headers['User-Agent']
        },
            json={
                "password": username,
                "type": "account",
                "username": password,
        })

        token = res.json()['token']
        res1 = requests.post("http://{}/api/v1/users/current/userInfo".format(
            WEB_URL_IPS,
        ), headers={"User-Agent": request.headers['User-Agent'], "authorization": token})
        return res


##########

PROXY_MANAGER = {
    'docSystem': ProxyDocSystem(),
    'guacamole': ProxyGuacamole(),
    'ips': ProxyIPS(),
    'cgi': ProxyCGI(),
    'ybck': ProxyYBCK(),
}


@app.route("/papi/autologin", methods=['GET'])
def auto_login():
    system = request.args.get("system")
    rproxy = PROXY_MANAGER.get(system)
    if DEV:
        token = rproxy.make_token('admin1', 'admin@guide')
    else:
        token = request.args.get("token")
    current_app.system = system
    if not rproxy:
        return 'Failed'

    username = rproxy.get_username(token)
    if username:
        try:
            resp = rproxy.login(username)
            print(resp.content)
            res_64_encode = base64.b64encode(
                rproxy.format_logindata(resp.content)).decode()
            new_resp = rproxy.gen_go_to_home_page_302_resp(res_64_encode)
            new_resp = rproxy.add_cookie(resp, new_resp)
        except Exception as e:
            return f'Failed {type(e)} {e}'
        return new_resp


@app.route("/papi/settoken", methods=['GET'])
def set_token():
    system = request.args.get("system")
    rproxy = PROXY_MANAGER.get(system)
    data = json.loads(base64.b64decode(request.args.get("data")).decode())
    return """
    <script>
    var kvs = {};
    for (var k in kvs){{
        window.localStorage.setItem(k, kvs[k]) 
    }}
    window.location.href = "{}";
    </script>""".format(data, rproxy.get_fin_page_url())


ps = []


def render(self, request):
    request.content.seek(0, 0)
    qs = proxy.urlparse(request.uri)[4]
    if qs:
        rest = self.path + b"?" + qs
    else:
        rest = self.path
    print(111111111111, rest)
    clientFactory = self.proxyClientFactoryClass(
        request.method,
        rest,
        request.clientproto,
        request.getAllHeaders(),
        request.content.read(),
        request,
    )
    self.reactor.connectTCP(self.host, self.port, clientFactory)
    return proxy.NOT_DONE_YET


proxy.ReverseProxyResource.render = render


def add_p(func, *args, **kwargs):
    ps.append(Process(target=func, args=args, kwargs=kwargs, daemon=True))


def run_ps():
    global ps
    for p in ps:
        name = getattr(p, '_target').__name__
        p.start()
        print(f"{name}: {p.pid}")
    for p in ps:
        p.join()


# noinspection PyTypeChecker
def run_proxy():
    # root = static.File(f"./")
    root = resource.Resource()
    # root = proxy.ReverseProxyResource(HOST_IPS, PORT_IPS, b'')

    for path, host, port, p_path in [
        (b"DocSystem", HOST_DOCSYSTEM, PORT_DOCSYSTEM, b'/DocSystem'),
        (b"ips", HOST_IPS, PORT_IPS, b'/'),
        (b"cgi-bin", HOST_CGI, PORT_CGI, b'/cgi-bin'),
        (b"luci-static", HOST_CGI, PORT_CGI, b'/luci-static'),
        (b"index.php", HOST_YBCK, PORT_YBCK, b'/index.php'),
        (b"ybk", HOST_YBK, PORT_YBK, b'/ybk'),
        (b"api", HOST_YBK, PORT_YBK, b'/api'),
        # (b"", HOST_IPS, PORT_IPS, b''),
        (b"papi", "127.0.0.1", 8110, b'/papi'),
    ]:
        root.putChild(path, proxy.ReverseProxyResource(host, port, p_path))
    site = server.Site(root)

    reactor.listenTCP(PORT, site)
    reactor.run()
    

if __name__ == "__main__":
    print("http://127.0.0.1:8111/papi/autologin?system=docSystem&token=1234")
    print("http://127.0.0.1:8111/papi/autologin?system=ips&token=1234")
    print("http://127.0.0.1:8111/papi/autologin?system=cgi&token=1234")
    print("http://127.0.0.1:8111/papi/autologin?system=ybck&token=1234")

    # 添加启动模拟登录后端 flask调用
    add_p(app.run, '0.0.0.0', port=8110, threaded=True)

    # 添加启动子系统和模拟登录后端的反向代理
    add_p(run_proxy)

    # 开始运行
    run_ps()
