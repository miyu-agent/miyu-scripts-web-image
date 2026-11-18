# web_image.py 的测试（审计 2026-11-18）。
#
# 跑法（在仓库根）：
#   python3 -I -B -m unittest discover -s .github/tests
# （不加 -t .：.github 不是合法的包名，加了 unittest 会报 Start directory is not importable。）
#
# 只用标准库；不联网：fetch 和各搜索引擎都换成桩，断网也能跑。HOME、XDG_*、MIYU_* 都指到临时目录。
# 放在 .github/tests/ 而不是 tests/：打包会跳过 .github，测试不会进包。

import importlib.util
import io
import ipaddress
import json
import os
import pathlib
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from unittest import mock

SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "web_image.py"

# 宽 100、高 200 的 SOF0 段（长度 11，8 位精度，高 200，宽 100，1 个分量）。
SOF0 = struct.pack(">HBHHB", 11, 8, 200, 100, 1) + b"\x01\x11\x00"


def load():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("web_image_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Sandbox(unittest.TestCase):
    """每条测试一个临时目录，环境里去掉所有 MIYU_*，网络函数先换成直接失败的桩。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("MIYU_", "XDG_"))}
        env.update(HOME=str(root / "home"), XDG_CONFIG_HOME=str(root / "cfg"),
                   XDG_CACHE_HOME=str(root / "xdg-cache"), XDG_STATE_HOME=str(root / "xdg-state"),
                   XDG_DATA_HOME=str(root / "xdg-data"))
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.root = root
        self.mod = load()
        self.calls = []

        def no_network(url, *args, **kwargs):
            self.calls.append(url)
            raise AssertionError(f"测试里不该联网：{url}")

        def no_search(query, limit, safe):
            raise AssertionError(f"测试里不该联网搜：{query}")

        self.mod.fetch = no_network
        for name in list(self.mod.SEARCHERS):
            self.mod.SEARCHERS[name] = no_search

    def call(self, args):
        """照 main() 跑一次：stdin 喂 JSON，返回 (退出码, 输出)。"""
        out = io.StringIO()
        code = 0
        with mock.patch.object(sys, "stdin", io.StringIO(json.dumps(args))), redirect_stdout(out):
            try:
                self.mod.main()
            except SystemExit as exc:
                code = exc.code or 0
        return code, out.getvalue()

    def run_script(self, stdin_text):
        """另起进程跑脚本，返回 (退出码, stdout+stderr)，用来看有没有 traceback。"""
        proc = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT)], input=stdin_text,
                              capture_output=True, text=True, timeout=10, env=dict(os.environ))
        return proc.returncode, proc.stdout + proc.stderr


class Sniff(Sandbox):
    # 审计 #173-d：JPEG 规范允许段标记前有任意个 0xFF 填充字节。sniff() 在 0xFF 后直接把下一字节当标记，
    # 碰到 FF FF C0 就把第二个 FF 当成段、按后两字节当长度跳走，合法 JPEG 判成 None，下载时被丢掉。
    def test_jpeg_with_fill_byte(self):
        data = b"\xff\xd8" + b"\xff\xff\xc0" + SOF0 + b"\xff\xd9"
        self.assertEqual(self.mod.sniff(data), ("image/jpeg", 100, 200))

    # 防改坏（现在就绿）：不带填充字节的照常认出。
    def test_jpeg_without_fill_byte(self):
        data = b"\xff\xd8" + b"\xff\xc0" + SOF0 + b"\xff\xd9"
        self.assertEqual(self.mod.sniff(data), ("image/jpeg", 100, 200))


class TopLevelType(Sandbox):
    # 审计 #176：main() 只接 JSONDecodeError，不查顶层是不是对象；
    # 喂 [] 或 null 直接 args.get → AttributeError，打 traceback。应像 calculator 那样友好报错、退出码 1。
    # 参数检查在联网之前，另起的进程不联网。
    def test_non_object_args_friendly_error(self):
        for raw in ("[]", "null"):
            with self.subTest(stdin=raw):
                code, out = self.run_script(raw)
                self.assertEqual(code, 1, out)
                self.assertIn("参数要是一个 JSON 对象", out)
                self.assertNotIn("Traceback", out)


class FakeNet:
    """桩掉解析和建连接：answers 是每个主机名依次回的地址（用完了就一直回最后一个），
    responses 是每条连接依次交回的原始 HTTP 回应。connected 记下每次真正去连的地址。"""

    def __init__(self, answers, responses):
        self.answers = {host: list(addrs) for host, addrs in answers.items()}
        self.responses = list(responses)
        self.lookups = []
        self.connected = []
        self.server_names = []
        net = self

        class FakeSocket:
            def __init__(self, *args, **kwargs):
                self.reply = b""

            def connect(self, address):
                net.connected.append(address[:2])
                self.reply = net.responses.pop(0) if net.responses else b""

            def makefile(self, *args, **kwargs):
                return io.BytesIO(self.reply)

            def settimeout(self, *args):
                pass

            def setsockopt(self, *args):
                pass

            def sendall(self, data):
                pass

            def close(self):
                pass

        self.socket_class = FakeSocket

    def getaddrinfo(self, host, port, *args, **kwargs):
        try:
            ipaddress.ip_address(host)
            address = host
        except ValueError:
            self.lookups.append(host)
            queue = self.answers[host]
            address = queue.pop(0) if len(queue) > 1 else queue[0]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port or 80))]

    def wrap_socket(self, context, sock, server_hostname=None, **kwargs):
        self.server_names.append(server_hostname)
        return sock

    def patches(self):
        return [mock.patch("socket.getaddrinfo", self.getaddrinfo),
                mock.patch("socket.socket", self.socket_class),
                mock.patch.object(ssl.SSLContext, "wrap_socket",
                                  lambda context, sock, **kw: self.wrap_socket(context, sock, **kw))]


def ok_response(body=b"ok"):
    return b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body)


class PinnedAddress(Sandbox):
    # 审计 #173-e：public_url() 先 getaddrinfo 判公网，之后 urlopen 自己再解析一次。
    # 攻击者控制一个短 TTL 的域名，第一次回公网、第二次回 127.0.0.1，查过的和连的就不是同一个地址。
    # 断言行为：解析被换了以后，连的仍是查过的公网地址或者干脆不连，绝不是 127.0.0.1。
    # Sandbox 把 self.mod.fetch 换成了桩，这里另载一份真的。

    def setUp(self):
        super().setUp()
        for name in [k for k in os.environ if k.lower().endswith("_proxy")]:
            del os.environ[name]

    def fetch(self, net, url, env=None):
        os.environ.update(env or {})
        mod = load()
        for patcher in net.patches():
            patcher.start()
            self.addCleanup(patcher.stop)
        return mod.fetch(url)[0]

    def test_rebound_dns_never_connects_loopback(self):
        for scheme in ("http", "https"):
            with self.subTest(scheme=scheme):
                net = FakeNet({"rebind.example": ["93.184.216.34", "127.0.0.1"]}, [ok_response()])
                try:
                    self.fetch(net, f"{scheme}://rebind.example/x.png")
                except urllib.error.URLError:
                    pass
                self.assertNotIn("127.0.0.1", [address[0] for address in net.connected])

    # 防改坏：公网地址照常取到内容；HTTPS 的 SNI（和证书核对）仍用原主机名。
    def test_public_address_fetches(self):
        net = FakeNet({"img.example": ["93.184.216.34"]}, [ok_response()])
        self.assertEqual(self.fetch(net, "http://img.example/x.png"), b"ok")
        self.assertEqual(net.connected, [("93.184.216.34", 80)])
        net = FakeNet({"img.example": ["93.184.216.34"]}, [ok_response()])
        self.assertEqual(self.fetch(net, "https://img.example/x.png"), b"ok")
        self.assertEqual(net.connected, [("93.184.216.34", 443)])
        self.assertEqual(net.server_names, ["img.example"])

    # 防改坏：内网地址照旧被拒，一次都不连。
    def test_private_address_refused(self):
        net = FakeNet({"inner.example": ["10.0.0.1"]}, [ok_response()])
        with self.assertRaisesRegex(urllib.error.URLError, "not a public address"):
            self.fetch(net, "http://inner.example/x.png")
        self.assertEqual(net.connected, [])

    # 防改坏：跳转到内网照旧被拒，只连过第一跳的公网地址。
    def test_redirect_to_private_refused(self):
        redirect = b"HTTP/1.1 302 Found\r\nLocation: http://inner.example/x.png\r\nContent-Length: 0\r\n\r\n"
        net = FakeNet({"img.example": ["93.184.216.34"], "inner.example": ["192.168.1.1"]},
                      [redirect, ok_response()])
        with self.assertRaisesRegex(urllib.error.URLError, "redirect to a non-public address"):
            self.fetch(net, "http://img.example/x.png")
        self.assertEqual(net.connected, [("93.184.216.34", 80)])

    # 防改坏：设了代理就连代理（本机的代理也行），目标在代理的假 IP 段 198.18.0.0/15 照旧放行。
    def test_proxy_connects_to_proxy(self):
        net = FakeNet({"img.example": ["198.18.0.5"]}, [ok_response()])
        data = self.fetch(net, "http://img.example/x.png", env={"http_proxy": "http://127.0.0.1:7890"})
        self.assertEqual(data, b"ok")
        self.assertEqual(net.connected, [("127.0.0.1", 7890)])


if __name__ == "__main__":
    unittest.main()
