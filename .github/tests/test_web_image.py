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
import json
import os
import pathlib
import struct
import sys
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
