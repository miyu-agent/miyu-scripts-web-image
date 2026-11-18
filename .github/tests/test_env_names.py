# web_image.py 读新环境变量名的测试（审计 2026-11-18 #168）。
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

# 200×150 的 PNG 头：sniff 只看前 24 字节。
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + struct.pack(">II", 200, 150) + b"\x08\x02\x00\x00\x00" + b"\0" * 4


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


class EnvNames(Sandbox):
    # 审计 #168：核心 FH-6 以后只给新名字 MIYU_CACHE_DIR / MIYU_IMAGES_DIR，旧名 MIYU_SCRIPT_CACHE_DIR /
    # MIYU_SCRIPT_IMAGES_DIR 会删。脚本三处只读旧名：cooldown_path()、main() 里存图的缓存目录、交图目录。
    # 只设新名时：冷却表不写、main() 报「没有图片目录也没有脚本缓存目录」、不交图。
    def setUp(self):
        super().setUp()
        for old in ("MIYU_SCRIPT_CACHE_DIR", "MIYU_SCRIPT_IMAGES_DIR"):
            self.assertNotIn(old, os.environ)

        def found(query, limit, safe):
            return [self.mod.candidate("猫", "https://example.com/p", "https://example.com/cat.png", "",
                                       "duckduckgo", 200, 150)]

        def blocked(query, limit, safe):
            raise RuntimeError("HTTP Error 429: Too Many Requests")

        def fake_fetch(url, *args, **kwargs):
            self.calls.append(url)
            return PNG, url, "image/png"

        self.mod.SEARCHERS["duckduckgo"] = found
        self.mod.SEARCHERS["bing"] = blocked
        self.mod.fetch = fake_fetch

    def test_cache_dir_new_name(self):
        # 没有 MIYU_PICTURES_DIR 的会话：图存进 MIYU_CACHE_DIR/images，被 429 的必应记进 MIYU_CACHE_DIR/cooldowns.json。
        cache = self.root / "cache"
        cache.mkdir()
        os.environ["MIYU_CACHE_DIR"] = str(cache)
        code, out = self.call({"query": "猫", "count": 1})
        with self.subTest("main() 存图用 MIYU_CACHE_DIR"):
            self.assertEqual(code, 0, out)
            saved = list((cache / "images").glob("*/01.png"))
            self.assertEqual(len(saved), 1, f"MIYU_CACHE_DIR 下没有存图：{out}")
        with self.subTest("cooldown_path() 用 MIYU_CACHE_DIR"):
            self.assertEqual(self.mod.cooldown_path(), str(cache / "cooldowns.json"))
            self.assertTrue((cache / "cooldowns.json").is_file(), "被 429 的必应应记进冷却表")
            self.assertIn("bing", json.loads((cache / "cooldowns.json").read_text(encoding="utf-8")))

    def test_images_dir_new_name(self):
        # 图片目录用现行的 MIYU_PICTURES_DIR（存图不受缓存目录影响），只看交图目录读不读 MIYU_IMAGES_DIR。
        pictures = self.root / "pictures"
        images = self.root / "images"
        pictures.mkdir()
        images.mkdir()
        os.environ["MIYU_PICTURES_DIR"] = str(pictures)
        os.environ["MIYU_IMAGES_DIR"] = str(images)
        code, out = self.call({"query": "猫", "count": 1})
        self.assertEqual(code, 0, out)
        self.assertTrue((images / "01.png").is_file(), f"MIYU_IMAGES_DIR 里没有交图：{sorted(os.listdir(images))}")
        self.assertIn("第 1 张附在后面给你看", out)


if __name__ == "__main__":
    unittest.main()
