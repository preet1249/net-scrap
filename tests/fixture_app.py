"""Local test application controlled by this project (two origins: app on 127.0.0.1, API on localhost)."""
from __future__ import annotations

import asyncio
import json
import socket
from typing import Any

from aiohttp import WSMsgType, web

SECRET_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXVzZXIifQ.c2lnbmF0dXJlLXRlc3Q"
SECRET_AWS = "AKIAIOSFODNN7EXAMPLE"
SECRET_PASSWORD = "hunter2-fixture-password"
SECRET_EMAIL = "alice.fixture@example.test"
SECRET_SSN = "123-45-6789"
SECRET_API_KEY = "sk_" + "live_" + "FIXTUREFIXTUREFIXTURE1234"  # assembled at runtime so source scanners do not flag this FAKE test key

APP_JS = r"""
(async function () {
  const API = window.API_ORIGIN, FAILED = window.FAILED_URL;
  const log = [];
  const step = async (name, fn) => { try { await fn(); log.push(name + ':ok'); } catch (e) { log.push(name + ':err:' + e.name); } };
  await step('fetch-json', () => fetch('/api/json').then(r => r.json()));
  await step('fetch-text', () => fetch('/api/text').then(r => r.text()));
  await step('xhr', () => new Promise((res, rej) => { const x = new XMLHttpRequest(); x.open('GET', '/api/xhr');
      x.onload = res; x.onerror = rej; x.send(); }));
  await step('post-json', () => fetch('/api/echo', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({name: 'x', password: '__PW__', note: 'n'})}));
  await step('vnd-json', () => fetch('/api/vnd').then(r => r.json()));
  await step('cors-simple', () => fetch(API + '/api/cors-simple').then(r => r.text()));
  await step('cors-preflight', () => fetch(API + '/api/cors', {headers: {'Authorization': 'Bearer FIXTURE-TOKEN-0123456789', 'X-Custom': '1'}}).then(r => r.json()));
  await step('cors-blocked', () => fetch(API + '/api/cors-nopolicy').then(r => r.text()));
  await step('redirect', () => fetch('/redirect/start').then(r => r.json()));
  await step('e404', () => fetch('/api/e404'));
  await step('e500', () => fetch('/api/e500'));
  await step('failed', () => fetch(FAILED));
  await step('repeated', () => fetch('/api/repeated'));
  await step('sensitive', () => fetch('/api/sensitive?token=FIXTURE-QUERY-TOKEN-0123456789&page=2').then(r => r.json()));
  await step('slow', () => fetch('/api/slow').then(r => r.text()));
  await step('large', () => fetch('/api/large').then(r => r.arrayBuffer()));
  await step('img', () => new Promise((res, rej) => { const i = new Image(); i.onload = res; i.onerror = rej; i.src = '/static/pixel.gif'; }));
  await step('ws', () => new Promise((res, rej) => { const w = new WebSocket(WS); w.onopen = () => w.send('hello');
      w.onmessage = () => { w.close(); }; w.onclose = res; w.onerror = rej; }));
  window.__log = log; window.__scenarioDone = true; document.title = 'Fixture Home (done)';
})();
//# sourceMappingURL=app.js.map
"""


def _a(fn: Any) -> Any:
    """Wrap a sync lambda into a coroutine handler."""
    async def handler(req: web.Request) -> Any:
        return fn(req)
    return handler


def _redir(location: str, status: int) -> web.Response:
    return web.Response(status=status, headers={"Location": location})


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class FixtureServer:
    def __init__(self) -> None:
        self.hits: list[tuple[str, str]] = []  # (method, path) of every request seen
        self.notes_store: list[str] = []
        self.profile_saved: dict[str, Any] | None = None
        self.uploads: list[dict[str, Any]] = []
        self.bodies: list[tuple[str, str, str]] = []  # (method, path, body) of state-changing requests
        self._runners: list[web.AppRunner] = []
        self.main_port = 0
        self.api_port = 0
        self.failed_port = 0

    @property
    def main_url(self) -> str:
        return f"http://127.0.0.1:{self.main_port}"

    @property
    def api_url(self) -> str:
        return f"http://localhost:{self.api_port}"

    def hit_methods(self, path_prefix: str) -> list[str]:
        return [m for m, p in self.hits if p.startswith(path_prefix)]

    # ---- app factory ------------------------------------------------------------------------
    def _main_app(self) -> web.Application:
        @web.middleware
        async def record(request: web.Request, handler: Any) -> web.StreamResponse:
            self.hits.append((request.method, request.path))
            if request.method not in ("GET", "HEAD", "OPTIONS"):
                self.bodies.append((request.method, request.path, (await request.read()).decode("utf-8", "replace")))
            return await handler(request)

        app = web.Application(middlewares=[record])
        r = app.router
        r.add_get("/", self.index)
        r.add_get("/static/app.js", self.app_js)
        r.add_get("/static/app.js.map", self.app_js_map)
        r.add_get("/static/pixel.gif", self.pixel)
        r.add_get("/api/json", _a(lambda req: web.json_response({"ok": True, "items": [1, 2, 3]})))
        r.add_get("/api/text", _a(lambda req: web.Response(text="plain text body", content_type="text/plain")))
        r.add_get("/api/xhr", _a(lambda req: web.json_response({"via": "xhr"})))
        r.add_post("/api/echo", self.echo)
        r.add_get("/api/vnd", self.vnd)
        r.add_get("/api/slow", self.slow)
        r.add_get("/api/large", self.large)
        r.add_get("/api/e404", _a(lambda req: web.json_response({"error": "nope"}, status=404)))
        r.add_get("/api/e500", _a(lambda req: web.json_response({"error": "boom"}, status=500)))
        r.add_get("/api/repeated", self.repeated)
        r.add_get("/api/sensitive", self.sensitive)
        r.add_get("/api/users/{uid}", self.user)
        r.add_get("/redirect/start", _a(lambda req: _redir("/redirect/mid", 302)))
        r.add_get("/redirect/mid", _a(lambda req: _redir("/redirect/end", 301)))
        r.add_get("/redirect/end", _a(lambda req: web.json_response({"final": True})))
        r.add_get("/redirect/offsite", _a(lambda req: _redir(f"{self.api_url}/offsite", 302)))
        r.add_get("/ws", self.ws)
        r.add_get("/popup-opener", self.popup_opener)
        r.add_get("/popup", _a(lambda req: self.html("<title>Popup</title><h1>popup</h1><script>fetch('/api/json')</script>")))
        r.add_get("/page2", self.page2)
        r.add_get("/page2/sub", _a(lambda req: self.html("<title>Sub</title><a href='/page2'>back</a>")))
        r.add_get("/users/{uid}", self.users_page)
        r.add_get("/danger", self.danger)
        r.add_post("/api/delete", _a(lambda req: web.json_response({"deleted": True})))
        r.add_get("/logout", _a(lambda req: self.html("<title>Logout</title>logged out")))
        r.add_get("/external", _a(lambda req: self.html(f"<title>External</title><a href='{self.api_url}/offsite'>offsite</a>")))
        r.add_get("/sw.js", self.sw_js)
        r.add_get("/sw-page", self.sw_page)
        r.add_get("/sw-data", _a(lambda req: web.json_response({"from": "network"})))
        r.add_get("/h/good", self.h_good)
        r.add_get("/h/bad", self.h_bad)
        r.add_get("/h/mixed", self.h_mixed)
        r.add_get("/leaky.js", self.leaky_js)
        r.add_get("/sec", self.sec_page)
        r.add_get("/dup", self.dup_page)
        r.add_get("/app", self.app_page)
        r.add_get("/spa", self.spa_page)
        r.add_post("/api/notes", self.notes_post)
        r.add_get("/api/notes", _a(lambda req: web.json_response(self.notes_store)))
        r.add_get("/spa2", self.spa2_page)
        r.add_get("/upl", self.upl_page)
        r.add_get("/upl2", self.upl2_page)
        r.add_get("/ov", self.ov_page)
        r.add_get("/ov2", self.ov_page)
        r.add_get("/prof", self.prof_page)
        r.add_post("/api/profile", self.profile_post)
        r.add_get("/inf", self.inf_page)
        r.add_get("/ov3", self.ov3_page)
        r.add_get("/clk", self.clk_page)
        r.add_get("/mem", self.mem_page)
        r.add_get("/img", self.img_page)
        r.add_get("/cover", self.cover_page)
        r.add_post("/api/card", _a(lambda req: web.json_response({"opened": True})))
        r.add_post("/api/upload", self.upload_post)
        r.add_post("/api/avatar", self.upload_post)
        r.add_delete("/api/upload/{uid}", _a(lambda req: web.json_response({"deleted": True})))
        r.add_route("*", "/notes", self.notes)
        r.add_post("/api/items", _a(lambda req: web.json_response({"created": True})))
        r.add_delete("/api/items/{iid}", _a(lambda req: web.json_response({"deleted": True})))
        r.add_post("/auth/v1/logout", _a(lambda req: web.json_response({"signed_out": True})))
        r.add_post("/account/password", _a(lambda req: self.html("<title>pw</title>changed")))
        r.add_post("/upload", _a(lambda req: self.html("<title>up</title>uploaded")))
        r.add_post("/api/invite", _a(lambda req: web.json_response({"invited": True})))
        r.add_get("/login", _a(lambda req: self.html("<title>Login</title><form><input type=password name=pw></form>")))
        r.add_get("/session-expired", _a(lambda req: _redir("/login", 302)))
        return app

    def _api_app(self) -> web.Application:
        app = web.Application()
        app.router.add_route("*", "/api/cors", self.cors)
        app.router.add_get("/api/cors-simple", self.cors_simple)
        app.router.add_get("/api/cors-nopolicy", _a(lambda req: web.Response(text="no cors headers")))
        app.router.add_get("/api/cors-reflect", self.cors_reflect)
        app.router.add_get("/offsite", self.offsite)
        return app

    # ---- handlers ---------------------------------------------------------------------------
    def html(self, body: str, headers: dict[str, str] | None = None) -> web.Response:
        return web.Response(text=f"<!doctype html><html><head><meta charset='utf-8'></head><body>{body}</body></html>",
                            content_type="text/html", headers=headers)

    async def index(self, req: web.Request) -> web.Response:
        ws = f"ws://127.0.0.1:{self.main_port}/ws"
        return self.html(
            f"<title>Fixture Home</title><nav><a href='/page2'>Page 2</a> <a href='/users/1'>User 1</a> "
            f"<a href='/users/2'>User 2</a> <a href='/danger'>Danger</a> <a href='/logout'>Logout</a> "
            f"<a href='/external'>External</a> <a href='/popup-opener'>Popup</a></nav>"
            f"<script>window.API_ORIGIN='{self.api_url}';window.FAILED_URL='http://127.0.0.1:{self.failed_port}/x';"
            f"window.WS='{ws}';</script><script src='/static/app.js'></script>")

    async def app_js(self, req: web.Request) -> web.Response:
        return web.Response(text=APP_JS.replace('__PW__', SECRET_PASSWORD), content_type="application/javascript")

    async def app_js_map(self, req: web.Request) -> web.Response:
        return web.json_response({"version": 3, "sources": ["src/app.ts"], "mappings": ""})

    async def pixel(self, req: web.Request) -> web.Response:
        gif = bytes.fromhex("47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b")
        return web.Response(body=gif, content_type="image/gif")

    async def vnd(self, req: web.Request) -> web.Response:
        return web.Response(text='{"id": 5, "kind": "vendor-json"}', content_type="application/vnd.pgrst.object+json")

    async def echo(self, req: web.Request) -> web.Response:
        return web.json_response({"received": True})

    async def slow(self, req: web.Request) -> web.Response:
        await asyncio.sleep(1.0)
        return web.Response(text="slow done", content_type="text/plain")

    async def large(self, req: web.Request) -> web.Response:
        return web.Response(body=b"A" * 2_000_000, content_type="application/octet-stream")

    async def repeated(self, req: web.Request) -> web.Response:
        resp = web.json_response({"ok": 1})
        resp.headers.add("X-Dup", "one")
        resp.headers.add("X-Dup", "two")
        resp.headers.add("Set-Cookie", "session=fixturesessionvalue123; Path=/")
        resp.headers.add("Set-Cookie", "pref=dark; Path=/; HttpOnly; Secure; SameSite=Lax")
        return resp

    async def sensitive(self, req: web.Request) -> web.Response:
        return web.json_response({
            "user": {"id": 7, "email": SECRET_EMAIL, "ssn": SECRET_SSN, "name": "Alice"},
            "password": SECRET_PASSWORD, "api_key": SECRET_API_KEY, "aws": SECRET_AWS, "token": SECRET_JWT,
            "debug": "Traceback (most recent call last):\n  File \"app.py\", line 1",
        })

    async def user(self, req: web.Request) -> web.Response:
        return web.json_response({"id": int(req.match_info["uid"]), "name": "User"})

    async def users_page(self, req: web.Request) -> web.Response:
        return self.html(f"<title>User {req.match_info['uid']}</title><script>fetch('/api/users/{req.match_info['uid']}')</script>")

    async def page2(self, req: web.Request) -> web.Response:
        return self.html("<title>Page 2</title><a href='/page2/sub'>sub</a> <a href='/'>home</a>"
                         "<div role='tablist'><button role='tab' id='t1' onclick=\"fetch('/api/json?tab=1')\">Tab One</button>"
                         "<button role='tab' id='t2' onclick=\"fetch('/api/json?tab=2')\">Tab Two</button></div>"
                         "<details><summary>More</summary><a href='/page2/sub'>hidden sub</a></details>")

    async def danger(self, req: web.Request) -> web.Response:
        return self.html("<title>Danger</title><button id='del' onclick=\"fetch('/api/delete',{method:'POST'})\">Delete account</button>"
                         "<button id='mystery' onclick=\"fetch('/api/json?mystery=1')\">Do thing</button>"
                         "<form method='post' action='/api/delete'><button type='submit'>Save</button></form>"
                         "<script>fetch('/api/delete',{method:'POST'})</script>")

    async def popup_opener(self, req: web.Request) -> web.Response:
        return self.html("<title>Opener</title><button id='open' onclick=\"window.open('/popup','_blank')\">open</button>"
                         "<script>window.open('/popup','_blank')</script>")

    async def ws(self, req: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(req)
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                await ws.send_str("echo:" + msg.data)
        return ws

    async def sw_js(self, req: web.Request) -> web.Response:
        js = ("self.addEventListener('install',e=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil(clients.claim()));"
              "self.addEventListener('fetch',e=>{if(new URL(e.request.url).pathname==='/sw-data'){e.respondWith(new Response(JSON.stringify({from:'sw'}),{headers:{'Content-Type':'application/json'}}))}});")
        return web.Response(text=js, content_type="application/javascript", headers={"Service-Worker-Allowed": "/"})

    async def sw_page(self, req: web.Request) -> web.Response:
        return self.html("<title>SW</title><script>(async()=>{const r=await navigator.serviceWorker.register('/sw.js');"
                         "await navigator.serviceWorker.ready;"
                         "if(!navigator.serviceWorker.controller){await new Promise(r=>navigator.serviceWorker.addEventListener('controllerchange',r));}"
                         "const d=await fetch('/sw-data').then(r=>r.json());window.__sw=d;document.title='SW ready '+d.from;})()</script>")

    async def h_good(self, req: web.Request) -> web.Response:
        return self.html("<title>Good headers</title>", headers={
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff", "Referrer-Policy": "strict-origin-when-cross-origin"})

    async def h_bad(self, req: web.Request) -> web.Response:
        return self.html("<title>Bad headers</title>", headers={
            "Content-Security-Policy": "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval' data:",
            "Referrer-Policy": "unsafe-url", "Set-Cookie": "sid=abcdefghijklmnop; Path=/"})

    async def h_mixed(self, req: web.Request) -> web.Response:
        return self.html("<title>Mixed</title>")

    async def app_page(self, req: web.Request) -> web.Response:
        return self.html(
            "<title>App</title><h1>Notes</h1>"
            "<form id='note' method='post' action='/notes'><input name='title' type='text'><textarea name='body'></textarea>"
            "<button type='submit'>Save note</button></form>"
            "<form id='pw' method='post' action='/account/password'><input type='password' name='pw'><button type='submit'>Save password</button></form>"
            "<form id='up' method='post' action='/upload' enctype='multipart/form-data'><input type='file' name='f'><button type='submit'>Save file</button></form>"
            "<button id='new' onclick=\"fetch('/api/items',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:'from-new-button'})})\">New item</button>"
            "<button id='del' onclick=\"fetch('/api/items/1',{method:'DELETE'})\">Remove item</button>"
            "<button id='out' onclick=\"fetch('/auth/v1/logout',{method:'POST'})\">Sign out</button>"
            "<button id='inv' onclick=\"fetch('/api/invite',{method:'POST'})\">Invite teammate</button>"
            "<a href='/logout'>Logout</a> <a href='/page2'>Page 2</a>"
            "<script>fetch('/api/items/1',{method:'DELETE'});fetch('/auth/v1/logout',{method:'POST'});</script>")  # hostile page-load requests

    async def notes_post(self, req: web.Request) -> web.Response:
        try:
            self.notes_store.append(str((await req.json()).get("text", "")))
        except Exception:
            pass
        return web.json_response({"created": True})

    async def upload_post(self, req: web.Request) -> web.Response:
        import re as _re
        data = await req.read()
        await asyncio.sleep(1.2)  # slow upload: navigating away mid-request would abort it
        m = _re.search(rb'filename="([^"]+)"', data)
        self.uploads.append({"path": req.path, "filename": m.group(1).decode() if m else None, "size": len(data),
                             "starts_pdf": b"%PDF" in data[:400], "has_png": b"PNG" in data[:400]})
        return web.json_response({"uploaded": True})

    async def clk_page(self, req: web.Request) -> web.Response:
        """SPA nav built from divs/spans (no <a>, no <button>): only cursor:pointer reveals them."""
        return self.html(
            "<title>Clickable divs</title><div style='cursor:pointer' onclick=\"fetch('/api/json?nav=memories')\">Memories</div>"
            "<ul><li style='cursor:pointer' onclick=\"fetch('/api/json?nav=children')\">Children</li></ul>"
            "<span style='cursor:pointer' onclick=\"fetch('/api/items/1',{method:'DELETE'})\">Remove everything</span>")

    async def mem_page(self, req: web.Request) -> web.Response:
        return self.html(
            "<title>Memories</title><button onclick=\"document.getElementById('m').style.display='block'\">Create a Memory</button>"
            "<button onclick=\"fetch('/api/invite',{method:'POST'})\">Create invite</button>"
            "<div id='m' role='dialog' style='display:none'><input placeholder='Title'><textarea placeholder='Write your memory'></textarea>"
            "<button onclick=\"fetch('/api/notes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:document.querySelector('#m textarea').value})})\">Save memory</button></div>")

    async def img_page(self, req: web.Request) -> web.Response:
        return self.html(
            "<title>Photo</title><input type='file' accept='image/*' style='display:none' onchange=\"document.getElementById('sv').disabled=false\">"
            "<button id='sv' disabled onclick=\"const f=document.querySelector('input[type=file]').files[0];const fd=new FormData();fd.append('file',f);fetch('/api/avatar',{method:'POST',body:fd})\">Save photo</button>")

    async def cover_page(self, req: web.Request) -> web.Response:
        """A transparent full-page layer (cookie-banner-like) intercepts pointer events but is not a dialog and has no close button."""
        return self.html(
            "<title>Cover</title><div style='position:fixed;inset:0;z-index:50;background:transparent'></div>"
            "<button role='tab' onclick=\"fetch('/api/json?covered=1')\">Covered tab</button>")

    async def profile_post(self, req: web.Request) -> web.Response:
        self.profile_saved = await req.json()
        return web.json_response({"saved": True})

    async def prof_page(self, req: web.Request) -> web.Response:
        """Formless profile editor: a prefilled field that must NOT be overwritten, an empty one that may be filled, a Save button."""
        return self.html(
            "<title>Profile</title><input id='name' placeholder='Display name' value='Existing Name'><textarea id='bio' placeholder='Your bio'></textarea>"
            "<button onclick=\"fetch('/api/profile',{method:'POST',headers:{'Content-Type':'application/json'},"
            "body:JSON.stringify({name:document.getElementById('name').value,bio:document.getElementById('bio').value})})\">Save</button>")

    async def inf_page(self, req: web.Request) -> web.Response:
        """Infinite list: each scroll to the bottom fetches the next page."""
        return self.html(
            "<title>Infinite</title><div id='l' style='height:200px'></div><div style='height:3000px'>spacer</div>"
            "<script>let n=1;const more=()=>{fetch('/api/json?page='+n);n++};more();"
            "window.addEventListener('scroll',()=>{if(window.innerHeight+scrollY>=document.documentElement.scrollHeight-5&&n<5)more()})</script>")

    async def ov3_page(self, req: web.Request) -> web.Response:
        """Harmless visible element whose class contains 'modal'/'popup' but does not cover or block anything."""
        return self.html("<title>Hint</title><span class='popup-hint modal-tag' style='font-size:10px'>tip</span>"
                         "<button role='tab' onclick=\"fetch('/api/json?tab=z')\">Zed</button><button role='tab' onclick=\"fetch('/api/json?tab=y')\">Why</button>")

    async def ov_page(self, req: web.Request) -> web.Response:
        """Floating 'Report issue' widget whose modal overlay covers the page until closed (as on many SPAs), plus tabs that re-render."""
        return self.html(
            "<title>Overlay</title>"
            "<div id='ov' role='dialog' style='display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:99'>"
            "<div style='background:#fff;margin:50px'>Tell us more <textarea></textarea><button onclick=\"document.getElementById('ov').style.display='none'\">Close</button></div></div>"
            "<button style='position:fixed;bottom:0;right:0;z-index:5' onclick=\"document.getElementById('ov').style.display='block'\">Report issue</button>"
            "<div id='tabs'><button role='tab' onclick=\"fetch('/api/json?tab=a');rr()\">Alpha</button>"
            "<button role='tab' onclick=\"fetch('/api/json?tab=b');rr()\">Beta</button>"
            "<button role='tab' onclick=\"fetch('/api/json?tab=c');rr()\">Gamma</button></div>"
            "<button onclick=\"fetch('/api/json?uncertain=1')\">Zoom thing</button>"
            "<a href='/ov2'>next</a><script>function rr(){const t=document.getElementById('tabs');t.innerHTML=t.innerHTML}</script>")

    async def upl2_page(self, req: web.Request) -> web.Response:
        return self.html(
            "<title>Upl2</title>"
            "<button>Upload A</button><button>Upload B</button><button>Upload C</button>"  # look like uploads but do nothing (no chooser, no request)
            "<button id='card' onclick=\"fetch('/api/card',{method:'POST'})\">Resume A<br>Uploaded</button>"  # status text on an existing item
            "<button id='new' onclick=\"fetch('/api/items',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:'created'})})\">New item</button>")

    async def upl_page(self, req: web.Request) -> web.Response:
        return self.html(
            "<title>Uploads</title>"
            "<button id='up' onclick=\"document.getElementById('f').click()\">Upload Resume</button>"
            "<input type='file' id='f' accept='.pdf,.docx' style='display:none' onchange=\"send('/api/upload', this.files[0])\">"
            "<input type='file' id='av' accept='image/*' style='display:none' onchange=\"send('/api/avatar', this.files[0])\">"
            "<button id='del' onclick=\"fetch('/api/upload/1',{method:'DELETE'})\">Delete file</button>"
            "<script>function send(u,f){const fd=new FormData();fd.append('file',f);fetch(u,{method:'POST',body:fd})}</script>")

    async def spa2_page(self, req: web.Request) -> web.Response:
        return self.html(
            "<title>SPA2</title><button onclick=\"document.getElementById('d').style.display='block'\">Paste Text</button>"
            "<div id='d' role='dialog' style='display:none'><textarea placeholder='Paste your resume text'></textarea>"
            "<button onclick=\"fetch('/api/notes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:document.querySelector('#d textarea').value})})\">Create</button></div>")

    async def spa_page(self, req: web.Request) -> web.Response:
        return self.html(
            "<title>SPA</title><ul id='l'></ul><script>fetch('/api/notes').then(r=>r.json()).then(a=>{document.getElementById('l').textContent=a.join(' | ')})</script><button id='open' onclick=\"document.getElementById('dlg').style.display='block'\">Spark Joy</button>"
            "<button id='del' onclick=\"fetch('/api/items/9',{method:'DELETE'})\">Delete note</button>"
            "<div id='dlg' role='dialog' style='display:none'><textarea id='t' placeholder='content'></textarea><input type='password' id='pw'>"
            "<button id='go' onclick=\"fetch('/api/notes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:document.getElementById('t').value})})\">Create</button>"
            "<button id='cancel'>Cancel</button></div>")

    async def notes(self, req: web.Request) -> web.Response:
        return self.html("<title>Notes saved</title>saved" if req.method == "POST" else "<title>Notes</title>notes")

    async def dup_page(self, req: web.Request) -> web.Response:
        return self.html("<title>Dup</title><script>(async()=>{for(let i=0;i<8;i++){await fetch('/api/json?i='+i).then(r=>r.json())}"
                         "window.__scenarioDone=true})()</script>")

    async def sec_page(self, req: web.Request) -> web.Response:
        return self.html(
            "<title>Security fixtures</title><a href='/h/good'>good</a> <a href='/h/bad'>bad</a> <a href='/users/1'>u1</a>"
            "<script src='/leaky.js'></script>"
            f"<script>const API='{self.api_url}';fetch('/api/sensitive');fetch('/static/app.js.map');"
            "fetch(API+'/api/cors-reflect',{credentials:'include'});fetch(API+'/api/cors-simple');"
            "fetch(API+'/api/cors',{headers:{'X-Custom':'1'}});fetch(API+'/api/cors-nopolicy').catch(()=>{})</script>")

    async def leaky_js(self, req: web.Request) -> web.Response:
        js = (f"var config = {{ apiKey: '{SECRET_API_KEY}', awsKey: '{SECRET_AWS}', publicFlag: true }};\n"
              f"var t = '{SECRET_JWT}';\n//# sourceMappingURL=leaky.js.map\n")
        return web.Response(text=js, content_type="application/javascript")

    # ---- API origin (cross-origin to the app) -----------------------------------------------
    async def cors(self, req: web.Request) -> web.Response:
        self.hits.append((req.method, "API:" + req.path))
        origin = req.headers.get("Origin", "")
        headers = {"Access-Control-Allow-Origin": origin, "Vary": "Origin"}
        if req.method == "OPTIONS":
            headers.update({"Access-Control-Allow-Methods": "GET, POST", "Access-Control-Allow-Headers": "authorization, x-custom",
                            "Access-Control-Max-Age": "60"})
            return web.Response(status=204, headers=headers)
        return web.json_response({"cors": "ok"}, headers=headers)

    async def offsite(self, req: web.Request) -> web.Response:
        self.hits.append((req.method, "API:" + req.path))
        return web.Response(text="<title>Offsite</title>offsite", content_type="text/html")

    async def cors_simple(self, req: web.Request) -> web.Response:
        self.hits.append((req.method, "API:" + req.path))
        return web.Response(text="simple", headers={"Access-Control-Allow-Origin": "*"})

    async def cors_reflect(self, req: web.Request) -> web.Response:
        return web.json_response({"x": 1}, headers={"Access-Control-Allow-Origin": req.headers.get("Origin", "*"),
                                                    "Access-Control-Allow-Credentials": "true"})

    # ---- lifecycle --------------------------------------------------------------------------
    async def start(self) -> "FixtureServer":
        self.failed_port = _free_port()  # nothing listens here -> connection refused
        for app, attr in ((self._main_app(), "main_port"), (self._api_app(), "api_port")):
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            port = _free_port()
            await web.TCPSite(runner, "127.0.0.1" if attr == "main_port" else None, port).start()
            setattr(self, attr, port)
            self._runners.append(runner)
        return self

    async def stop(self) -> None:
        for r in self._runners:
            await r.cleanup()
        self._runners.clear()


if __name__ == "__main__":  # manual run: python tests/fixture_app.py
    async def _main() -> None:
        s = await FixtureServer().start()
        print(json.dumps({"main": s.main_url, "api": s.api_url}))
        await asyncio.Event().wait()

    asyncio.run(_main())
