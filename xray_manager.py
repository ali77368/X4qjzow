"""Optional Xray-core bridge for Trojan/VMess over WebSocket.

The public FastAPI service terminates HTTPS/WSS. Xray listens only on localhost
for the actual Trojan/VMess protocol, and this module bridges public WebSocket
connections to those local listeners.
"""
import asyncio, json, os, platform, stat, subprocess, tempfile, zipfile
from pathlib import Path
from urllib.request import urlopen, Request
import secrets
from datetime import datetime

XRAY_VERSION = os.environ.get("XRAY_VERSION", "26.3.27")
XRAY_DIR = Path(os.environ.get("XRAY_DIR", "/data/xray"))
XRAY_BIN = XRAY_DIR / "xray"
XRAY_CFG = XRAY_DIR / "config.json"
VMESS_PORT = int(os.environ.get("VMESS_LOCAL_PORT", "10081"))
TROJAN_PORT = int(os.environ.get("TROJAN_LOCAL_PORT", "10082"))
_sync_lock = asyncio.Lock()
_process = None


def _asset_name():
    arch = platform.machine().lower()
    if arch in ("aarch64", "arm64"):
        return "Xray-linux-arm64-v8a.zip"
    if arch in ("x86_64", "amd64"):
        return "Xray-linux-64.zip"
    raise RuntimeError(f"Unsupported Linux architecture: {arch}")


def _download_xray():
    XRAY_DIR.mkdir(parents=True, exist_ok=True)
    if XRAY_BIN.exists() and os.access(XRAY_BIN, os.X_OK):
        return
    url = f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/{_asset_name()}"
    tmp = XRAY_DIR / "xray.zip"
    req = Request(url, headers={"User-Agent": "X4G-Xray-Manager"})
    with urlopen(req, timeout=60) as r, open(tmp, "wb") as f:
        f.write(r.read())
    with zipfile.ZipFile(tmp) as z:
        member = next((n for n in z.namelist() if n.endswith("/xray") or n == "xray"), None)
        if not member:
            raise RuntimeError("Xray binary not found in release archive")
        with z.open(member) as src, open(XRAY_BIN, "wb") as dst:
            dst.write(src.read())
    XRAY_BIN.chmod(XRAY_BIN.stat().st_mode | stat.S_IEXEC)
    tmp.unlink(missing_ok=True)


def _build_config(links):
    vmess_users = []
    trojan_clients = []
    for uid, link in links.items():
        proto = link.get("protocol")
        if proto == "vmess-ws":
            vmess_users.append({"id": uid, "alterId": 0, "email": f"x4g-{uid[:8]}"})
        elif proto == "trojan-ws":
            trojan_clients.append({"password": uid, "email": f"x4g-{uid[:8]}"})

    inbounds = []
    if vmess_users:
        inbounds.append({
            "listen": "127.0.0.1", "port": VMESS_PORT, "protocol": "vmess",
            "settings": {"clients": vmess_users},
            "streamSettings": {"network": "ws", "wsSettings": {"path": "/vmess"}},
        })
    if trojan_clients:
        inbounds.append({
            "listen": "127.0.0.1", "port": TROJAN_PORT, "protocol": "trojan",
            "settings": {"clients": trojan_clients},
            "streamSettings": {"network": "ws", "wsSettings": {"path": "/trojan"}},
        })
    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }


def _stop_sync():
    global _process
    if _process and _process.poll() is None:
        _process.terminate()
        try: _process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _process.kill()
    _process = None

async def stop_xray():
    global _process
    async with _sync_lock:
        await asyncio.to_thread(_stop_sync)

async def sync_xray():
    global _process
    async with _sync_lock:
        # Import lazily to avoid import cycles during main.py startup.
        from main import LINKS, LINKS_LOCK
        async with LINKS_LOCK:
            links = dict(LINKS)
        wanted = any(l.get("protocol") in ("vmess-ws", "trojan-ws") for l in links.values())
        if not wanted:
            await asyncio.to_thread(_stop_sync)
            return
        cfg = _build_config(links)
        await asyncio.to_thread(_download_xray)
        XRAY_DIR.mkdir(parents=True, exist_ok=True)
        XRAY_CFG.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        await asyncio.to_thread(_stop_sync)
        _process = subprocess.Popen([str(XRAY_BIN), "run", "-c", str(XRAY_CFG)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        await asyncio.sleep(0.25)
        if _process.poll() is not None:
            raise RuntimeError("Xray exited immediately; check XRAY_VERSION/architecture")

async def _bridge(ws, uuid, local_port, expected_proto):
    from main import LINKS, LINKS_LOCK, is_link_allowed, is_ip_allowed, connections, stats, error_logs, log_activity, save_state
    from speed_limit import throttle
    import websockets
    await ws.accept()
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not link or link.get("protocol") != expected_proto or not is_link_allowed(link):
        await ws.close(code=1008, reason="not authorized")
        return
    ip = ws.headers.get("x-forwarded-for", "").split(",")[0].strip() or ws.headers.get("x-real-ip") or (ws.client.host if ws.client else "unknown")
    if not is_ip_allowed(link, uuid, ip):
        await ws.close(code=1008, reason="ip limit reached")
        return
    cid = secrets.token_urlsafe(6)
    connections[cid] = {"uuid": uuid, "ip": ip, "transport": expected_proto, "connected_at": datetime.now().isoformat(), "bytes": 0}
    upstream = None
    try:
        upstream = await websockets.connect(f"ws://127.0.0.1:{local_port}/{expected_proto.split('-')[0]}", max_size=None, ping_interval=None)
        async def client_to_xray():
            while True:
                msg = await ws.receive()
                if msg["type"] == "websocket.disconnect": break
                data = msg.get("bytes") or (msg.get("text") or "").encode()
                if not data: continue
                async with LINKS_LOCK:
                    l = LINKS.get(uuid)
                    if not is_link_allowed(l):
                        await ws.close(code=1008, reason="quota/disabled")
                        break
                    l["used_bytes"] += len(data); stats["total_bytes"] += len(data)
                await throttle(uuid, len(data)); stats["total_requests"] += 1
                connections[cid]["bytes"] += len(data)
                await upstream.send(data)
        async def xray_to_client():
            while True:
                data = await upstream.recv()
                if isinstance(data, str): data = data.encode()
                if not data: continue
                async with LINKS_LOCK:
                    l = LINKS.get(uuid)
                    if not is_link_allowed(l):
                        await ws.close(code=1008, reason="quota/disabled")
                        break
                    l["used_bytes"] += len(data); stats["total_bytes"] += len(data)
                await throttle(uuid, len(data)); connections[cid]["bytes"] += len(data)
                await ws.send_bytes(data)
        await asyncio.gather(client_to_xray(), xray_to_client())
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if upstream:
            try: await upstream.close()
            except Exception: pass
        connections.pop(cid, None)
        asyncio.create_task(save_state())

async def trojan_ws_bridge(ws, uuid: str):
    await _bridge(ws, uuid, TROJAN_PORT, "trojan-ws")

async def vmess_ws_bridge(ws, uuid: str):
    await _bridge(ws, uuid, VMESS_PORT, "vmess-ws")
