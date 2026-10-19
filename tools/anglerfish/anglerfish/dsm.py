"""
Believable Synology DSM webapi facade + login SPA.

Scripted answers only. Never grants access to anything real; planted/canary
credentials mint a sandboxed File Station session that serves bait.py's fake
filesystem and fires canary events on download.
"""

import hashlib
import json
import os
import time

from . import bait

# Realistic SYNO.API.Info catalog (subset a real DS220+-class DSM 7.1 returns).
_API_CATALOG = {
    "SYNO.API.Info": {"path": "query.cgi", "minVersion": 1, "maxVersion": 1},
    "SYNO.API.Auth": {"path": "auth.cgi", "minVersion": 1, "maxVersion": 7},
    "SYNO.FileStation.Info": {
        "path": "entry.cgi", "minVersion": 1, "maxVersion": 2,
        "requestFormat": "JSON",
    },
    "SYNO.FileStation.List": {
        "path": "entry.cgi", "minVersion": 1, "maxVersion": 2,
        "requestFormat": "JSON",
    },
    "SYNO.FileStation.Download": {
        "path": "entry.cgi", "minVersion": 1, "maxVersion": 2,
        "requestFormat": "JSON",
    },
    "SYNO.Core.System": {
        "path": "entry.cgi", "minVersion": 1, "maxVersion": 3,
        "requestFormat": "JSON",
    },
    "SYNO.Core.Desktop.Initdata": {
        "path": "entry.cgi", "minVersion": 1, "maxVersion": 1,
        "requestFormat": "JSON",
    },
}


def api_info_response(query="all"):
    """SYNO.API.Info — unauthenticated catalog, success:true."""
    if not query or query == "all":
        data = dict(_API_CATALOG)
    else:
        data = {}
        for name in query.split(","):
            name = name.strip()
            if name in _API_CATALOG:
                data[name] = _API_CATALOG[name]
    return {"success": True, "data": data}


def auth_login_response(ok, sid="", synotoken=""):
    """SYNO.API.Auth login. ok=False → error 400 (no such account / incorrect)."""
    if ok:
        return {
            "success": True,
            "data": {
                "sid": sid or _sid(),
                "synotoken": synotoken or _sid(),
                "is_portal_port": False,
            },
        }
    # Real DSM uses error code 400 for bad account/password.
    return {"success": False, "error": {"code": 400}}


def auth_logout_response():
    return {"success": True}


def entry_need_auth():
    """Unauthenticated entry.cgi — DSM error 119 (session timeout / no auth)."""
    return {"success": False, "error": {"code": 119}}


def entry_list_shares(world):
    """Minimal FileStation.List share listing from bait shares."""
    shares = world.get("shares") or {}
    files = []
    for name in sorted(shares.keys()):
        files.append({
            "isdir": True,
            "name": name,
            "path": "/" + name,
            "additional": {"owner": {"user": "admin", "group": "users"}},
        })
    return {
        "success": True,
        "data": {"files": files, "offset": 0, "total": len(files)},
    }


def system_info(world):
    return {
        "success": True,
        "data": {
            "model": world.get("nas_model") or "DS220+",
            "serial": "20A0BQN" + hashlib.md5(
                (world.get("hostname") or "x").encode()).hexdigest()[:6].upper(),
            "version": world.get("nas_firmware") or "5.0.1.2376",
            "version_string": "DSM " + (world.get("nas_firmware") or "5.0.1.2376"),
            "hostname": world.get("hostname") or "files01",
            "firmware_date": "2023/07/25",
            "firmware_ver": world.get("nas_firmware") or "5.0.1.2376",
            "uptime": int(max(0, time.time() - (world.get("boot_time")
                                                 or time.time() - 47 * 86400))),
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
            # The fake shell's `date`/`uname` are UTC; keep DSM consistent.
            "time_zone": "UTC",
            "time_zone_desc": "(GMT) Coordinated Universal Time",
        },
    }


def _sid():
    return os.urandom(8).hex().upper()


def login_page_html(world, failed=False, session_id=""):
    """DSM-looking SPA shell: references JS/CSS assets, not a 1309-byte form."""
    # Same brand rule as the live appliance login (sensor._login_page), so
    # both login surfaces name the one persona the same way ("Example Clinic NAS").
    company = world.get("company") or "Example Clinic"
    brand = "%s NAS" % (company.split()[0] if company else "File")
    model = world.get("nas_model") or "DS220+"
    firmware = world.get("nas_firmware") or "5.0.1.2376"
    host = world.get("hostname") or "files01"
    # Small natural variation so responses aren't byte-identical every time.
    nonce = os.urandom(4).hex()
    err = ""
    if failed:
        err = (
            '<div id="error" class="login-error" style="display:block">'
            "The username or password was not recognised.</div>"
        )
    else:
        err = '<div id="error" class="login-error" style="display:none"></div>'
    return (
        "<!DOCTYPE html>\n"
        "<html lang=en>\n<head>\n"
        "<meta charset=utf-8>\n"
        "<meta name=viewport content=\"width=device-width,initial-scale=1\">\n"
        "<meta name=synology content=\"DSM\">\n"
        "<meta name=session content=\"%s\">\n"
        "<title>%s - DiskStation</title>\n"
        "<link rel=stylesheet href=\"/webman/login.cgi?v=%s&css=1\">\n"
        "<script src=\"/webman/login.js?v=%s\"></script>\n"
        "<script src=\"/scripts/synology/dist/login.js?v=%s\"></script>\n"
        "</head>\n<body class=login-body data-host=\"%s\" data-model=\"%s\">\n"
        "<div id=sds-login class=login-container>\n"
        "  <div class=logo><span class=syno>%s</span> "
        "<span class=dsm>DiskStation Manager</span></div>\n"
        "  <div class=panel>\n"
        "    <h1>Sign in</h1>\n"
        "    <p class=meta>%s &middot; %s &middot; DSM %s</p>\n"
        "    %s\n"
        "    <form id=login-form method=post action=/ action-api="
        "\"/webapi/auth.cgi\">\n"
        "      <label for=username>Account</label>\n"
        "      <input id=username name=username autocomplete=username autofocus>\n"
        "      <label for=password>Password</label>\n"
        "      <input id=password name=password type=password "
        "autocomplete=current-password>\n"
        "      <label class=remember><input type=checkbox name=remember "
        "value=1> Stay signed in</label>\n"
        "      <button type=submit id=btn-login>Log in</button>\n"
        "    </form>\n"
        "  </div>\n"
        "  <p class=foot>&copy; Synology Inc. &middot; %s</p>\n"
        "</div>\n"
        "<script>window.SYNO={Session:{id:'%s'}}; "
        "if(window.SYNOLogin)SYNOLogin.init();</script>\n"
        "</body>\n</html>\n"
    ) % (
        session_id or nonce, brand, nonce, nonce, nonce,
        host, model, brand, company, model, firmware, err, company,
        session_id or nonce,
    )


def login_css():
    return (
        "body.login-body{margin:0;background:#4b4b4b;font-family:"
        "Verdana,'Segoe UI',sans-serif;color:#222}"
        ".login-container{max-width:420px;margin:64px auto}"
        ".logo{text-align:center;color:#fff;margin-bottom:18px}"
        ".logo .syno{font-size:28px;font-weight:700;letter-spacing:1px}"
        ".logo .dsm{font-size:18px;margin-left:6px;opacity:.85}"
        ".panel{background:#fff;border-radius:4px;padding:22px 28px 28px;"
        "box-shadow:0 2px 8px rgba(0,0,0,.25)}"
        ".panel h1{font-size:18px;font-weight:600;margin:0 0 6px}"
        ".meta{color:#777;font-size:12px;margin:0 0 14px}"
        "label{display:block;font-size:12px;margin:12px 0 4px}"
        "input[type=text],input[type=password],input#username,input#password{"
        "width:100%;padding:9px 10px;box-sizing:border-box;border:1px solid #bbb;"
        "border-radius:2px;font-size:14px}"
        "label.remember{font-size:12px;color:#555;margin-top:14px}"
        "button#btn-login{margin-top:18px;width:100%;background:#0086e5;color:#fff;"
        "border:0;padding:10px;font-size:14px;border-radius:2px;cursor:pointer}"
        "button#btn-login:hover{background:#0070c0}"
        ".login-error{background:#fdecea;color:#8a1f11;padding:10px 12px;"
        "margin:0 0 12px;font-size:12px;border-radius:2px}"
        ".foot{text-align:center;color:#bbb;font-size:11px;margin-top:18px}\n"
    )


def login_js():
    # Tiny client script so the page is a real SPA shell, not a static harvester.
    # Still posts to / (form) and also knows about /webapi/auth.cgi.
    return (
        "window.SYNOLogin=window.SYNOLogin||{init:function(){"
        "var f=document.getElementById('login-form');if(!f)return;"
        "f.addEventListener('submit',function(ev){"
        "var u=(document.getElementById('username')||{}).value||'';"
        "var p=(document.getElementById('password')||{}).value||'';"
        "if(!u||!p){ev.preventDefault();"
        "var e=document.getElementById('error');if(e){e.style.display='block';"
        "e.textContent='Please enter both account and password.';}}"
        "});}};\n"
    )


def not_found_html(world, path=""):
    # Tiny natural variation (comment with path hash) so 404s aren't byte-identical.
    tag = hashlib.md5((path or "/").encode()).hexdigest()[:8]
    return (
        "<!DOCTYPE html><html><head><meta charset=utf-8>"
        "<title>404 - Page Not Found</title>"
        "<!-- %s --></head>"
        "<body style='font-family:Verdana,sans-serif;padding:24px;background:#f5f5f5'>"
        "<h1 style='font-size:18px'>The page you are looking for is not found.</h1>"
        "<p><a href='/'>Back to DSM</a></p></body></html>\n"
    ) % tag


def nginx_414_html():
    return (
        "<html>\r\n<head><title>414 Request-URI Too Large</title></head>\r\n"
        "<body>\r\n<center><h1>414 Request-URI Too Large</h1></center>\r\n"
        "<hr><center>%s</center>\r\n"
        "</body>\r\n</html>\r\n" % bait.HTTP_SERVER
    )


def nginx_default_html():
    """nginx default-server page for unknown Host headers."""
    return (
        "<!DOCTYPE html>\n<html>\n<head><title>Welcome to nginx!</title>"
        "<style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,"
        "sans-serif}</style></head>\n<body>\n"
        "<h1>Welcome to nginx!</h1>\n"
        "<p>If you see this page, the nginx web server is successfully installed "
        "and working. Further configuration is required.</p>\n"
        "<p><em>Thank you for using nginx.</em></p>\n"
        "</body>\n</html>\n"
    )


def filestation_list(world, folder_path, shares):
    """SYNO.FileStation.List for one share folder, built only from bait shares
    (the in-memory fake tree under /srv/shares; nothing on the real disk)."""
    folder = (folder_path or "").strip("/")
    share = folder.split("/", 1)[0] if folder else ""
    if not share or share not in shares:
        return {"success": False, "error": {"code": 408}}
    rows = []
    for row in shares[share]:
        rows.append({
            "isdir": False,
            "name": row["name"],
            "path": "/%s/%s" % (share, row["name"]),
            "additional": {"size": row.get("size", 0),
                           "owner": {"user": "admin", "group": "users"}},
        })
    return {"success": True,
            "data": {"files": rows, "offset": 0, "total": len(rows)}}


def filestation_not_found():
    """DSM FileStation error 408: no such file or directory."""
    return {"success": False, "error": {"code": 408}}
