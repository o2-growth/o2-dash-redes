"""Coleta diária das métricas do Instagram da O2 e do Pedro para o dashboard.

Uso:
  python coletar.py            coleta os dias que faltam (até ontem) e atualiza posts e público
  python coletar.py --dias 90  refaz os últimos 90 dias

Precisa da variável META_TOKEN (token de usuário do sistema da Meta com instagram_manage_insights).
Grava em data/historico.json, data/posts.json e data/publico.json (só no computador, fora do Git).
Com DASH_SENHA definida, grava também data/painel.enc: os três arquivos juntos, criptografados
com AES-GCM e chave derivada da senha (PBKDF2-SHA256). É o único arquivo de dados publicado.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API = "https://graph.facebook.com/v23.0"
CONTAS = {"o2": "17841444734303992", "pedro": "17841401814883010"}
DATA = Path(__file__).parent / "data"
BRT = dt.timezone(dt.timedelta(hours=-3))
DIA_METRICAS = "reach,views,accounts_engaged,total_interactions,profile_views,website_clicks"
POST_METRICAS = "reach,views,saved,shares,total_interactions,likes,comments"
ITERACOES = 310000


def _chave(senha: str, sal: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=sal, iterations=ITERACOES).derive(senha.encode())


def cifrar(dados: dict, senha: str) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    sal, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(_chave(senha, sal)).encrypt(iv, json.dumps(dados, ensure_ascii=False).encode(), None)
    b = lambda x: base64.b64encode(x).decode()
    return {"v": 1, "iter": ITERACOES, "sal": b(sal), "iv": b(iv), "dados": b(ct)}


def decifrar(pacote: dict, senha: str) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    d = lambda k: base64.b64decode(pacote[k])
    return json.loads(AESGCM(_chave(senha, d("sal"))).decrypt(d("iv"), d("dados"), None))


def chamar(caminho: str, **params) -> dict:
    params["access_token"] = os.environ["META_TOKEN"].strip()
    url = f"{API}/{caminho}?{urllib.parse.urlencode(params)}"
    for tentativa in range(4):
        try:
            with urllib.request.urlopen(url, timeout=90) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            corpo = e.read().decode()[:300]
            if e.code in (429, 500, 502, 503) and tentativa < 3:
                time.sleep(20 * (tentativa + 1))
                continue
            raise RuntimeError(f"{caminho}: {e.code} {corpo}") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            if tentativa < 3:
                time.sleep(20)
                continue
            raise
    return {}


def ler(nome: str, padrao):
    f = DATA / nome
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else padrao


def gravar(nome: str, valor) -> None:
    DATA.mkdir(exist_ok=True)
    (DATA / nome).write_text(json.dumps(valor, ensure_ascii=False, indent=1), encoding="utf-8")


def janela(dia: dt.date) -> dict:
    ini = dt.datetime.combine(dia, dt.time(0), BRT)
    return {"since": int(ini.timestamp()), "until": int((ini + dt.timedelta(days=1)).timestamp())}


def dia_conta(ig: str, dia: dt.date) -> dict:
    j = janela(dia)
    out: dict = {}
    r = chamar(f"{ig}/insights", metric=DIA_METRICAS, period="day", metric_type="total_value", **j)
    for m in r.get("data", []):
        out[m["name"]] = m["total_value"].get("value", 0)
    r = chamar(f"{ig}/insights", metric="reach", period="day", metric_type="total_value",
               breakdown="media_product_type,follow_type", **j)
    alc = {"org_seg": 0, "org_nao": 0, "pago_seg": 0, "pago_nao": 0}
    for x in r["data"][0]["total_value"].get("breakdowns", [{}])[0].get("results", []):
        tipo, seg = x["dimension_values"]
        chave = ("pago" if tipo == "AD" else "org") + ("_seg" if seg == "FOLLOWER" else "_nao")
        alc[chave] += x["value"]
    out["alcance"] = alc
    r = chamar(f"{ig}/insights", metric="follows_and_unfollows", period="day", metric_type="total_value",
               breakdown="follow_type", **j)
    fu = {x["dimension_values"][0]: x["value"]
          for x in r["data"][0]["total_value"].get("breakdowns", [{}])[0].get("results", [])}
    out["seguiram"] = fu.get("FOLLOWER", 0)
    out["deixaram"] = fu.get("NON_FOLLOWER", 0)
    return out


def posts_conta(ig: str, desde: dt.date) -> list[dict]:
    posts, depois = [], None
    while True:
        p = {"fields": "id,timestamp,media_type,media_product_type,caption,permalink,like_count,comments_count",
             "limit": 50}
        if depois:
            p["after"] = depois
        r = chamar(f"{ig}/media", **p)
        lote = r.get("data", [])
        for m in lote:
            if m["timestamp"][:10] < desde.isoformat():
                return posts
            try:
                ins = chamar(f"{m['id']}/insights", metric=POST_METRICAS)
                met = {x["name"]: x["values"][0]["value"] for x in ins.get("data", [])}
            except RuntimeError:
                met = {"likes": m.get("like_count", 0), "comments": m.get("comments_count", 0)}
            legenda = (m.get("caption") or "").strip()
            posts.append({
                "id": m["id"], "data": m["timestamp"], "formato": m.get("media_product_type") == "REELS" and "Reel"
                or {"CAROUSEL_ALBUM": "Carrossel", "IMAGE": "Imagem", "VIDEO": "Vídeo"}.get(m["media_type"], m["media_type"]),
                "titulo": legenda.split("\n")[0][:140], "link": m["permalink"], **met})
        depois = r.get("paging", {}).get("cursors", {}).get("after")
        if not lote or not r.get("paging", {}).get("next"):
            return posts


def publico_conta(ig: str) -> dict:
    out = {}
    for bd in ("age", "gender", "city"):
        r = chamar(f"{ig}/insights", metric="follower_demographics", period="lifetime",
                   metric_type="total_value", breakdown=bd)
        res = r["data"][0]["total_value"].get("breakdowns", [{}])[0].get("results", [])
        out[bd] = {",".join(x["dimension_values"]): x["value"] for x in res}
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dias", type=int, default=0, help="refazer os últimos N dias")
    ap.add_argument("--desde", help="coletar a partir desta data (AAAA-MM-DD), só os dias que faltam")
    args = ap.parse_args()
    hoje = dt.datetime.now(BRT).date()
    ontem = hoje - dt.timedelta(days=1)
    senha = os.environ.get("DASH_SENHA", "").strip()
    hist = ler("historico.json", None)
    posts_db = ler("posts.json", {})
    publico = ler("publico.json", {})
    if hist is None and senha and (DATA / "painel.enc").exists():
        try:
            pac = decifrar(json.loads((DATA / "painel.enc").read_text(encoding="utf-8")), senha)
            hist, posts_db, publico = pac["hist"], pac["posts"], pac["publico"]
        except Exception:
            print("painel.enc não abriu com a senha atual: recomeçando o histórico")
    if hist is None:
        hist = {"contas": {k: {} for k in CONTAS}, "seguidores": {k: {} for k in CONTAS}}
        if not args.desde and not args.dias:
            args.desde = f"{hoje.year}-01-01"

    for nome, ig in CONTAS.items():
        dias = hist["contas"].setdefault(nome, {})
        inicio = ontem - dt.timedelta(days=(args.dias or 30) - 1)
        if dias and not args.dias:
            ultimo = max(dt.date.fromisoformat(d) for d in dias)
            inicio = max(inicio, min(ultimo + dt.timedelta(days=1), ontem - dt.timedelta(days=2)))
        if args.desde:
            inicio = dt.date.fromisoformat(args.desde)
        d = inicio
        while d <= ontem:
            if args.desde and d.isoformat() in dias and d < ontem - dt.timedelta(days=2):
                d += dt.timedelta(days=1)
                continue
            dias[d.isoformat()] = dia_conta(ig, d)
            print(nome, d, dias[d.isoformat()]["reach"] if "reach" in dias[d.isoformat()] else "")
            if d.day == 1:
                gravar("historico.json", hist)
            d += dt.timedelta(days=1)
        gravar("historico.json", hist)
        perfil = chamar(ig, fields="followers_count,follows_count,media_count")
        hist["seguidores"].setdefault(nome, {})[hoje.isoformat()] = perfil.get("followers_count")
        posts_db[nome] = posts_conta(ig, dt.date(hoje.year, 1, 1))
        if hoje.weekday() == 0 or nome not in publico:
            publico[nome] = {"data": hoje.isoformat(), **publico_conta(ig)}

    hist["atualizado"] = dt.datetime.now(BRT).strftime("%d/%m/%Y %H:%M")
    gravar("historico.json", hist)
    gravar("posts.json", posts_db)
    gravar("publico.json", publico)
    if senha:
        gravar("painel.enc", cifrar({"hist": hist, "posts": posts_db, "publico": publico}, senha))
    print("ok", hist["atualizado"])


if __name__ == "__main__":
    main()
