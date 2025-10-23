from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import re
import tldextract
from datetime import datetime, timedelta
import secrets
import logging
logging.basicConfig(level=logging.INFO)

# ----- App FastAPI -----
app = FastAPI(title="API de Controle Parental Avançada")

# ----- CORS -----
origins = [
    "http://127.0.0.1:8000",             
    "http://localhost:3000",             
    "http://localhost:5173",            
    "https://paideferro.vercel.app",
    "https://content-filter-api3.vercel.app"  
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----- Healthcheck -----
@app.get("/health")
def health():
    return {"status": "ok"}

# ----- Modelos -----
class ContentCheck(BaseModel):
    text: str

class ScheduleItem(BaseModel):
    day: str
    start_hour: str
    end_hour: str
    allowed: bool

class Permissions(BaseModel):
    admin_override: bool
    temporary_access: bool

class Restrictions(BaseModel):
    max_daily_usage: str
    block_unapproved_sites: bool

class ParentalControlSettings(BaseModel):
    blocked_categories: List[str]
    blocked_keywords: List[str]
    blocked_domains: List[str]
    allowed_categories: List[str]
    schedule: List[ScheduleItem]
    permissions: Permissions
    restrictions: Restrictions

# ----- Configurações iniciais -----
settings = ParentalControlSettings(
    blocked_categories=["pornografia", "conteudo_adulto", "drogas"],
    blocked_keywords=["sex", "porn", "drugs", "adult"],
    blocked_domains=["exampleporn.com", "drugsales.com"],
    allowed_categories=["educacao", "entretenimento_infantil", "noticias_gerais"],
    schedule=[
        ScheduleItem(day="segunda-feira", start_hour="07:00", end_hour="21:00", allowed=True),
        ScheduleItem(day="sabado", start_hour="09:00", end_hour="23:00", allowed=True),
        ScheduleItem(day="domingo", start_hour="09:00", end_hour="21:00", allowed=True)
    ],
    permissions=Permissions(admin_override=True, temporary_access=True),
    restrictions=Restrictions(max_daily_usage="4h", block_unapproved_sites=True)
)

# ----- Blacklist simples -----
BLACKLIST = [
    "sexo", "pornografia", "nudez", "xxx", "putaria",
    "caralho", "porra", "fuder", "buceta", "boquete",
    "transar", "puta", "merda", "corno", "vagabunda",
    "vadia", "prostituta", "vagabundo",
    "xvideos", "pornhub", "redtube", "xnxx", "brazzers",
    "onlyfans", "xhamster", "cam4", "youporn", "bangbros",
    "hentai", "erotico", "camgirls"
]

# ----- Funções de verificação -----
def check_blacklist(text: str):
    text_lower = text.lower()
    blocked_words = [word for word in BLACKLIST if word in text_lower]

    extracted = tldextract.extract(text_lower)
    domain = extracted.domain
    if domain in BLACKLIST:
        blocked_words.append(domain)

    return list(set(blocked_words))

def is_time_allowed(day: str, time: str) -> bool:
    schedule_item = next((s for s in settings.schedule if s.day.lower() == day.lower()), None)
    if not schedule_item:
        return False
    h, m = map(int, time.split(":"))
    sh, sm = map(int, schedule_item.start_hour.split(":"))
    eh, em = map(int, schedule_item.end_hour.split(":"))

    after_start = h > sh or (h == sh and m >= sm)
    before_end = h < eh or (h == eh and m <= em)
    return schedule_item.allowed and after_start and before_end

def is_url_allowed(url: str) -> bool:
    url_lower = url.lower()
    for domain in settings.blocked_domains:
        if domain.lower() in url_lower:
            return False
    for keyword in settings.blocked_keywords:
        if re.search(rf"\b{re.escape(keyword)}\b", url_lower):
            return False
    return True

# ----- Endpoints -----
@app.post("/check-content/")
def check_content(data: ContentCheck):
    blocked_words = check_blacklist(data.text)
    if blocked_words:
        return {"allowed": False, "reason": "Conteúdo bloqueado", "blocked_words": blocked_words}
    return {"allowed": True, "reason": "Conteúdo permitido"}

@app.get("/verificar_acesso")
def verificar_acesso(categoria: str = None, url: str = None, dia: str = None, horario: str = None):
    if dia is None or horario is None:
        raise HTTPException(status_code=400, detail="Dia e horário são obrigatórios")
    if not is_time_allowed(dia, horario):
        return {"acesso": "bloqueado", "motivo": "fora do horário permitido"}
    if categoria and categoria.lower() in [c.lower() for c in settings.blocked_categories]:
        return {"acesso": "bloqueado", "motivo": f"categoria '{categoria}' proibida"}
    if url and not is_url_allowed(url):
        return {"acesso": "bloqueado", "motivo": f"url '{url}' proibida"}
    return {"acesso": "permitido"}

@app.post("/atualizar_config")
def atualizar_config(novas_config: ParentalControlSettings):
    global settings
    settings = novas_config
    return {"status": "Configurações atualizadas com sucesso!"}

@app.get("/")
def root():
    return {"message": "🚀 API de Controle Parental está online! Acesse /docs para explorar os endpoints."}
from datetime import datetime, timedelta
import secrets

# ----- Modelos adicionais -----
class Parent(BaseModel):
    id: str
    nome: str
    email: str

class Device(BaseModel):
    id: str
    nome: str
    sistema: str  # "android" ou "ios"
    parent_id: str
    pareado_em: datetime
    ultimo_heartbeat: datetime | None = None
    ativo: bool = True

class PairCode(BaseModel):
    code: str
    parent_id: str
    expires_at: datetime
    usado: bool = False

# ----- Banco em memória (simples por enquanto) -----
pais_db = []
dispositivos_db = []
codigos_db = []

# ----- Endpoint: gerar código de pareamento -----
@app.post("/gerar_codigo_pareamento")
def gerar_codigo_pareamento(parent_id: str):
    code = secrets.token_hex(3).upper()  # ex: 'A1B2C3'
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    codigo = PairCode(code=code, parent_id=parent_id, expires_at=expires_at)
    codigos_db.append(codigo)
    return {"codigo": code, "expira_em": expires_at}

# ----- Endpoint: parear dispositivo -----
class ParingRequest(BaseModel):
    codigo: str
    nome_dispositivo: str
    sistema: str  # android / ios

@app.post("/parear_dispositivo")
def parear_dispositivo(req: ParingRequest):
    codigo = next((c for c in codigos_db if c.code == req.codigo and not c.usado), None)
    if not codigo:
        raise HTTPException(status_code=400, detail="Código inválido ou expirado")
    if codigo.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Código expirado")

    device_id = secrets.token_hex(8)
    dispositivo = Device(
        id=device_id,
        nome=req.nome_dispositivo,
        sistema=req.sistema,
        parent_id=codigo.parent_id,
        pareado_em=datetime.utcnow()
    )
    dispositivos_db.append(dispositivo)
    codigo.usado = True
    return {"status": "pareado", "device_id": device_id}

# ----- Endpoint: heartbeat (dispositivo ativo) -----
@app.post("/heartbeat/{device_id}")
def heartbeat(device_id: str):
    device = next((d for d in dispositivos_db if d.id == device_id), None)
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")
    device.ultimo_heartbeat = datetime.utcnow()
    return {"status": "ok", "ultimo_heartbeat": device.ultimo_heartbeat}

# ----- Endpoint: listar dispositivos do pai -----
@app.get("/listar_dispositivos/{parent_id}")
def listar_dispositivos(parent_id: str):
    lista = [d for d in dispositivos_db if d.parent_id == parent_id]
    return {"dispositivos": lista}
