from fastapi import FastAPI, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Optional
import re
import tldextract
from datetime import datetime, timedelta
import secrets
import uuid
import logging

# 🔹 Handler para Vercel
from mangum import Mangum

# --------------------------------------------------
# 🔹 Logs
# --------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --------------------------------------------------
# 🔹 Inicialização do app
# --------------------------------------------------
app = FastAPI(
    title="API de Controle Parental Avançada",
    description="API para filtragem e pareamento",
    version="1.0.0"
)

# --------------------------------------------------
# 🔹 CORS DEFINITIVO
# --------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://(.*\.lovable\.app|.*\.lovableproject\.com|.*\.vercel\.app)",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------
# 🔹 Autenticação
# --------------------------------------------------
security = HTTPBearer()
SECURE_TOKEN = "CHAVE_SUPER_SECRETA_123"

def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    if credentials.credentials != SECURE_TOKEN:
        raise HTTPException(status_code=403, detail="Acesso negado")
    return True

# --------------------------------------------------
# 🔹 Healthcheck
# --------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok"}

# --------------------------------------------------
# 🔹 MODELOS
# --------------------------------------------------
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

# --------------------------------------------------
# 🔹 Configuração inicial
# --------------------------------------------------
settings = ParentalControlSettings(
    blocked_categories=["pornografia", "conteudo_adulto", "drogas"],
    blocked_keywords=["sex", "porn", "drugs", "adult"],
    blocked_domains=["exampleporn.com", "drugsales.com"],
    allowed_categories=["educacao", "entretenimento_infantil", "noticias_gerais"],
    schedule=[
        ScheduleItem(day="segunda-feira", start_hour="07:00", end_hour="21:00", allowed=True),
        ScheduleItem(day="sabado", start_hour="09:00", end_hour="23:00", allowed=True),
        ScheduleItem(day="domingo", start_hour="09:00", end_hour="21:00", allowed=True),
    ],
    permissions=Permissions(admin_override=True, temporary_access=True),
    restrictions=Restrictions(max_daily_usage="4h", block_unapproved_sites=True),
)

# --------------------------------------------------
# 🔹 Lista negra
# --------------------------------------------------
BLACKLIST = [
    "sexo", "pornografia", "nudez", "xxx", "putaria",
    "caralho", "porra", "fuder", "buceta", "boquete",
    "transar", "puta", "merda", "corno", "vagabunda",
    "vadia", "prostituta", "vagabundo",
    "xvideos", "pornhub", "redtube", "xnxx", "brazzers",
    "onlyfans", "xhamster", "cam4", "youporn", "bangbros",
    "hentai", "erotico", "camgirls"
]

# --------------------------------------------------
# 🔹 Funções auxiliares
# --------------------------------------------------
def check_blacklist(text: str):
    text_lower = text.lower()
    blocked = [w for w in BLACKLIST if w in text_lower]
    extracted = tldextract.extract(text_lower).domain
    if extracted in BLACKLIST:
        blocked.append(extracted)
    return list(set(blocked))

def is_time_allowed(day: str, time: str) -> bool:
    schedule = next((s for s in settings.schedule if s.day.lower() == day.lower()), None)
    if not schedule:
        return False
    h, m = map(int, time.split(":"))
    sh, sm = map(int, schedule.start_hour.split(":"))
    eh, em = map(int, schedule.end_hour.split(":"))
    return schedule.allowed and (h > sh or (h == sh and m >= sm)) and (h < eh or (h == eh and m <= em))

def is_url_allowed(url: str):
    u = url.lower()
    for d in settings.blocked_domains:
        if d.lower() in u:
            return False
    for k in settings.blocked_keywords:
        if re.search(rf"\b{re.escape(k)}\b", u):
            return False
    return True

# --------------------------------------------------
# 🔹 Endpoints principais
# --------------------------------------------------
@app.post("/check-content/")
def check_content(data: ContentCheck):
    blocked = check_blacklist(data.text)
    if blocked:
        return {"allowed": False, "reason": "Conteúdo bloqueado", "blocked_words": blocked}
    return {"allowed": True, "reason": "Conteúdo permitido"}

@app.get("/verificar_acesso")
def verificar_acesso(categoria: Optional[str] = None, url: Optional[str] = None,
                     dia: Optional[str] = None, horario: Optional[str] = None):

    if not dia or not horario:
        raise HTTPException(status_code=400, detail="Dia e horário são obrigatórios")

    if not is_time_allowed(dia, horario):
        return {"acesso": "bloqueado", "motivo": "fora do horário permitido"}

    if categoria and categoria.lower() in [c.lower() for c in settings.blocked_categories]:
        return {"acesso": "bloqueado", "motivo": f"categoria '{categoria}' proibida"}

    if url and not is_url_allowed(url):
        return {"acesso": "bloqueado", "motivo": f"url '{url}' proibida"}

    return {"acesso": "permitido"}

@app.post("/atualizar_config")
def atualizar_config(cfg: ParentalControlSettings, _: bool = Security(verify_token)):
    global settings
    settings = cfg
    return {"status": "Configurações atualizadas com sucesso!"}

@app.get("/")
def root():
    return {"message": "API de Controle Parental ativa!"}

# --------------------------------------------------
# 🔹 Pareamento
# --------------------------------------------------
class Parent(BaseModel):
    id: str = str(uuid.uuid4())
    nome: str
    email: str

class Device(BaseModel):
    id: str
    nome: str
    sistema: str
    parent_id: str
    pareado_em: datetime
    ultimo_heartbeat: Optional[datetime] = None
    ativo: bool = True

class PairCode(BaseModel):
    code: str
    parent_id: str
    expires_at: datetime
    usado: bool = False

pais_db = []
dispositivos_db = []
codigos_db = []

@app.post("/gerar_codigo_pareamento")
def gerar_codigo_pareamento(parent_id: str, _: bool = Security(verify_token)):
    code = secrets.token_hex(3).upper()
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    codigos_db.append(PairCode(code=code, parent_id=parent_id, expires_at=expires_at))
    return {"codigo": code, "expira_em": expires_at}

class ParingRequest(BaseModel):
    codigo: str
    nome_dispositivo: str
    sistema: str

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
        pareado_em=datetime.utcnow(),
    )
    dispositivos_db.append(dispositivo)
    codigo.usado = True
    return {"status": "pareado", "device_id": device_id}

@app.post("/heartbeat/{device_id}")
def heartbeat(device_id: str):
    device = next((d for d in dispositivos_db if d.id == device_id), None)
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")
    device.ultimo_heartbeat = datetime.utcnow()
    return {"status": "ok", "ultimo_heartbeat": device.ultimo_heartbeat}

@app.get("/listar_dispositivos/{parent_id}")
def listar_dispositivos(parent_id: str, _: bool = Security(verify_token)):
    lista = [d for d in dispositivos_db if d.parent_id == parent_id]
    return {"dispositivos": lista}

# --------------------------------------------------
# 🔹 Handler Serverless (OBRIGATÓRIO NA VERCEL)
# --------------------------------------------------
handler = Mangum(app)
