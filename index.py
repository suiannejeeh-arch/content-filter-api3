# index.py
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import tldextract
import logging

# SQLAlchemy (sincrono, leve) para persistência em SQLite
from sqlalchemy import (
    create_engine, Column, String, Boolean, DateTime, Integer, Text
)
from sqlalchemy.orm import sessionmaker, declarative_base

# Mangum para handlers serverless (opcional - mantido para compatibilidade)
from mangum import Mangum

# --------------------------
# Config / Logging
# --------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pai_de_ferro_api")

DB_FILE = os.getenv("DB_FILE", "pai_de_ferro.db")
SECURE_TOKEN = os.getenv("SECURE_TOKEN", "CHAVE_SUPER_SECRETA_123")

# --------------------------
# FastAPI app & CORS
# --------------------------
app = FastAPI(
    title="Pai de Ferro - API de Controle Parental",
    description="Filtragem de conteúdo, pareamento de dispositivos e verificação de acesso.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://.*",  # em produção, substitua por allow_origins=["https://seu.site"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    if not credentials or credentials.credentials != SECURE_TOKEN:
        raise HTTPException(status_code=403, detail="Token inválido")
    return True

# --------------------------
# Banco de dados (SQLite)
# --------------------------
engine = create_engine(f"sqlite:///{DB_FILE}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class ParentDB(Base):
    __tablename__ = "parents"
    id = Column(String, primary_key=True, index=True)
    nome = Column(String, nullable=False)
    email = Column(String, nullable=False)

class DeviceDB(Base):
    __tablename__ = "devices"
    id = Column(String, primary_key=True, index=True)
    nome = Column(String, nullable=False)
    sistema = Column(String, nullable=False)
    parent_id = Column(String, nullable=False)
    pareado_em = Column(DateTime, nullable=False)
    ultimo_heartbeat = Column(DateTime, nullable=True)
    ativo = Column(Boolean, default=True)

class PairCodeDB(Base):
    __tablename__ = "paircodes"
    id = Column(Integer, primary_key=True, autoincrement=True)
    code = Column(String, index=True, nullable=False)
    parent_id = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    usado = Column(Boolean, default=False)

# cria tables
Base.metadata.create_all(bind=engine)

# --------------------------
# Pydantic models (API)
# --------------------------
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

class ParingRequest(BaseModel):
    codigo: str
    nome_dispositivo: str
    sistema: str

# --------------------------
# Config default em memória
# (armazene em DB ou arquivo se quiser persistir settings)
# --------------------------
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

# BLACKLIST básico
BLACKLIST = [
    "sexo", "pornografia", "nudez", "xxx", "putaria",
    "caralho", "porra", "fuder", "buceta", "boquete",
    "transar", "puta", "merda", "corno", "vagabunda",
    "vadia", "prostituta", "vagabundo",
    "xvideos", "pornhub", "redtube", "xnxx", "brazzers",
    "onlyfans", "xhamster", "cam4", "youporn", "bangbros",
    "hentai", "erotico", "camgirls"
]

# --------------------------
# Auxiliares
# --------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def check_blacklist(text: str):
    text_lower = text.lower()
    blocked = [w for w in BLACKLIST if w in text_lower]
    try:
        extracted = tldextract.extract(text_lower)
        domain = ".".join(part for part in (extracted.domain, extracted.suffix) if part)
        if domain and any(b in domain for b in BLACKLIST):
            blocked.append(domain)
    except Exception:
        logger.debug("tldextract: falha ao extrair domínio (ambiente isolado).")
    return list(set(blocked))

def is_time_allowed(day: str, time_str: str) -> bool:
    schedule = next((s for s in settings.schedule if s.day.lower() == day.lower()), None)
    if not schedule:
        return False
    try:
        h, m = map(int, time_str.split(":"))
        sh, sm = map(int, schedule.start_hour.split(":"))
        eh, em = map(int, schedule.end_hour.split(":"))
    except Exception:
        return False
    now = h * 60 + m
    start = sh * 60 + sm
    end = eh * 60 + em
    return schedule.allowed and (start <= now <= end)

def is_url_allowed(url: str):
    u = url.lower()
    for d in settings.blocked_domains:
        if d.lower() in u:
            return False
    for k in settings.blocked_keywords:
        if re.search(rf"\b{re.escape(k)}\b", u):
            return False
    return True

# --------------------------
# Endpoints
# --------------------------
@app.get("/health")
async def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}

@app.post("/filter")
async def filter_text(payload: dict):
    try:
        text = payload.get("text", "")
        banned_words = ["proibido", "banido"]
        for w in banned_words:
            if w in text.lower():
                return {"allowed": False, "reason": "Conteúdo bloqueado (palavra proibida)."}
        return {"allowed": True}
    except Exception as e:
        logger.exception("Erro em /filter")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/check-content")
async def check_content(data: ContentCheck):
    blocked = check_blacklist(data.text)
    if blocked:
        return {"allowed": False, "reason": "Conteúdo bloqueado", "blocked_words": blocked}
    return {"allowed": True, "reason": "Conteúdo permitido"}

@app.get("/verificar_acesso")
async def verificar_acesso(
    categoria: Optional[str] = None,
    url: Optional[str] = None,
    dia: Optional[str] = None,
    horario: Optional[str] = None,
):
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
async def atualizar_config(cfg: ParentalControlSettings, authorized: bool = Security(verify_token)):
    global settings
    settings = cfg
    return {"status": "Configurações atualizadas com sucesso!"}

# Pareamento / persistência
@app.post("/gerar_codigo_pareamento")
async def gerar_codigo_pareamento(parent_id: str, authorized: bool = Security(verify_token)):
    code = secrets.token_hex(3).upper()
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    db = next(get_db())
    pc = PairCodeDB(code=code, parent_id=parent_id, expires_at=expires_at, usado=False)
    db.add(pc)
    db.commit()
    db.refresh(pc)
    return {"codigo": code, "expira_em": expires_at.isoformat()}

@app.post("/parear_dispositivo")
async def parear_dispositivo(req: ParingRequest):
    db = next(get_db())
    codigo = db.query(PairCodeDB).filter(PairCodeDB.code == req.codigo, PairCodeDB.usado == False).first()
    if not codigo:
        raise HTTPException(status_code=400, detail="Código inválido ou já usado")
    if codigo.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Código expirado")
    device_id = secrets.token_hex(8)
    dispositivo = DeviceDB(
        id=device_id,
        nome=req.nome_dispositivo,
        sistema=req.sistema,
        parent_id=codigo.parent_id,
        pareado_em=datetime.utcnow(),
        ativo=True
    )
    db.add(dispositivo)
    codigo.usado = True
    db.commit()
    return {"status": "pareado", "device_id": device_id}

@app.post("/heartbeat/{device_id}")
async def heartbeat(device_id: str):
    db = next(get_db())
    device = db.query(DeviceDB).filter(DeviceDB.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")
    device.ultimo_heartbeat = datetime.utcnow()
    db.commit()
    return {"status": "ok", "ultimo_heartbeat": device.ultimo_heartbeat.isoformat()}

@app.get("/listar_dispositivos/{parent_id}")
async def listar_dispositivos(parent_id: str, authorized: bool = Security(verify_token)):
    db = next(get_db())
    lista = db.query(DeviceDB).filter(DeviceDB.parent_id == parent_id).all()
    # serializar manualmente
    out = []
    for d in lista:
        out.append({
            "id": d.id,
            "nome": d.nome,
            "sistema": d.sistema,
            "parent_id": d.parent_id,
            "pareado_em": d.pareado_em.isoformat(),
            "ultimo_heartbeat": d.ultimo_heartbeat.isoformat() if d.ultimo_heartbeat else None,
            "ativo": d.ativo
        })
    return {"dispositivos": out}

@app.get("/")
async def root():
    return {"message": "API Pai de Ferro ativa!"}

# Handler para environments que esperam AWS Lambda (Mangum)
handler = Mangum(app)
