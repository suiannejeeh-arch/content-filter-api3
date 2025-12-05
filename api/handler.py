from vercel_asgi import VercelAsgi
from api.index import app  # importa o app FastAPI definido no index.py

# Cria o handler que a Vercel usa para executar o FastAPI
handler = VercelAsgi(app)
