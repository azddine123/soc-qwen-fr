"""SOC-Qwen-FR — application web (Render).

Interface + API REST légère. L'inférence est déléguée au Hugging Face Space qui héberge
le modèle (Render gratuit n'a ni GPU ni assez de RAM pour un modèle de 4B).

  GET  /              interface web
  POST /api/triage    {"event": {...} | "texte"}  ->  triage JSON
  GET  /api/examples  exemples d'événements
  GET  /health        état du service
"""
import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

SPACE_ID = os.getenv("SPACE_ID", "AZAS123/soc-qwen-fr")
HF_TOKEN = os.getenv("HF_TOKEN") or None  # seulement si le Space est privé
HERE = Path(__file__).parent
EXAMPLES = json.loads((HERE / "examples.json").read_text(encoding="utf-8"))

app = FastAPI(title="SOC-Qwen-FR", version="1.0",
              description="Triage d'alertes Windows en français (MITRE ATT&CK) par un Qwen3-4B fine-tuné.")
_client = None


def client():
    global _client
    if _client is None:
        from gradio_client import Client
        _client = Client(SPACE_ID, hf_token=HF_TOKEN, verbose=False)
    return _client


class TriageRequest(BaseModel):
    event: dict | str


@app.get("/health")
def health():
    return {"status": "ok", "space": SPACE_ID}


@app.get("/api/examples")
def examples():
    return EXAMPLES


@app.post("/api/triage")
def triage(req: TriageRequest):
    text = req.event if isinstance(req.event, str) else json.dumps(req.event, ensure_ascii=False)
    if not text.strip():
        raise HTTPException(400, "Événement vide")
    if len(text) > 8000:
        raise HTTPException(413, "Événement trop long (8000 caractères max)")
    try:
        raw = client().predict(text, api_name="/triage")
    except Exception as e:  # Space endormi, en construction, etc.
        global _client
        _client = None
        raise HTTPException(503, f"Le modèle n'est pas disponible pour le moment ({type(e).__name__}). "
                                 "Le Space Hugging Face se réveille peut-être : réessayez dans une minute.")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {"brut": raw}


@app.get("/", response_class=HTMLResponse)
def index():
    return (HERE / "index.html").read_text(encoding="utf-8")
