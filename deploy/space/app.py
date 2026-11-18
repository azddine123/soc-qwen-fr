"""SOC-Qwen-FR — démo Hugging Face Space (CPU gratuit).

Charge la version GGUF (q4_k_m) du modèle fine-tuné avec llama.cpp et expose :
  - une interface Gradio (coller un événement Windows → triage JSON) ;
  - l'API Gradio `/triage`, appelée par l'application Render.
"""
import json
import os

import gradio as gr
from huggingface_hub import HfApi, hf_hub_download
from llama_cpp import Llama

MODEL_REPO = os.getenv("MODEL_REPO", "AZAS123/soc-qwen3-4b-fr-GGUF")
HF_TOKEN = os.getenv("HF_TOKEN")  # nécessaire seulement si le dépôt du modèle est privé

SYSTEM_PROMPT = (
    "Tu es un analyste SOC expert en détection sur Windows. "
    "Analyse l'événement fourni et réponds UNIQUEMENT avec un objet JSON contenant : "
    "verdict (\"suspect\" ou \"bénin\"), technique_id, technique, tactique, severite, "
    "explication (en français) et recommandations (liste, en français)."
)


def find_gguf():
    files = HfApi(token=HF_TOKEN).list_repo_files(MODEL_REPO)
    ggufs = [f for f in files if f.lower().endswith(".gguf")]
    if not ggufs:
        raise RuntimeError(f"Aucun fichier .gguf dans {MODEL_REPO}")
    q4 = [f for f in ggufs if "q4_k_m" in f.lower()]
    return (q4 or ggufs)[0]


MODEL_FILE = os.getenv("MODEL_FILE") or find_gguf()
path = hf_hub_download(MODEL_REPO, MODEL_FILE, token=HF_TOKEN)
llm = Llama(model_path=path, n_ctx=2048, n_threads=os.cpu_count() or 2, verbose=False)

EXAMPLES = json.load(open(os.path.join(os.path.dirname(__file__), "examples.json"), encoding="utf-8"))


def triage(event_text: str) -> str:
    """Analyse un événement Windows (JSON ou texte brut) et renvoie le triage JSON."""
    event_text = (event_text or "").strip()
    if not event_text:
        return json.dumps({"erreur": "Événement vide"}, ensure_ascii=False)
    try:  # normalise le JSON comme à l'entraînement
        event_text = json.dumps(json.loads(event_text), ensure_ascii=False)
    except json.JSONDecodeError:
        pass
    user = "Analyse cet événement Windows :\n```json\n" + event_text[:6000] + "\n```"
    out = llm.create_chat_completion(
        messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}],
        temperature=0.0, max_tokens=512)
    txt = out["choices"][0]["message"]["content"].strip()
    try:
        start, end = txt.index("{"), txt.rindex("}") + 1
        return json.dumps(json.loads(txt[start:end]), ensure_ascii=False, indent=2)
    except ValueError:
        return txt


with gr.Blocks(title="SOC-Qwen-FR") as demo:
    gr.Markdown(
        "# SOC-Qwen-FR — triage d'alertes Windows\n"
        "Qwen3-4B fine-tuné (QLoRA) sur des règles SigmaHQ et MITRE ATT&CK. Collez un événement "
        "Windows (Sysmon, Security, PowerShell…) au format JSON. *Démo sur CPU gratuit : comptez "
        "30 à 90 secondes par analyse.*")
    with gr.Row():
        inp = gr.Code(label="Événement Windows (JSON)", language="json", lines=14)
        out = gr.Code(label="Triage", language="json", lines=14)
    btn = gr.Button("Analyser", variant="primary")
    btn.click(triage, inputs=inp, outputs=out, api_name="triage")
    gr.Examples([[json.dumps(e["event"], ensure_ascii=False, indent=1)] for e in EXAMPLES], inputs=inp,
                example_labels=[e["label"] for e in EXAMPLES])
    gr.Markdown("Code : https://github.com/azddine123/soc-qwen-fr — usage défensif uniquement.")

demo.queue(default_concurrency_limit=1).launch()
