"""Génère notebooks/train_kaggle.ipynb (cellules définies ci-dessous)."""
import json
import os

CELLS = []


def md(s):
    CELLS.append({"cell_type": "markdown", "metadata": {}, "source": s.strip("\n")})


def code(s):
    CELLS.append({"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [], "source": s.strip("\n")})


md(r"""
# SOC-Qwen-FR — Fine-tuning de Qwen3-4B pour le triage d'alertes SOC (français)

Ce notebook :
1. charge le dataset (événements Windows → triage JSON en français, construit à partir de SigmaHQ + MITRE ATT&CK) ;
2. évalue **Qwen3-4B-Instruct de base** sur le jeu de test ;
3. fine-tune le modèle en **QLoRA** (Unsloth) ;
4. évalue le **modèle fine-tuné** sur le même jeu de test ;
5. publie le dataset, l'adaptateur LoRA, une version GGUF et les résultats sur Hugging Face.

**Prérequis Kaggle** : GPU T4 (ou P100) activé, Internet activé, secret `HF_TOKEN` (token Hugging Face en écriture).
""")

code(r"""
import os
os.environ["CUDA_VISIBLE_DEVICES"] = "0"   # Unsloth : un seul GPU
!pip install -q unsloth
# garder des versions compatibles avec unsloth-zoo (datasets < 4.4, huggingface_hub < 2)
!pip install -q "datasets>=3.4.1,<4.4" "huggingface_hub<2.0"
!pip list 2>/dev/null | grep -E "^(unsloth|unsloth_zoo|transformers|trl|datasets|huggingface-hub|torch) "
""")

code(r"""
# ---------------- Configuration
HF_USER      = "AZAS123"
GITHUB_REPO  = "https://github.com/azddine123/soc-qwen-fr.git"
BASE_MODEL   = "unsloth/Qwen3-4B-Instruct-2507"
LORA_REPO    = f"{HF_USER}/soc-qwen3-4b-fr-lora"
GGUF_REPO    = f"{HF_USER}/soc-qwen3-4b-fr-GGUF"
DATASET_REPO = f"{HF_USER}/soc-triage-fr"
MAX_SEQ_LEN  = 1536
N_EVAL       = 200      # nombre d'exemples de test évalués (tous les événements réels + échantillon)
EPOCHS       = 1
SEED         = 42
""")

code(r"""
from kaggle_secrets import UserSecretsClient
from huggingface_hub import login
HF_TOKEN = UserSecretsClient().get_secret("HF_TOKEN")
login(token=HF_TOKEN)
""")

code(r"""
!rm -rf soc-qwen-fr && git clone -q --depth 1 {GITHUB_REPO}
from datasets import load_dataset
ds = load_dataset("json", data_files={"train": "soc-qwen-fr/data/train.jsonl", "test": "soc-qwen-fr/data/test.jsonl"})
print(ds)
# publication du dataset sur le Hub (privé par défaut)
try:
    ds.push_to_hub(DATASET_REPO, private=True, token=HF_TOKEN)
    print("Dataset publié :", DATASET_REPO)
except Exception as e:
    print("Publication du dataset ignorée :", e)
""")

code(r"""
# ---------------- Jeu d'évaluation : tous les événements réels + échantillon synthétique/bénin
import random
rnd = random.Random(SEED)
test = list(ds["test"])
real = [e for e in test if e["source"] == "reel"]
other = [e for e in test if e["source"] != "reel"]
rnd.shuffle(other)
eval_set = (real + other)[:N_EVAL]
from collections import Counter
print(len(eval_set), Counter(e["source"] for e in eval_set))
""")

code(r"""
# ---------------- Fonctions d'évaluation
import json, re, time, torch

def extract_json(txt):
    txt = re.sub(r"<think>.*?</think>", "", txt, flags=re.S).strip()
    m = re.search(r"\{.*\}", txt, flags=re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None

def score(pred_txt, ex):
    exp = json.loads(ex["messages"][2]["content"])
    p = extract_json(pred_txt)
    r = {"json_valide": p is not None}
    valid = set(ex["techniques_valides"] or [])
    # technique : depuis le JSON si possible, sinon premier ID trouvé dans le texte
    tid = (p or {}).get("technique_id") if p else None
    if not tid:
        m = re.search(r"T\d{4}(?:\.\d{3})?", pred_txt)
        tid = m.group(0) if m else None
    verdict = ((p or {}).get("verdict") or "").lower() if p else ""
    if not verdict:
        verdict = "bénin" if re.search(r"b[ée]nin|legitimate|benign", pred_txt, re.I) and not tid else "suspect"
    r["verdict_ok"] = (verdict.startswith("b") == (exp["verdict"] == "bénin"))
    if exp["verdict"] == "bénin":
        return r
    r["technique_exacte"] = tid in valid if tid else False
    r["technique_parent"] = bool(tid) and tid.split(".")[0] in {v.split(".")[0] for v in valid}
    exp_ta = re.search(r"TA\d{4}", exp["tactique"] or "").group(0)
    tac = str((p or {}).get("tactique") or "") if p else pred_txt
    r["tactique_ok"] = exp_ta in tac
    return r

def generate_batch(model, tokenizer, batch, max_new_tokens=384):
    prompts = [tokenizer.apply_chat_template(ex["messages"][:2], tokenize=False, add_generation_prompt=True) for ex in batch]
    enc = tokenizer(prompts, return_tensors="pt", padding=True, truncation=True, max_length=MAX_SEQ_LEN).to("cuda")
    with torch.no_grad():
        out = model.generate(**enc, max_new_tokens=max_new_tokens, do_sample=False, use_cache=True,
                             pad_token_id=tokenizer.pad_token_id)
    return tokenizer.batch_decode(out[:, enc["input_ids"].shape[1]:], skip_special_tokens=True)

def evaluate(model, tokenizer, name, bs=8):
    from unsloth import FastLanguageModel
    FastLanguageModel.for_inference(model)
    tokenizer.padding_side = "left"
    rows, t0 = [], time.time()
    for i in range(0, len(eval_set), bs):
        batch = eval_set[i:i+bs]
        for ex, txt in zip(batch, generate_batch(model, tokenizer, batch)):
            rows.append({"source": ex["source"], "rule_title": ex["rule_title"], "sortie": txt, **score(txt, ex)})
        print(f"\r{name}: {len(rows)}/{len(eval_set)}", end="")
    print(f"  ({time.time()-t0:.0f}s)")
    return rows

def summarize(rows):
    import pandas as pd
    df = pd.DataFrame(rows)
    out = {}
    for grp, d in [("global", df)] + list(df.groupby("source")):
        s = {"n": len(d), "json_valide": d["json_valide"].mean(), "verdict_ok": d["verdict_ok"].mean()}
        for c in ("technique_exacte", "technique_parent", "tactique_ok"):
            if c in d and d[c].notna().any():
                s[c] = d[c].dropna().astype(float).mean()
        out[grp] = {k: (round(v, 3) if isinstance(v, float) else v) for k, v in s.items()}
    return out
""")

code(r"""
# ---------------- 1) Modèle de base
from unsloth import FastLanguageModel
model, tokenizer = FastLanguageModel.from_pretrained(BASE_MODEL, max_seq_length=MAX_SEQ_LEN, load_in_4bit=True)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token
base_rows = evaluate(model, tokenizer, "base")
base_res = summarize(base_rows)
print(json.dumps(base_res, indent=2, ensure_ascii=False))
print("\nExemple de sortie du modèle de base :\n", base_rows[0]["sortie"][:800])
""")

code(r"""
# ---------------- 2) QLoRA
model = FastLanguageModel.get_peft_model(
    model, r=16, lora_alpha=16, lora_dropout=0, bias="none",
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    use_gradient_checkpointing="unsloth", random_state=SEED)
FastLanguageModel.for_training(model)
tokenizer.padding_side = "right"

def fmt(ex):
    return {"text": tokenizer.apply_chat_template(ex["messages"], tokenize=False)}
train_ds = ds["train"].map(fmt, remove_columns=ds["train"].column_names)
print(train_ds[0]["text"][:600])
""")

code(r"""
from trl import SFTTrainer, SFTConfig
from unsloth.chat_templates import train_on_responses_only
from unsloth import is_bfloat16_supported

trainer = SFTTrainer(
    model=model, tokenizer=tokenizer, train_dataset=train_ds,
    args=SFTConfig(
        dataset_text_field="text", max_seq_length=MAX_SEQ_LEN, packing=False,
        per_device_train_batch_size=4, gradient_accumulation_steps=4,
        num_train_epochs=EPOCHS, learning_rate=2e-4, warmup_ratio=0.03,
        lr_scheduler_type="cosine", optim="adamw_8bit", weight_decay=0.01,
        fp16=not is_bfloat16_supported(), bf16=is_bfloat16_supported(),
        logging_steps=10, save_strategy="no", seed=SEED, output_dir="outputs", report_to="none"),
)
# on n'entraîne que sur la réponse de l'assistant
trainer = train_on_responses_only(trainer, instruction_part="<|im_start|>user\n", response_part="<|im_start|>assistant\n")
stats = trainer.train()
print(stats)
""")

code(r"""
# ---------------- 3) Modèle fine-tuné
ft_rows = evaluate(model, tokenizer, "fine-tuné")
ft_res = summarize(ft_rows)
print(json.dumps(ft_res, indent=2, ensure_ascii=False))
print("\nExemple de sortie du modèle fine-tuné :\n", ft_rows[0]["sortie"][:800])
""")

code(r"""
# ---------------- Comparaison
import pandas as pd
rows = []
for name, res in (("Qwen3-4B base", base_res), ("SOC-Qwen-FR (fine-tuné)", ft_res)):
    for grp, s in res.items():
        rows.append({"modèle": name, "sous-ensemble": grp, **s})
cmp = pd.DataFrame(rows)
display(cmp)
results = {"base": base_res, "fine_tune": ft_res, "train_loss": stats.training_loss,
           "n_train": len(train_ds), "n_eval": len(eval_set), "base_model": BASE_MODEL}
json.dump(results, open("results.json", "w"), indent=2, ensure_ascii=False)
pd.DataFrame(base_rows).to_json("pred_base.jsonl", orient="records", lines=True, force_ascii=False)
pd.DataFrame(ft_rows).to_json("pred_finetune.jsonl", orient="records", lines=True, force_ascii=False)
""")

code(r"""
# ---------------- 4) Publication sur Hugging Face
def pct(x): return "—" if x is None else f"{100*x:.1f} %"
def line(name, r):
    return f"| {name} | {pct(r.get('json_valide'))} | {pct(r.get('verdict_ok'))} | {pct(r.get('technique_exacte'))} | {pct(r.get('technique_parent'))} | {pct(r.get('tactique_ok'))} |"
table = "\n".join([
    "| Modèle | JSON valide | Verdict | Technique exacte | Technique (parent) | Tactique |",
    "|---|---|---|---|---|---|",
    line("Qwen3-4B-Instruct (base)", base_res["global"]), line("SOC-Qwen-FR (fine-tuné)", ft_res["global"]),
    line("Base — événements réels", base_res.get("reel", {})), line("Fine-tuné — événements réels", ft_res.get("reel", {})),
])
REPO_URL = GITHUB_REPO[:-4]
card = f'''---
base_model: {BASE_MODEL}
library_name: peft
license: apache-2.0
language: [fr]
tags: [cybersecurity, soc, mitre-attack, sigma, qlora, unsloth]
---
# SOC-Qwen-FR (Qwen3-4B, LoRA)

Assistant de **triage d'alertes SOC en français** : à partir d'un événement Windows (Sysmon, Security, PowerShell…),
le modèle renvoie un JSON avec le verdict, la technique **MITRE ATT&CK**, la tactique, la sévérité, une explication
et des recommandations.

- Modèle de base : `{BASE_MODEL}` — fine-tuning QLoRA (r=16) avec Unsloth sur {len(train_ds)} exemples.
- Données : construites à partir des règles **SigmaHQ** (licence DRL 1.1) et de **MITRE ATT&CK** — événements
  synthétiques générés depuis la logique de détection + événements réels issus de `regression_data` de SigmaHQ.
- Évaluation sur {len(eval_set)} exemples de test (règles Sigma jamais vues pendant l'entraînement).

## Résultats
{table}

## Limites
Usage défensif uniquement. Les explications sont générées à partir de gabarits ; le modèle peut se tromper de
technique sur des comportements rares et doit rester un outil d'aide à l'analyste, pas un système de décision
autonome. Code : {REPO_URL}
'''
model.push_to_hub(LORA_REPO, private=True, token=HF_TOKEN)
tokenizer.push_to_hub(LORA_REPO, private=True, token=HF_TOKEN)
from huggingface_hub import HfApi
api = HfApi(token=HF_TOKEN)
api.upload_file(path_or_fileobj=card.encode(), path_in_repo="README.md", repo_id=LORA_REPO)
for f in ("results.json", "pred_base.jsonl", "pred_finetune.jsonl"):
    api.upload_file(path_or_fileobj=f, path_in_repo=f"eval/{f}", repo_id=LORA_REPO)
print("Adaptateur publié :", LORA_REPO)
print(table)
""")

code(r"""
# ---------------- 5) Version GGUF (pour Ollama / llama.cpp) — optionnelle
try:
    model.push_to_hub_gguf(GGUF_REPO, tokenizer, quantization_method="q4_k_m", token=HF_TOKEN, private=True)
    print("GGUF publié :", GGUF_REPO)
except Exception as e:
    print("Export GGUF ignoré :", e)
""")

nb = {"cells": CELLS, "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
                                    "language_info": {"name": "python"}},
      "nbformat": 4, "nbformat_minor": 5}
os.makedirs("notebooks", exist_ok=True)
json.dump(nb, open("notebooks/train_kaggle.ipynb", "w", encoding="utf-8"), indent=1, ensure_ascii=False)
print("ok", len(CELLS), "cellules")
