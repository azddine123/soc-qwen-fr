"""Génère notebooks/publish_kaggle.ipynb : publication après l'entraînement."""
import json, os
CELLS = []
def md(s): CELLS.append({"cell_type": "markdown", "metadata": {}, "source": s.strip("\n")})
def code(s): CELLS.append({"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [], "source": s.strip("\n")})

md(r"""
# SOC-Qwen-FR — publication (Hugging Face)

À lancer **après** le notebook d'entraînement. Prérequis :
- en entrée (*Add Input*), la sortie du notebook « SOC-Qwen-FR - finetuning Qwen3-4B QLoRA » ;
- GPU T4 et Internet activés ;
- secret `HF_TOKEN` (token Hugging Face en écriture).

Ce notebook publie : l'adaptateur LoRA, la version GGUF `q4_k_m`, le dataset et le **Space** de démonstration.
""")
code(r"""
import os
os.environ["CUDA_VISIBLE_DEVICES"] = "0"
!pip install -q unsloth
!pip install -q "datasets>=4.7,<5.0" "huggingface_hub<2.0"
""")
code(r"""
HF_USER     = "AZAS123"
PUBLIC      = True      # True : modèle, dataset et Space publics (portfolio) ; False : privés
GITHUB_REPO = "https://github.com/azddine123/soc-qwen-fr.git"
LORA_REPO   = f"{HF_USER}/soc-qwen3-4b-fr-lora"
GGUF_REPO   = f"{HF_USER}/soc-qwen3-4b-fr-GGUF"
DATA_REPO   = f"{HF_USER}/soc-triage-fr"
SPACE_REPO  = f"{HF_USER}/soc-qwen-fr"

from kaggle_secrets import UserSecretsClient
from huggingface_hub import HfApi, login
HF_TOKEN = UserSecretsClient().get_secret("HF_TOKEN")
login(token=HF_TOKEN)
api = HfApi(token=HF_TOKEN)
print(api.whoami()["name"])
""")
code(r"""
import glob
cands = glob.glob("/kaggle/input/**/soc-qwen3-4b-fr-lora/adapter_config.json", recursive=True)
assert cands, "Ajoutez la sortie du notebook d'entraînement en entrée (Add Input)"
ADAPTER = os.path.dirname(cands[0])
print(ADAPTER, os.listdir(ADAPTER))
!rm -rf soc-qwen-fr && git clone -q --depth 1 {GITHUB_REPO}
""")
code(r"""
# 1) adaptateur LoRA (+ fiche modèle et résultats d'évaluation)
api.create_repo(LORA_REPO, private=not PUBLIC, exist_ok=True)
api.upload_folder(folder_path=ADAPTER, repo_id=LORA_REPO)
api.update_repo_settings(LORA_REPO, private=not PUBLIC)
print("LoRA :", f"https://huggingface.co/{LORA_REPO}")

# 2) dataset
from datasets import load_dataset
ds = load_dataset("json", data_files={"train": "soc-qwen-fr/data/train.jsonl", "test": "soc-qwen-fr/data/test.jsonl"})
ds.push_to_hub(DATA_REPO, private=not PUBLIC, token=HF_TOKEN)
print("Dataset :", f"https://huggingface.co/datasets/{DATA_REPO}")
""")
code(r"""
# 3) GGUF q4_k_m (fusion de l'adaptateur + quantification llama.cpp)
from unsloth import FastLanguageModel
model, tokenizer = FastLanguageModel.from_pretrained(ADAPTER, max_seq_length=2048, load_in_4bit=True)
model.push_to_hub_gguf(GGUF_REPO, tokenizer, quantization_method="q4_k_m", token=HF_TOKEN, private=not PUBLIC)
api.update_repo_settings(GGUF_REPO, private=not PUBLIC)
print([f for f in api.list_repo_files(GGUF_REPO) if f.endswith(".gguf")])
""")
code(r"""
# 4) Space de démonstration (Gradio + llama.cpp sur CPU gratuit)
api.create_repo(SPACE_REPO, repo_type="space", space_sdk="gradio", private=not PUBLIC, exist_ok=True)
api.upload_folder(folder_path="soc-qwen-fr/deploy/space", repo_id=SPACE_REPO, repo_type="space")
api.add_space_variable(SPACE_REPO, "MODEL_REPO", GGUF_REPO)
if not PUBLIC:
    api.add_space_secret(SPACE_REPO, "HF_TOKEN", HF_TOKEN)
print("Space :", f"https://huggingface.co/spaces/{SPACE_REPO}")
""")
nb = {"cells": CELLS, "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python"}}, "nbformat": 4, "nbformat_minor": 5}
json.dump(nb, open("notebooks/publish_kaggle.ipynb", "w", encoding="utf-8"), indent=1, ensure_ascii=False)
print("ok", len(CELLS))
