"""Génère notebooks/split_for_browser.ipynb : découpe le GGUF en morceaux de 512 Mo pour wllama."""
import json
CELLS = []
def md(s): CELLS.append({"cell_type": "markdown", "metadata": {}, "source": s.strip("\n")})
def code(s): CELLS.append({"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [], "source": s.strip("\n")})
md(r"""
# SOC-Qwen-FR — modèle découpé pour le navigateur

Un navigateur ne peut pas charger un fichier de plus de 2 Go. Ce notebook découpe
`Qwen3-4B-Instruct-2507.Q4_K_M.gguf` en morceaux de 512 Mo avec `llama-gguf-split`
et les publie dans `split/` du dépôt GGUF. Prérequis : Internet activé, secret `HF_TOKEN` (écriture). Pas besoin de GPU.
""")
code(r"""
import os, glob, json, zipfile, tarfile, urllib.request, subprocess, stat
from kaggle_secrets import UserSecretsClient
from huggingface_hub import HfApi, hf_hub_download, login
HF_TOKEN = UserSecretsClient().get_secret("HF_TOKEN")
login(token=HF_TOKEN)
api = HfApi(token=HF_TOKEN)
REPO = "AZAS123/soc-qwen3-4b-fr-GGUF"
SRC = "Qwen3-4B-Instruct-2507.Q4_K_M.gguf"
path = hf_hub_download(REPO, SRC, local_dir="model")
print(path, os.path.getsize(path) / 1e9, "Go")
""")
code(r"""
# binaire llama-gguf-split depuis la dernière release de llama.cpp
rel = json.load(urllib.request.urlopen("https://api.github.com/repos/ggml-org/llama.cpp/releases/latest"))
asset = next(a for a in rel["assets"] if "ubuntu-x64" in a["name"] and not any(k in a["name"] for k in ("vulkan", "cuda", "rocm", "sycl", "kompute")))
print(rel["tag_name"], asset["name"])
urllib.request.urlretrieve(asset["browser_download_url"], asset["name"])
os.makedirs("llama", exist_ok=True)
if asset["name"].endswith(".zip"):
    zipfile.ZipFile(asset["name"]).extractall("llama")
else:
    tarfile.open(asset["name"]).extractall("llama")
binary = next(p for p in glob.glob("llama/**/llama-gguf-split", recursive=True))
os.chmod(binary, os.stat(binary).st_mode | stat.S_IEXEC)
print(binary)
""")
code(r"""
os.makedirs("split", exist_ok=True)
env = dict(os.environ, LD_LIBRARY_PATH=os.path.dirname(binary) + ":" + os.environ.get("LD_LIBRARY_PATH", ""))
subprocess.run([binary, "--split-max-size", "512M", path, "split/soc-qwen3-4b-fr-Q4_K_M"], check=True, env=env)
files = sorted(glob.glob("split/*.gguf"))
for f in files: print(f, round(os.path.getsize(f) / 1e6), "Mo")
assert files and all(os.path.getsize(f) < 2e9 for f in files)
""")
code(r"""
api.upload_folder(folder_path="split", path_in_repo="split", repo_id=REPO,
                  commit_message="Modèle découpé (512 Mo) pour exécution dans le navigateur (wllama)")
print([f for f in api.list_repo_files(REPO) if f.startswith("split/")])
""")
nb = {"cells": CELLS, "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python"}}, "nbformat": 4, "nbformat_minor": 5}
json.dump(nb, open("notebooks/split_for_browser.ipynb", "w", encoding="utf-8"), indent=1, ensure_ascii=False)
print("ok")
