---
title: SOC-Qwen-FR
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: gradio
app_file: app.py
pinned: false
license: apache-2.0
short_description: Triage d'alertes SOC Windows en français (Qwen3-4B fine-tuné)
---

# SOC-Qwen-FR

Démo du modèle **SOC-Qwen-FR** : un événement Windows en entrée, un triage JSON en sortie
(verdict, technique MITRE ATT&CK, tactique, sévérité, explication et recommandations en français).

- Modèle : Qwen3-4B-Instruct fine-tuné en QLoRA, version GGUF `q4_k_m` exécutée avec llama.cpp sur CPU.
- Code, données et notebook d'entraînement : https://github.com/azddine123/soc-qwen-fr

Variables d'environnement : `MODEL_REPO` (dépôt GGUF), `MODEL_FILE` (optionnel), secret `HF_TOKEN`
si le dépôt du modèle est privé.
