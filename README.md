# SOC-Qwen-FR

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/azddine123/soc-qwen-fr/blob/main/notebooks/demo_colab.ipynb)
[![Modèle](https://img.shields.io/badge/🤗-soc--qwen3--4b--fr--lora-yellow)](https://huggingface.co/AZAS123/soc-qwen3-4b-fr-lora)
[![GGUF](https://img.shields.io/badge/🤗-GGUF%20Q4__K__M-yellow)](https://huggingface.co/AZAS123/soc-qwen3-4b-fr-GGUF)
[![Dataset](https://img.shields.io/badge/🤗-soc--triage--fr-yellow)](https://huggingface.co/datasets/AZAS123/soc-triage-fr)

**Fine-tuning de Qwen3-4B pour le triage d'alertes SOC en français.**

À partir d'un événement Windows brut (Sysmon, Security, PowerShell, Defender…), le modèle renvoie un triage structuré :

```json
{
  "verdict": "suspect",
  "technique_id": "T1003.001",
  "technique": "OS Credential Dumping : LSASS Memory",
  "tactique": "Accès aux identifiants (TA0006)",
  "severite": "élevée",
  "explication": "Le champ CommandLine contient « cmd.exe /c …\\mimikatz.exe \"sekurlsa::logonpasswords full\" » …",
  "recommandations": ["Réinitialiser les mots de passe des comptes potentiellement exposés", "…"]
}
```

## Essayer

- **Console web** : https://azddine123.github.io/soc-qwen-fr/ — tableau de bord SOC (verdict, technique ATT&CK,
  chaîne d'attaque, historique, export CSV/JSON). Deux moteurs : le modèle exécuté **dans le navigateur**
  (WebAssembly/WebGPU, aucune donnée envoyée) ou la démo **Colab** connectée par son lien `gradio.live`.

- **Dans le navigateur (GPU gratuit)** : bouton *Open in Colab* ci-dessus → `Exécution → Tout exécuter`
  (GPU T4). Une interface Gradio s'ouvre avec un lien public partageable.
- **En local avec Ollama** :
  ```bash
  ollama run hf.co/AZAS123/soc-qwen3-4b-fr-GGUF
  ```

## Pourquoi ce projet

Les LLM généralistes connaissent MITRE ATT&CK, mais ils répondent souvent en anglais, dans un format libre et
difficile à intégrer à un SIEM, et ils se trompent fréquemment de sous-technique. L'objectif est un petit modèle
(4B, exécutable sur un GPU grand public ou en local via Ollama) qui :

- produit **toujours un JSON exploitable** par un outil (SOAR, ticketing, SOC Copilot) ;
- identifie la **technique ATT&CK** (v19, y compris les nouvelles tactiques *Stealth* et *Defense Impairment*) ;
- explique et recommande **en français**.

## Données

`scripts/build_dataset.py` construit le dataset à partir de sources publiques :

| Source | Utilisation |
|---|---|
| [SigmaHQ](https://github.com/SigmaHQ/sigma) — règles Windows (DRL 1.1) | Label (technique, tactique, sévérité, faux positifs) + génération d'événements synthétiques à partir de la logique de détection |
| SigmaHQ `regression_data` | **Événements réels** capturés en laboratoire (Atomic Red Team, etc.) |
| [MITRE ATT&CK Enterprise](https://github.com/mitre/cti) | Noms des techniques et tactiques |

| Split | Exemples | Dont réels | Dont bénins |
|---|---|---|---|
| train | 6 002 | 289 | 444 |
| test | 413 | 123 | 30 |

Le split se fait **par règle Sigma** : aucune règle du test n'est vue pendant l'entraînement (124 techniques en test,
dont 13 jamais vues en train).

## Entraînement

`notebooks/train_kaggle.ipynb` (GPU T4 gratuit de Kaggle) :

- modèle de base : `unsloth/Qwen3-4B-Instruct-2507` en 4 bits ;
- QLoRA r=16 sur toutes les projections, 1 époque, lr 2e-4, perte calculée uniquement sur la réponse ;
- évaluation **avant / après** sur le même jeu de test (tous les événements réels + échantillon) ;
- publication sur Hugging Face : dataset, adaptateur LoRA, GGUF `q4_k_m` et prédictions.

## Métriques

- **JSON valide** : la réponse est un JSON exploitable ;
- **Verdict** : suspect / bénin correct ;
- **Technique exacte** : l'ID prédit fait partie des techniques taguées par la règle ;
- **Technique (parent)** : même technique parente (ex. T1003 pour T1003.001) ;
- **Tactique** : identifiant TA correct.

### Résultats (run Kaggle T4, 1 époque, 6 002 exemples, ~1 h 50)

Évaluation sur 200 exemples de test issus de règles Sigma **jamais vues** à l'entraînement
(123 événements réels, 70 synthétiques, 7 bénins). Détail : `results/results.json`.

**Événements réels (n = 123)**

| Modèle | JSON valide | Verdict | Technique exacte | Technique (parent) | Tactique (ID TA) |
|---|---|---|---|---|---|
| Qwen3-4B-Instruct (base) | 33,3 % | 86,2 % | 17,9 % | 21,1 % | 0 % |
| **SOC-Qwen-FR (fine-tuné)** | **94,3 %** | **100 %** | **24,4 %** | **33,3 %** | **35,8 %** |

**Ensemble du test (n = 200)**

| Modèle | JSON valide | Verdict | Technique exacte | Technique (parent) | Tactique (ID TA) |
|---|---|---|---|---|---|
| Qwen3-4B-Instruct (base) | 34,5 % | 83,0 % | 14,5 % | 17,1 % | 0 % |
| **SOC-Qwen-FR (fine-tuné)** | **96,5 %** | **100 %** | **20,2 %** | **28,0 %** | **32,1 %** |

Lecture :
- le gain le plus net est sur le **format** (JSON exploitable 33 % → 94 %) et le **verdict** (100 %) : le modèle
  devient intégrable dans un pipeline SOC ;
- l'identification de la technique progresse (+6,5 points exacte, +12 points parente sur les logs réels) mais reste
  difficile : 270 techniques, règles de test inédites, et une seule époque sur un petit modèle ;
- la tactique « 0 % » du modèle de base vient surtout de la métrique, qui exige l'identifiant TA (le modèle de base
  donne le nom de la tactique sans identifiant).

Pistes d'amélioration : ajouter une étape de **RAG** sur la base ATT&CK (récupérer les techniques candidates avant la
génération), 2 à 3 époques, davantage d'événements réels, et un modèle plus grand (Qwen3.5-9B).

## Reproduire

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma.git
curl -L -o enterprise-attack.json https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
pip install pyyaml
python scripts/build_dataset.py sigma enterprise-attack.json data
python scripts/make_notebook.py   # régénère le notebook
```

Puis importer `notebooks/train_kaggle.ipynb` dans Kaggle (GPU + Internet activés, secret `HF_TOKEN`).

## Déploiement (100 % gratuit)

| Brique | Hébergement | Dossier |
|---|---|---|
| Entraînement + évaluation | Kaggle (GPU T4) | `notebooks/train_kaggle.ipynb` |
| Publication (LoRA, GGUF, dataset, Space) | Kaggle | `notebooks/publish_kaggle.ipynb` |
| Démo interactive (Gradio, GPU T4) | Google Colab | `notebooks/demo_colab.ipynb` |
| Modèle GGUF `q4_k_m` + API Gradio `/triage` | Hugging Face Space (nécessite HF PRO) | `deploy/space/` |
| Interface web + API REST `POST /api/triage` | Render (appelle le Space) | `deploy/render/`, `render.yaml` |

```bash
curl -X POST https://<service>.onrender.com/api/triage \
  -H "Content-Type: application/json" \
  -d '{"event": {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": "C:\\Windows\\System32\\vssadmin.exe", "CommandLine": "vssadmin.exe delete shadows /all /quiet"}}'
```

## Limites

- Les événements synthétiques sont générés à partir des règles : ils sont plus « propres » que des logs réels.
  Les scores sur le sous-ensemble **réel** sont les plus représentatifs.
- Les exemples bénins proviennent d'un petit nombre de gabarits : le score « verdict » sur ces exemples est optimiste.
- Les explications et recommandations suivent des gabarits par tactique ; elles ne remplacent pas l'analyse humaine.
- Usage **défensif** uniquement.

## Auteur

Azddine EL HAMDAOUI — élève ingénieur IA & Cybersécurité, ENSA Béni Mellal.
