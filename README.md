# SOC-Qwen-FR

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

Les résultats sont publiés dans la fiche du modèle sur Hugging Face et dans `results/`.

## Reproduire

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma.git
curl -L -o enterprise-attack.json https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
pip install pyyaml
python scripts/build_dataset.py sigma enterprise-attack.json data
python scripts/make_notebook.py   # régénère le notebook
```

Puis importer `notebooks/train_kaggle.ipynb` dans Kaggle (GPU + Internet activés, secret `HF_TOKEN`).

## Limites

- Les événements synthétiques sont générés à partir des règles : ils sont plus « propres » que des logs réels.
  Les scores sur le sous-ensemble **réel** sont les plus représentatifs.
- Les exemples bénins proviennent d'un petit nombre de gabarits : le score « verdict » sur ces exemples est optimiste.
- Les explications et recommandations suivent des gabarits par tactique ; elles ne remplacent pas l'analyse humaine.
- Usage **défensif** uniquement.

## Auteur

Azddine EL HAMDAOUI — élève ingénieur IA & Cybersécurité, ENSA Béni Mellal.
