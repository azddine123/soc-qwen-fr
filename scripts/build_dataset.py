"""Construit le dataset SOC-Qwen-FR.

Sources (publiques) :
  - SigmaHQ (règles Windows + logs réels de regression_data) — licence DRL 1.1
  - MITRE ATT&CK Enterprise (STIX) — conditions d'utilisation MITRE

Tâche : à partir d'un événement Windows (Sysmon / Security / PowerShell...),
le modèle doit produire un triage SOC en JSON (verdict, technique ATT&CK,
tactique, sévérité, explication, recommandations) en français.

Usage : python build_dataset.py <dossier_sigma> <enterprise-attack.json> <dossier_sortie>
"""
import glob
import json
import os
import random
import re
import sys
from collections import Counter, defaultdict

import yaml

SEED = 42
rng = random.Random(SEED)

SIGMA_DIR, ATTACK_JSON, OUT_DIR = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(OUT_DIR, exist_ok=True)

SYSTEM_PROMPT = (
    "Tu es un analyste SOC expert en détection sur Windows. "
    "Analyse l'événement fourni et réponds UNIQUEMENT avec un objet JSON contenant : "
    "verdict (\"suspect\" ou \"bénin\"), technique_id, technique, tactique, severite, "
    "explication (en français) et recommandations (liste, en français)."
)

# ---------------------------------------------------------------- ATT&CK
TACTIC_FR = {
    "reconnaissance": ("Reconnaissance", "TA0043"),
    "resource-development": ("Développement de ressources", "TA0042"),
    "initial-access": ("Accès initial", "TA0001"),
    "execution": ("Exécution", "TA0002"),
    "persistence": ("Persistance", "TA0003"),
    "privilege-escalation": ("Élévation de privilèges", "TA0004"),
    "stealth": ("Furtivité", "TA0005"),  # ex-« Defense Evasion » (ATT&CK v19)
    "defense-impairment": ("Affaiblissement des défenses", "TA0112"),
    "credential-access": ("Accès aux identifiants", "TA0006"),
    "discovery": ("Découverte", "TA0007"),
    "lateral-movement": ("Mouvement latéral", "TA0008"),
    "collection": ("Collecte", "TA0009"),
    "command-and-control": ("Commande et contrôle", "TA0011"),
    "exfiltration": ("Exfiltration", "TA0010"),
    "impact": ("Impact", "TA0040"),
}

RECO_FR = {
    "reconnaissance": ["Identifier la source des requêtes de reconnaissance", "Vérifier l'exposition des services concernés"],
    "resource-development": ["Rechercher les indicateurs associés dans la threat intelligence", "Bloquer les domaines ou outils identifiés"],
    "initial-access": ["Isoler le poste si la compromission est confirmée", "Analyser le vecteur d'entrée (pièce jointe, lien, service exposé)", "Réinitialiser les identifiants de l'utilisateur concerné"],
    "execution": ["Récupérer la ligne de commande complète et l'arbre des processus", "Vérifier la légitimité du binaire (signature, hash, réputation)", "Isoler le poste si l'exécution est malveillante"],
    "persistence": ["Supprimer le mécanisme de persistance identifié", "Rechercher d'autres mécanismes de persistance sur le poste", "Vérifier l'historique des modifications du compte ou de la clé concernée"],
    "privilege-escalation": ["Vérifier les privilèges obtenus par le processus", "Contrôler les comptes à privilèges et les groupes sensibles", "Appliquer les correctifs de sécurité manquants"],
    "stealth": ["Analyser le binaire ou le script masqué (signature, hash, réputation)", "Investiguer l'activité du processus avant et après l'événement", "Rechercher le même artefact sur les autres postes"],
    "defense-impairment": ["Vérifier l'état des outils de sécurité (EDR, antivirus, journalisation)", "Rétablir les configurations de sécurité modifiées", "Identifier le compte à l'origine de la modification"],
    "credential-access": ["Réinitialiser les mots de passe des comptes potentiellement exposés", "Vérifier les accès à LSASS et aux bases d'identifiants", "Rechercher des connexions anormales avec ces comptes"],
    "discovery": ["Corréler avec d'autres commandes de découverte sur la même période", "Vérifier si l'utilisateur a un besoin légitime de ces commandes"],
    "lateral-movement": ["Identifier les machines source et destination", "Vérifier les connexions administratives à distance", "Isoler les postes compromis pour limiter la propagation"],
    "collection": ["Identifier les données collectées et leur sensibilité", "Surveiller les tentatives d'exfiltration associées"],
    "command-and-control": ["Bloquer la destination réseau (IP / domaine) au niveau du proxy et du pare-feu", "Rechercher d'autres postes communiquant avec cette destination", "Isoler le poste concerné"],
    "exfiltration": ["Bloquer le canal d'exfiltration identifié", "Évaluer le volume et la nature des données sorties", "Déclencher la procédure de gestion d'incident"],
    "impact": ["Isoler immédiatement le poste concerné", "Vérifier l'intégrité des sauvegardes", "Déclencher la procédure de gestion d'incident"],
}

SEVERITY_FR = {"informational": "informative", "low": "faible", "medium": "moyenne", "high": "élevée", "critical": "critique"}

attack = json.load(open(ATTACK_JSON))
TECH = {}
for o in attack["objects"]:
    if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
        continue
    ext = [r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"]
    if not ext:
        continue
    tid = ext[0]["external_id"]
    tactics = [p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
    TECH[tid] = {"name": o["name"], "tactics": tactics}
# nom complet pour les sous-techniques : "Parent : Sous-technique"
for tid, t in TECH.items():
    if "." in tid and tid.split(".")[0] in TECH:
        t["full_name"] = f"{TECH[tid.split('.')[0]]['name']} : {t['name']}"
    else:
        t["full_name"] = t["name"]
print(f"ATT&CK : {len(TECH)} techniques")

# ---------------------------------------------------------------- Événements synthétiques
USERS = ["CORP\\a.benali", "CORP\\s.elidrissi", "CORP\\m.ouazzani", "CORP\\k.amrani", "CORP\\j.dupont",
         "CORP\\admin.it", "NT AUTHORITY\\SYSTEM", "CORP\\y.lahlou", "CORP\\h.berrada", "CORP\\svc_backup"]
HOSTS = ["WS-%03d.corp.local" % i for i in range(1, 60)] + ["SRV-FILE01.corp.local", "SRV-DC01.corp.local", "SRV-APP02.corp.local"]
DIRS = ["C:\\Windows\\System32", "C:\\Users\\Public", "C:\\Users\\a.benali\\AppData\\Local\\Temp",
        "C:\\Users\\k.amrani\\Downloads", "C:\\ProgramData", "C:\\Windows\\Temp", "C:\\Users\\j.dupont\\AppData\\Roaming"]
TOKENS = ["update", "svc", "a1b2", "data", "x64", "tmp01", "report", "client", "9f3e", "setup"]
PARENTS = ["C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
           "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "C:\\Windows\\System32\\services.exe", "C:\\Windows\\System32\\wscript.exe"]

CATEGORY_META = {
    "process_creation": ("Microsoft-Windows-Sysmon/Operational", 1),
    "file_event": ("Microsoft-Windows-Sysmon/Operational", 11),
    "file_delete": ("Microsoft-Windows-Sysmon/Operational", 23),
    "file_access": ("Microsoft-Windows-Kernel-File/Analytic", 12),
    "registry_set": ("Microsoft-Windows-Sysmon/Operational", 13),
    "registry_event": ("Microsoft-Windows-Sysmon/Operational", 12),
    "registry_add": ("Microsoft-Windows-Sysmon/Operational", 12),
    "registry_delete": ("Microsoft-Windows-Sysmon/Operational", 12),
    "network_connection": ("Microsoft-Windows-Sysmon/Operational", 3),
    "image_load": ("Microsoft-Windows-Sysmon/Operational", 7),
    "driver_load": ("Microsoft-Windows-Sysmon/Operational", 6),
    "dns_query": ("Microsoft-Windows-Sysmon/Operational", 22),
    "create_remote_thread": ("Microsoft-Windows-Sysmon/Operational", 8),
    "process_access": ("Microsoft-Windows-Sysmon/Operational", 10),
    "pipe_created": ("Microsoft-Windows-Sysmon/Operational", 17),
    "create_stream_hash": ("Microsoft-Windows-Sysmon/Operational", 15),
    "raw_access_thread": ("Microsoft-Windows-Sysmon/Operational", 9),
    "process_tampering": ("Microsoft-Windows-Sysmon/Operational", 25),
    "ps_script": ("Microsoft-Windows-PowerShell/Operational", 4104),
    "ps_module": ("Microsoft-Windows-PowerShell/Operational", 4103),
    "ps_classic_start": ("Windows PowerShell", 400),
}
SERVICE_CHANNEL = {
    "security": "Security", "system": "System", "application": "Application",
    "windefend": "Microsoft-Windows-Windows Defender/Operational",
    "sysmon": "Microsoft-Windows-Sysmon/Operational",
    "powershell": "Microsoft-Windows-PowerShell/Operational",
    "taskscheduler": "Microsoft-Windows-TaskScheduler/Operational",
    "bits-client": "Microsoft-Windows-Bits-Client/Operational",
    "codeintegrity-operational": "Microsoft-Windows-CodeIntegrity/Operational",
    "firewall-as": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "dns-client": "Microsoft-Windows-DNS Client Events/Operational",
    "appxdeployment-server": "Microsoft-Windows-AppXDeploymentServer/Operational",
    "msexchange-management": "MSExchange Management",
}


class Unsupported(Exception):
    pass


def fill_wildcards(s):
    s = re.sub(r"(?<!\\)\*", lambda m: rng.choice(TOKENS), s)
    s = re.sub(r"(?<!\\)\?", lambda m: rng.choice("abcdefxyz0123"), s)
    return s


def looks_path(v):
    return "\\" in v or re.search(r"\.(exe|dll|ps1|bat|vbs|js|hta|sys|tmp|lnk|zip|iso)$", v, re.I)


def realize(field, mods, value):
    """Construit une valeur concrète satisfaisant (approximativement) les modificateurs Sigma."""
    if value is None:
        return None
    if isinstance(value, (int, float, bool)):
        return value
    v = str(value)
    if any(m in mods for m in ("re", "base64", "base64offset", "expand", "fieldref", "gt", "gte", "lt", "lte", "exists", "utf16le", "utf16be", "wide", "utf16")):
        raise Unsupported(mods)
    if "cidr" in mods:
        net = v.split("/")[0].split(".")
        while len(net) < 4:
            net.append("0")
        net[3] = str(rng.randint(2, 250)) if net[3] == "0" else net[3]
        return ".".join(net)
    if "windash" in mods:
        v = v.replace("-", rng.choice(["-", "/"]), 1)
    v = fill_wildcards(v)
    if "contains" in mods:
        if field.lower() in ("commandline", "parentcommandline"):
            return f"{rng.choice(['cmd.exe /c', 'powershell.exe -nop', '\"C:\\\\Windows\\\\System32\\\\rundll32.exe\"', 'wmic.exe'])} {v} {rng.choice(['', '/q', '-f', 'C:\\\\ProgramData\\\\' + rng.choice(TOKENS)])}".strip()
        if looks_path(v):
            return f"{rng.choice(DIRS)}\\{v.strip(chr(92))}" if not v.startswith("C:") else v
        return f"{rng.choice(TOKENS)} {v} {rng.choice(TOKENS)}"
    if "endswith" in mods:
        if v.startswith("\\"):
            return rng.choice(DIRS) + v
        if field.lower() in ("targetobject",):
            return "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\" + v
        if looks_path(v):
            return f"{rng.choice(DIRS)}\\{rng.choice(TOKENS)}{v}"
        return f"{rng.choice(TOKENS)} {v}"
    if "startswith" in mods:
        if looks_path(v) or v.endswith("\\"):
            return v + ("" if v.endswith("\\") else "\\") + rng.choice(TOKENS) + ".exe"
        return v + " " + rng.choice(TOKENS)
    return v


def parse_key(k):
    parts = k.split("|")
    return parts[0], parts[1:]


def realize_selection(sel):
    """Retourne un dict de champs concrets pour une sélection Sigma."""
    out = {}
    if isinstance(sel, list):
        if all(isinstance(x, dict) for x in sel):
            return realize_selection(rng.choice(sel))
        # liste de mots-clés
        kw = [fill_wildcards(str(x)) for x in sel]
        out["__keywords__"] = rng.choice(kw)
        return out
    if not isinstance(sel, dict):
        out["__keywords__"] = fill_wildcards(str(sel))
        return out
    for k, val in sel.items():
        field, mods = parse_key(k)
        if "all" in mods and isinstance(val, list):
            mods2 = [m for m in mods if m != "all"]
            pieces = [str(realize(field, mods2, x)) for x in val]
            if "contains" in mods:
                out[field] = " ".join(pieces)
            else:
                out[field] = pieces[0]
            continue
        if isinstance(val, list):
            val = rng.choice(val) if val else None
        r = realize(field, mods, val)
        if r is not None:
            out[field] = r
    return out


def negated_names(condition, names):
    neg = set()
    cond = condition
    for n in names:
        if re.search(r"not\s+" + re.escape(n) + r"\b", cond):
            neg.add(n)
    for m in re.finditer(r"not\s+(?:1|all)\s+of\s+([\w*]+)", cond):
        pat = m.group(1).replace("*", ".*")
        for n in names:
            if re.fullmatch(pat, n):
                neg.add(n)
    return neg


def synth_event(rule):
    det = rule["detection"]
    condition = det.get("condition")
    if isinstance(condition, list):
        condition = condition[0]
    condition = str(condition)
    if any(x in condition for x in ("|", "count(", "near")) or "timeframe" in det:
        raise Unsupported("aggregation")
    names = [k for k in det if k not in ("condition", "timeframe")]
    neg = negated_names(condition, names)
    pos = [n for n in names if n not in neg and n in condition or (n not in neg and re.search(r"of\s+" + re.escape(n.split("_")[0]), condition))]
    pos = [n for n in pos if n not in neg]
    if not pos:
        raise Unsupported("no positive selection")
    if " or " in condition or re.search(r"\b1 of\b", condition):
        if re.search(r"\band\b", condition) and not re.search(r"\b1 of\b", condition):
            chosen = pos  # condition mixte : on prend tout (approximation)
        else:
            chosen = [rng.choice(pos)]
    else:
        chosen = pos
    fields = {}
    for n in chosen:
        fields.update(realize_selection(det[n]))

    ls = rule["logsource"]
    cat, svc = ls.get("category"), ls.get("service")
    if cat in CATEGORY_META:
        channel, eid = CATEGORY_META[cat]
    elif svc in SERVICE_CHANNEL:
        channel, eid = SERVICE_CHANNEL[svc], fields.pop("EventID", None)
    else:
        raise Unsupported(f"logsource {cat}/{svc}")
    eid = fields.pop("EventID", eid)
    if isinstance(eid, list):
        eid = eid[0]

    kw = fields.pop("__keywords__", None)
    data = {}
    user = rng.choice(USERS)
    if cat == "process_creation":
        img = fields.get("Image") or fields.get("NewProcessName")
        if not img:
            ofn = fields.get("OriginalFileName")
            img = f"C:\\Windows\\System32\\{ofn.lower()}" if isinstance(ofn, str) and ofn.lower().endswith(".exe") else rng.choice(
                ["C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Windows\\System32\\rundll32.exe"])
        data["Image"] = img
        data["CommandLine"] = fields.get("CommandLine") or f"\"{img}\" {rng.choice(['', '/c ' + rng.choice(TOKENS), '-nop -w hidden'])}".strip()
        data["ParentImage"] = fields.get("ParentImage") or rng.choice(PARENTS)
        data["CurrentDirectory"] = rng.choice(DIRS) + "\\"
        data["User"] = fields.get("User") or user
        data["IntegrityLevel"] = fields.get("IntegrityLevel") or rng.choice(["Medium", "High", "System"])
    elif cat in ("file_event", "file_delete", "file_access", "create_stream_hash"):
        data["Image"] = fields.get("Image") or rng.choice(PARENTS)
        data["TargetFilename"] = fields.get("TargetFilename") or f"{rng.choice(DIRS)}\\{rng.choice(TOKENS)}.tmp"
        data["User"] = user
    elif cat and cat.startswith("registry"):
        data["EventType"] = "SetValue" if cat == "registry_set" else ("DeleteKey" if cat == "registry_delete" else "CreateKey")
        data["Image"] = fields.get("Image") or rng.choice(PARENTS)
        data["TargetObject"] = fields.get("TargetObject") or "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" + rng.choice(TOKENS)
        if cat == "registry_set":
            data["Details"] = fields.get("Details") or "DWORD (0x00000001)"
    elif cat == "network_connection":
        data["Image"] = fields.get("Image") or rng.choice(PARENTS)
        data["Initiated"] = "true"
        data["DestinationIp"] = fields.get("DestinationIp") or f"185.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}"
        data["DestinationPort"] = fields.get("DestinationPort") or rng.choice([443, 80, 4444, 8080])
    elif cat in ("image_load", "driver_load"):
        data["Image"] = fields.get("Image") or rng.choice(PARENTS)
        data["ImageLoaded"] = fields.get("ImageLoaded") or f"{rng.choice(DIRS)}\\{rng.choice(TOKENS)}.dll"
    elif cat == "dns_query":
        data["Image"] = fields.get("Image") or rng.choice(PARENTS)
        data["QueryName"] = fields.get("QueryName") or f"{rng.choice(TOKENS)}.example.net"
    elif cat in ("create_remote_thread", "process_access"):
        data["SourceImage"] = fields.get("SourceImage") or rng.choice(PARENTS)
        data["TargetImage"] = fields.get("TargetImage") or "C:\\Windows\\System32\\lsass.exe"
    elif cat == "ps_script":
        data["ScriptBlockText"] = fields.get("ScriptBlockText") or kw or "Get-Process"
        kw = None
    elif cat in ("ps_module", "ps_classic_start"):
        data["Payload" if cat == "ps_module" else "Data"] = fields.get("Payload") or fields.get("Data") or kw or "powershell.exe"
        kw = None
    # tous les champs de la détection sont conservés
    for k, v in fields.items():
        data.setdefault(k, v)
    if kw:
        data["Message"] = kw
    ev = {"Channel": channel, "EventID": eid, "Computer": rng.choice(HOSTS),
          "TimeCreated": f"2026-{rng.randint(1,10):02d}-{rng.randint(1,28):02d}T{rng.randint(0,23):02d}:{rng.randint(0,59):02d}:{rng.randint(0,59):02d}Z"}
    ev.update(data)
    return ev


# ---------------------------------------------------------------- Événements réels (regression_data)
DROP_FIELDS = {"ProcessGuid", "ParentProcessGuid", "LogonGuid", "SourceProcessGUID", "TargetProcessGUID", "RuleName",
               "UtcTime", "Hashes", "LogonId", "ProcessId", "ParentProcessId", "SourceProcessId", "TargetProcessId", "ThreadID", "TerminalSessionId", "FileVersion", "SourceProcessGuid", "TargetProcessGuid", "CreationUtcTime"}


def flatten_real(evt):
    e = evt.get("Event", evt)
    sysd = e.get("System", {})
    out = {"Channel": sysd.get("Channel"), "EventID": sysd.get("EventID"), "Computer": sysd.get("Computer")}
    tc = sysd.get("TimeCreated", {})
    if isinstance(tc, dict):
        out["TimeCreated"] = tc.get("#attributes", {}).get("SystemTime")
    ed = e.get("EventData") or e.get("UserData") or {}
    if isinstance(ed, dict):
        for k, v in ed.items():
            if k in DROP_FIELDS or k.startswith("#"):
                continue
            if isinstance(v, dict):
                for k2, v2 in v.items():
                    if not k2.startswith("#") and k2 not in DROP_FIELDS:
                        out[k2] = v2
            else:
                out[k] = v
    for k, v in list(out.items()):
        if isinstance(v, str) and len(v) > 1200:
            out[k] = v[:1200] + "…"
        if v in (None, "", "-"):
            out.pop(k)
    return out


def load_real_events(rule_path, rule):
    rtp = rule.get("regression_tests_path")
    if not rtp:
        return []
    info_path = os.path.normpath(os.path.join(SIGMA_DIR, rtp))
    folder = os.path.dirname(info_path)
    evs = []
    for jf in glob.glob(os.path.join(folder, "*.json")):
        txt = open(jf, encoding="utf-8", errors="ignore").read().strip()
        try:
            objs = [json.loads(txt)]
        except json.JSONDecodeError:
            objs = [json.loads(l) for l in txt.splitlines() if l.strip()]
        for o in objs:
            if isinstance(o, list):
                evs.extend(o)
            else:
                evs.append(o)
    return [flatten_real(e) for e in evs[:3]]


# ---------------------------------------------------------------- Réponse cible
def summarize(ev):
    for k in ("CommandLine", "ScriptBlockText", "Payload", "TargetObject", "TargetFilename", "ImageLoaded",
              "QueryName", "DestinationIp", "TargetImage", "PipeName", "ServiceName", "ImagePath", "Image", "Message"):
        if ev.get(k) not in (None, ""):
            v = str(ev[k])
            return k, (v[:120] + "…") if len(v) > 120 else v
    return None, None


def target(rule, ev):
    tags = [t.lower() for t in rule.get("tags") or []]
    techs = [t.split(".", 1)[1].upper() for t in tags if re.match(r"attack\.t\d{4}", t)]
    techs = [t for t in techs if t in TECH]
    if not techs:
        return None, None
    techs.sort(key=lambda t: -t.count("."))  # la plus spécifique d'abord
    tid = techs[0]
    tactic_tags = [t.split(".", 1)[1] for t in tags if t.split(".", 1)[1] in TACTIC_FR]
    tac = next((t for t in tactic_tags if t in TECH[tid]["tactics"]), None) or (tactic_tags or TECH[tid]["tactics"] or ["execution"])[0]
    tac_fr, tac_id = TACTIC_FR.get(tac, ("Inconnue", ""))
    sev = SEVERITY_FR.get(rule.get("level", "medium"), "moyenne")
    k, v = summarize(ev)
    src = f"{ev.get('Channel', 'journal Windows')} (EventID {ev.get('EventID')})"
    obs = f"Le champ {k} contient « {v} »" if k else "Les champs de l'événement"
    expl = (f"{obs} sur {ev.get('Computer', 'le poste')} ({src}). "
            f"Ce comportement correspond à la technique {tid} « {TECH[tid]['full_name']} » "
            f"(tactique : {tac_fr}).")
    fps = rule.get("falsepositives") or []
    fps = [f for f in fps if isinstance(f, str) and f.lower() not in ("unknown", "unlikely", "none")]
    if fps:
        expl += " Faux positif possible : " + fps[0].rstrip(".") + "."
    out = {
        "verdict": "suspect",
        "technique_id": tid,
        "technique": TECH[tid]["full_name"],
        "tactique": f"{tac_fr} ({tac_id})",
        "severite": sev,
        "explication": expl,
        "recommandations": RECO_FR.get(tac, RECO_FR["execution"]),
    }
    return out, techs


BENIGN = [
    {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "CommandLine": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=renderer --lang=fr", "ParentImage": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
    {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "CommandLine": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\"", "ParentImage": "C:\\Windows\\explorer.exe"},
    {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": "C:\\Windows\\System32\\notepad.exe", "CommandLine": "\"C:\\Windows\\System32\\notepad.exe\" C:\\Users\\a.benali\\Documents\\notes.txt", "ParentImage": "C:\\Windows\\explorer.exe"},
    {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": "C:\\Windows\\System32\\svchost.exe", "CommandLine": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule", "ParentImage": "C:\\Windows\\System32\\services.exe"},
    {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": "C:\\Users\\k.amrani\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", "CommandLine": "\"Teams.exe\" --process-start-reason=startup", "ParentImage": "C:\\Windows\\explorer.exe"},
    {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe Get-ChildItem C:\\Users\\j.dupont\\Documents", "ParentImage": "C:\\Windows\\explorer.exe"},
    {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 3, "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "DestinationHostname": "outlook.office365.com", "DestinationIp": "52.97.146.162", "DestinationPort": 443, "Initiated": "true"},
    {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 11, "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "TargetFilename": "C:\\Users\\h.berrada\\Documents\\budget_2026.xlsx"},
    {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 22, "Image": "C:\\Program Files\\Mozilla Firefox\\firefox.exe", "QueryName": "www.ensabm.ac.ma"},
    {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 13, "EventType": "SetValue", "Image": "C:\\Windows\\System32\\svchost.exe", "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\LastOnlineScanTimeForAppCategory", "Details": "QWORD (0x01db2a3f-0x1c2b3d4e)"},
    {"Channel": "Security", "EventID": 4624, "TargetUserName": "a.benali", "TargetDomainName": "CORP", "LogonType": 2, "IpAddress": "-", "WorkstationName": "WS-012"},
    {"Channel": "Security", "EventID": 4634, "TargetUserName": "s.elidrissi", "TargetDomainName": "CORP", "LogonType": 3},
    {"Channel": "Microsoft-Windows-PowerShell/Operational", "EventID": 4104, "ScriptBlockText": "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName"},
    {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 7, "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "ImageLoaded": "C:\\Program Files\\Microsoft Office\\root\\Office16\\MSO.DLL"},
    {"Channel": "System", "EventID": 7036, "param1": "Windows Update", "param2": "running"},
]


def benign_example():
    ev = dict(rng.choice(BENIGN))
    ev = {"Computer": rng.choice(HOSTS), **ev}
    if ev["EventID"] in (1,) and "User" not in ev:
        ev["User"] = rng.choice(USERS[:6])
    k, v = summarize(ev)
    expl = (f"Activité courante : le champ {k} contient « {v} »." if k else "Activité courante.") + \
           " Aucun indicateur de technique d'attaque n'est présent ; il s'agit d'un comportement légitime attendu sur un poste ou serveur d'entreprise."
    return ev, {"verdict": "bénin", "technique_id": None, "technique": None, "tactique": None, "severite": "informative",
                "explication": expl, "recommandations": ["Aucune action requise", "Conserver l'événement pour la corrélation si nécessaire"]}


def to_chat(ev, ans, meta):
    user = "Analyse cet événement Windows :\n```json\n" + json.dumps(ev, ensure_ascii=False) + "\n```"
    return {"messages": [{"role": "system", "content": SYSTEM_PROMPT},
                         {"role": "user", "content": user},
                         {"role": "assistant", "content": json.dumps(ans, ensure_ascii=False)}],
            **meta}


# ---------------------------------------------------------------- Construction
rule_files = sorted(glob.glob(os.path.join(SIGMA_DIR, "rules", "windows", "**", "*.yml"), recursive=True))
rules = []
for f in rule_files:
    try:
        r = yaml.safe_load(open(f, encoding="utf-8"))
    except Exception:
        continue
    if not isinstance(r, dict) or r.get("status") in ("deprecated", "unsupported") or "detection" not in r:
        continue
    rules.append((f, r))
print(f"Règles Windows : {len(rules)}")

has_real = [x for x in rules if x[1].get("regression_tests_path")]
no_real = [x for x in rules if not x[1].get("regression_tests_path")]
rng.shuffle(has_real)
rng.shuffle(no_real)
n_test_real = int(len(has_real) * 0.3)
n_test_syn = int(len(no_real) * 0.08)
test_ids = {r["id"] for _, r in has_real[:n_test_real] + no_real[:n_test_syn]}

train, test = [], []
stats = Counter()
for f, r in rules:
    split = "test" if r["id"] in test_ids else "train"
    real_events = []
    try:
        real_events = load_real_events(f, r)
    except Exception:
        stats["real_err"] += 1
    samples = [("reel", e) for e in real_events]
    n_syn = 1 if split == "test" else 3
    seen = set()
    for _ in range(n_syn * 3):
        if sum(1 for s in samples if s[0] == "synthetique") >= n_syn:
            break
        try:
            ev = synth_event(r)
        except Unsupported:
            stats["unsupported"] += 1
            break
        except Exception:
            stats["synth_err"] += 1
            break
        key = json.dumps({k: v for k, v in ev.items() if k not in ("Computer", "TimeCreated", "User")}, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        samples.append(("synthetique", ev))
    for src, ev in samples:
        ans, techs = target(r, ev)
        if ans is None:
            stats["no_technique"] += 1
            break
        ex = to_chat(ev, ans, {"source": src, "rule_id": r["id"], "rule_title": r["title"], "techniques_valides": techs,
                               "tactique_attendue": ans["tactique"]})
        (test if split == "test" else train).append(ex)
        stats[f"{split}_{src}"] += 1

# exemples bénins (~8 %)
for split, lst, n in (("train", train, int(len(train) * 0.08)), ("test", test, max(30, int(len(test) * 0.08)))):
    for _ in range(n):
        ev, ans = benign_example()
        lst.append(to_chat(ev, ans, {"source": "benin", "rule_id": None, "rule_title": None, "techniques_valides": [], "tactique_attendue": None}))
        stats[f"{split}_benin"] += 1

rng.shuffle(train)
rng.shuffle(test)
for name, lst in (("train", train), ("test", test)):
    with open(os.path.join(OUT_DIR, f"{name}.jsonl"), "w", encoding="utf-8") as fh:
        for ex in lst:
            fh.write(json.dumps(ex, ensure_ascii=False, default=str) + "\n")

print(dict(stats))
print(f"train={len(train)} test={len(test)}")
tech_train = Counter(t for ex in train for t in ex["techniques_valides"][:1])
tech_test = Counter(t for ex in test for t in ex["techniques_valides"][:1])
print(f"techniques distinctes : train={len(tech_train)} test={len(tech_test)} ; test non vues en train={len(set(tech_test) - set(tech_train))}")
