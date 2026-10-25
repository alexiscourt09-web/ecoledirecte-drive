"""
École Directe -> Google Drive (API NON officielle, usage personnel).

Variables d'environnement :
  ED_ID, ED_PASSWORD      identifiants École Directe
  ED_FA                   jeton double auth (JSON), obtenu avec : python main.py setup
  DRIVE_WEBHOOK_URL       adresse du script Google Apps Script (voir apps_script.gs)
  DRIVE_WEBHOOK_SECRET    mot de passe partagé avec ce script
Sans DRIVE_WEBHOOK_URL, les fichiers sont écrits dans le dossier ./sortie (pour tester).
"""
import base64
import json
import os
import re
import sys
from datetime import date, timedelta

import requests

API = "https://api.ecoledirecte.com/v3"
V = os.environ.get("ED_VERSION", "4.101.4")  # ajustable si le serveur répond 517


def b64e(s):
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def b64d(s):
    return base64.b64decode(s).decode("utf-8")


class ED:
    """Client minimal : suit X-Token et 2FA-Token comme l'appli web."""

    def __init__(self):
        self.s = requests.Session()
        self.s.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
        self.token = ""
        self.token2fa = ""
        self.gtk = ""

    def _track(self, r):
        t = r.headers.get("X-Token")
        if t:
            self.token = t
        t2 = r.headers.get("2FA-Token")
        if t2:
            self.token2fa = t2
        return r

    def _headers(self, with_gtk=False):
        h = {"X-Token": self.token, "2FA-Token": self.token2fa}
        if with_gtk and self.gtk:
            h["X-Gtk"] = self.gtk
        return h

    def refresh_gtk(self):
        r = self.s.get(f"{API}/login.awp?gtk=1&v={V}", timeout=30)
        self.gtk = (r.headers.get("X-GTK") or self.s.cookies.get("GTK") or "")
        return self.gtk

    def call(self, path, data=None, params="", method="POST"):
        url = f"{API}{path}?{params}v={V}"
        if method == "GET":
            r = self.s.get(url, headers=self._headers(), timeout=30)
        else:
            r = self.s.post(url, data={"data": json.dumps(data or {})},
                            headers=self._headers(), timeout=30)
        self._track(r)
        try:
            return r.json()
        except Exception:
            return {"code": r.status_code, "message": r.text[:200]}

    def login(self, ident, pwd, fa=None, flat=None):
        """flat = {'cn':..,'cv':..} à ajouter au niveau supérieur (fin de 2FA)."""
        self.refresh_gtk()  # GTK frais avant chaque POST de login
        payload = {"identifiant": ident, "motdepasse": pwd,
                   "isReLogin": False, "uuid": "", "fa": fa or []}
        if flat:
            payload.update(flat)
        r = self.s.post(f"{API}/login.awp?v={V}",
                        data={"data": json.dumps(payload)},
                        headers=self._headers(with_gtk=True), timeout=30)
        self._track(r)
        try:
            j = r.json()
        except Exception:
            return {"code": r.status_code, "message": r.text[:200]}
        if j.get("token"):
            self.token = j["token"] if not r.headers.get("X-Token") else self.token
        return j


def setup_2fa():
    """À lancer UNE FOIS en local pour obtenir le jeton ED_FA."""
    import getpass
    ident = input("Identifiant : ")
    pwd = getpass.getpass("Mot de passe (masqué) : ")
    ed = ED()
    j = ed.login(ident, pwd)
    code = j.get("code")
    print(f"Connexion : code {code} - {j.get('message')}")
    print(f"  jeton: {bool(ed.token)}, 2FA-Token: {bool(ed.token2fa)}")
    if code == 200:
        print("Pas de double authentification demandée : ED_FA peut rester [].")
        return
    if code != 250:
        return

    # 1) la question (GET), avec X-Token + 2FA-Token, sans X-Gtk
    q = {}
    for method in ("POST", "GET"):
        q = ed.call("/connexion/doubleauth.awp", {}, "verbe=get&", method=method)
        print(f"  question via {method} : code {q.get('code')} - {q.get('message')}")
        if (q.get("data") or {}).get("question"):
            break
    d = q.get("data") or {}
    if "question" not in d:
        print("\nRéponse inattendue de l'API (copie-la à Claude) :")
        print(json.dumps(q, ensure_ascii=False)[:1500])
        return
    print("\nQuestion :", b64d(d["question"]))
    props = d["propositions"]  # base64, à renvoyer tel quel
    for i, p in enumerate(props):
        print(f"  {i}. {b64d(p)}")
    choix = props[int(input("Numéro de ta réponse : "))]

    # 2) la réponse (POST)
    r = ed.call("/connexion/doubleauth.awp", {"choix": choix}, "verbe=post&")
    rd = r.get("data") or {}
    if "cn" not in rd:
        print("\nRéponse inattendue après ta réponse :")
        print(json.dumps(r, ensure_ascii=False)[:1500])
        return

    # 3) re-login pour valider (cn/cv à plat ET dans fa)
    fa = [{"cn": rd["cn"], "cv": rd["cv"], "uniq": False}]
    j2 = ed.login(ident, pwd, fa, flat={"cn": rd["cn"], "cv": rd["cv"]})
    print(f"\nValidation : code {j2.get('code')} - {j2.get('message')}")
    if j2.get("code") != 200:
        return
    print("\nValeur à mettre dans ED_FA :\n")
    print(json.dumps(fa))


def collect(ed):
    ident = os.environ["ED_ID"].strip()
    pwd = os.environ["ED_PASSWORD"].strip()
    fa = json.loads(os.environ.get("ED_FA", "[]"))
    print(f"Diagnostic : identifiant {len(ident)} car., mot de passe {len(pwd)} car., "
          f"ED_FA {len(fa)} entrée(s)")
    if pwd[:1] in "\"'" and pwd[-1:] == pwd[:1]:
        print("ATTENTION : le mot de passe est entouré de guillemets dans la variable.")
    j = ed.login(ident, pwd, fa)
    if j.get("code") != 200:
        raise SystemExit(f"Connexion refusée : {j.get('code')} {j.get('message')}")

    acc = j["data"]["accounts"][0]
    if acc.get("typeCompte") == "E":
        students = [{"id": acc["id"], "nom": acc.get("prenom", "eleve")}]
    else:  # compte parent
        students = [{"id": e["id"], "nom": e.get("prenom", str(e["id"]))}
                    for e in acc["profile"].get("eleves", [])]

    today = date.today()
    out = {}
    for st in students:
        sid, nom = st["id"], st["nom"]
        notes = safe(ed, f"/eleves/{sid}/notes.awp", {}, "verbe=get&")
        devoirs = safe(ed, f"/Eleves/{sid}/cahierdetexte.awp", {}, "verbe=get&")
        vie = safe(ed, f"/eleves/{sid}/viescolaire.awp", {}, "verbe=get&")

        # Détail des devoirs, jour par jour (contenu complet)
        jours = {}
        dates = list((devoirs.get("data") or {}).keys())[:20]
        for d in dates:
            jours[d] = safe(ed, f"/Eleves/{sid}/cahierdetexte/{d}.awp", {}, "verbe=get&")

        out[f"{nom}_notes.json"] = notes
        out[f"{nom}_devoirs_liste.json"] = devoirs
        out[f"{nom}_devoirs_detail.json"] = jours
        out[f"{nom}_vie_scolaire.json"] = vie
        out[f"{nom}_emploi_du_temps.json"] = safe(
            ed, f"/E/{sid}/emploidutemps.awp",
            {"dateDebut": today.isoformat(),
             "dateFin": (today + timedelta(days=14)).isoformat(),
             "avecTrous": False},
            "verbe=get&",
        )
        out[f"{nom}_messages_recus.json"] = safe(
            ed, f"/eleves/{sid}/messages.awp", {"anneeMessages": ""},
            "verbe=get&typeRecuperation=received&")
        out[f"{nom}_messages_envoyes.json"] = safe(
            ed, f"/eleves/{sid}/messages.awp", {"anneeMessages": ""},
            "verbe=get&typeRecuperation=sent&")
        out[f"{nom}_fil_actualite.json"] = safe(ed, f"/eleves/{sid}/timeline.awp", {}, "verbe=get&")
        out[f"{nom}_documents.json"] = safe(ed, "/familledocuments.awp", {}, "verbe=get&")
        out[f"{nom}_RESUME.txt"] = make_summary(nom, notes, jours, vie)
    return out


def safe(ed, path, data=None, params=""):
    """Un échec sur une rubrique n'arrête pas tout le reste."""
    try:
        return ed.call(path, data, params)
    except Exception as e:
        return {"erreur": str(e)}


def clean_html(b):
    try:
        t = b64d(b)
    except Exception:
        return ""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", t)).strip()


def make_summary(nom, notes, jours, vie):
    """Fichier texte lisible, pratique pour Gemini / NotebookLM."""
    L = [f"=== {nom} (mis à jour le {date.today().isoformat()}) ===", "", "-- NOTES --"]
    for n in (notes.get("data") or {}).get("notes", []):
        L.append(f"{n.get('date')} | {n.get('libelleMatiere')} | {n.get('devoir')} | "
                 f"{n.get('valeur')}/{n.get('noteSur')} (coef {n.get('coef')}, "
                 f"moyenne classe {n.get('moyenneClasse')})")
    L += ["", "-- DEVOIRS A FAIRE --"]
    for jour, rep in jours.items():
        for m in (rep.get("data") or {}).get("matieres", []):
            af = m.get("aFaire")
            if af:
                L.append(f"Pour le {jour} | {m.get('matiere')} | "
                         f"{clean_html(af.get('contenu', ''))}")
    vd = vie.get("data") or {}
    L += ["", "-- ABSENCES / RETARDS --"]
    for a in vd.get("absencesRetards", []):
        L.append(f"{a.get('typeElement')} | {a.get('displayDate') or a.get('date')} | "
                 f"{a.get('libelle')} | justifié: {a.get('justifie')}")
    L += ["", "-- SANCTIONS / ENCOURAGEMENTS --"]
    for s in vd.get("sanctionsEncouragements", []):
        L.append(f"{s.get('typeElement')} | {s.get('date')} | {s.get('libelle')} | {s.get('motif')}")
    return "\n".join(L)


def push(files):
    """Envoie les fichiers au script Apps Script (qui les écrit dans ton Drive)."""
    url = os.environ.get("DRIVE_WEBHOOK_URL")
    if not url:
        os.makedirs("sortie", exist_ok=True)
        for name, content in files.items():
            text = content if isinstance(content, str) else json.dumps(
                content, ensure_ascii=False, indent=2)
            with open(os.path.join("sortie", name), "w", encoding="utf-8") as f:
                f.write(text)
            print("écrit (local)", name)
        return
    payload = {"secret": os.environ["DRIVE_WEBHOOK_SECRET"], "files": files}
    r = requests.post(url, json=payload, timeout=120)
    print("Réponse du Drive :", r.status_code, r.text[:200])
    if not r.text.startswith("ok"):
        raise SystemExit("Envoi vers Drive refusé : vérifie l'URL et le secret.")


def main():
    push(collect(ED()))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "setup":
        setup_2fa()
    else:
        main()
