# vhi_manager.py
import os, sys, json, base64, requests, ipaddress, math, time, datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from rich import box
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.layout import Layout
from rich.panel import Panel
from rich.align import Align

console = Console()

# ====== CONFIG VHI (en dur) ======
OS_AUTH_URL = "https://vhi-panel.X.fr:5000/v3"
OS_USERNAME = "evan"
OS_PASSWORD = ""
OS_USER_DOMAIN_NAME = ""
OS_PROJECT_DOMAIN_NAME = ""
OS_PROJECT_NAME = "Evan"  # si auth 401, essaie "evan"
VERIFY_TLS = True
# =================================

# ---------- Helpers HTTP ----------
def GET(url, token, **kw):
    return requests.get(url, headers={"X-Auth-Token": token}, timeout=30, verify=VERIFY_TLS, **kw)
def POST(url, token, **kw):
    return requests.post(url, headers={"X-Auth-Token": token, **kw.pop("headers", {})}, timeout=120, verify=VERIFY_TLS, **kw)
def DELETE(url, token, **kw):
    return requests.delete(url, headers={"X-Auth-Token": token}, timeout=30, verify=VERIFY_TLS, **kw)
def PUT(url, token, **kw):
    return requests.put(url, headers={"X-Auth-Token": token}, timeout=300, verify=VERIFY_TLS, **kw)

def safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return {"_status": resp.status_code, "_text": resp.text[:400]}

# ---------- Auth Keystone v3 ----------
def keystone_auth() -> tuple[str, Dict[str, str], str]:
    payload = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {"user": {
                    "name": OS_USERNAME,
                    "domain": {"name": OS_USER_DOMAIN_NAME},
                    "password": OS_PASSWORD
                }}
            },
            "scope": {"project": {
                "name": OS_PROJECT_NAME,
                "domain": {"name": OS_PROJECT_DOMAIN_NAME}
            }}
        }
    }
    r = requests.post(f"{OS_AUTH_URL.rstrip('/')}/auth/tokens", json=payload, timeout=30, verify=VERIFY_TLS)
    if r.status_code != 201:
        try: console.print(f"[red]Auth error: {r.status_code} {json.dumps(r.json(), indent=2)}[/red]")
        except Exception: console.print(f"[red]Auth error: {r.status_code} {r.text}[/red]")
        r.raise_for_status()

    token = r.headers["X-Subject-Token"]
    body = r.json()
    project_id = body["token"]["project"]["id"]

    endpoints: Dict[str,str] = {}
    for svc in body["token"]["catalog"]:
        stype = svc.get("type")
        for ep in svc.get("endpoints", []):
            if ep.get("interface") == "public":
                endpoints[stype] = ep["url"].rstrip("/")
                break
    return token, endpoints, project_id

# ---------- Dashboard ----------
def gather_stats(token, ep, project_id) -> Dict[str, Any]:
    stats: Dict[str, Any] = {}

    nova = ep.get("compute")
    if nova:
        sv = safe_json(GET(f"{nova}/servers/detail", token))
        stats["vm_count"] = len(sv.get("servers", [])) if isinstance(sv, dict) else 0
        lim = safe_json(GET(f"{nova}/limits", token))
        abs_lim = lim.get("limits", {}).get("absolute", {}) if isinstance(lim, dict) else {}
        stats["cores_used"] = abs_lim.get("totalCoresUsed")
        stats["cores_max"]  = abs_lim.get("maxTotalCores")
        stats["ram_used"]   = abs_lim.get("totalRAMUsed")
        stats["ram_max"]    = abs_lim.get("maxTotalRAMSize")

    neutron = ep.get("network")
    if neutron:
        fips = safe_json(GET(f"{neutron}/v2.0/floatingips", token)).get("floatingips", [])
        stats["fip_total"] = len(fips)
        stats["fip_associated"] = sum(1 for f in fips if f.get("port_id"))

    cinder = ep.get("volumev3") or ep.get("volumev2") or ep.get("volume")
    if cinder:
        base = cinder.rstrip("/")
        if base.endswith(f"/{project_id}"):
            vol_url = f"{base}/volumes/detail"; lim_url = f"{base}/limits"
        elif base.endswith("/v3") or base.endswith("/v2"):
            probe = GET(f"{base}/volumes/detail", token)
            if probe.status_code in (200, 203):
                vol_url = f"{base}/volumes/detail"; lim_url = f"{base}/limits"
            else:
                vol_url = f"{base}/{project_id}/volumes/detail"; lim_url = f"{base}/{project_id}/limits"
        else:
            vol_url = f"{base}/volumes/detail"; lim_url = f"{base}/limits"
        vols = safe_json(GET(vol_url, token)).get("volumes", [])
        stats["vol_count"] = len(vols)
        stats["vol_size_gb"] = sum(v.get("size", 0) for v in vols)
        limj = safe_json(GET(lim_url, token))
        abs_lim = limj.get("limits", {}).get("absolute", {}) if isinstance(limj, dict) else {}
        if abs_lim: stats["vol_gb_max"] = abs_lim.get("maxTotalVolumeGigabytes")
    return stats

def render_dashboard(stats: Dict[str, Any]) -> Panel:
    t = Table(box=box.SIMPLE_HEAVY, expand=True, show_header=True, header_style="bold magenta")
    t.add_column("Ressource", style="cyan", no_wrap=True)
    t.add_column("Utilisation", justify="right")
    t.add_row("VMs", str(stats.get("vm_count","n/a")))
    if stats.get("cores_used") is not None: t.add_row("vCPU", f"{stats['cores_used']} / {stats.get('cores_max','?')}")
    if stats.get("ram_used")   is not None: t.add_row("RAM (MB)", f"{stats['ram_used']} / {stats.get('ram_max','?')}")
    if stats.get("vol_count")  is not None: t.add_row("Volumes", f"{stats['vol_count']} — {stats.get('vol_size_gb',0)} GiB")
    if stats.get("fip_total")  is not None: t.add_row("Floating IPs", f"{stats['fip_associated']} / {stats['fip_total']}")
    return Panel(t, title="Projet", border_style="magenta")

# ---------- Listages ----------
def list_images(token, ep) -> List[dict]:
    glance = ep.get("image")
    imgs = []
    for q in ["", "?visibility=public", "?visibility=shared&member_status=accepted", "?visibility=community"]:
        r = GET(f"{glance}/v2/images{q}", token)
        if r.status_code in (200, 203):
            imgs += r.json().get("images", [])
    seen, uniq = set(), []
    for im in imgs:
        if im["id"] in seen: continue
        seen.add(im["id"]); uniq.append(im)
    return uniq

def list_flavors(token, ep) -> List[dict]:
    nova = ep.get("compute")
    return GET(f"{nova}/flavors/detail", token).json().get("flavors", [])

def list_networks(token, ep) -> List[dict]:
    neutron = ep.get("network")
    return GET(f"{neutron}/v2.0/networks", token).json().get("networks", [])

def list_servers(token, ep) -> List[dict]:
    nova = ep.get("compute")
    return GET(f"{nova}/servers/detail", token).json().get("servers", [])

# ---------- Sélections ----------
def pick_image(token, ep) -> Optional[str]:
    imgs = list_images(token, ep)
    if not imgs:
        console.print("[yellow]Aucune image visible (uploade une ISO/QCOW2 dans le cloud si besoin)[/yellow]")
        return None
    table = Table(title="Images", box=box.ROUNDED)
    table.add_column("Idx"); table.add_column("Name"); table.add_column("Visibility"); table.add_column("ID")
    for i, im in enumerate(imgs): table.add_row(str(i), im.get("name",""), im.get("visibility","?"), im["id"])
    console.print(table)
    idx = IntPrompt.ask("Choisis l'indice", default=0)
    return imgs[idx]["id"]

def pick_flavor(token, ep) -> Optional[str]:
    fls = list_flavors(token, ep)
    if not fls:
        console.print("[yellow]Aucun flavor[/yellow]"); return None
    default_idx = 0
    for i, f in enumerate(fls):
        if f.get("name","").lower() == "small":
            default_idx = i; break
    table = Table(title="Flavors (small pré-sélectionné si dispo)", box=box.ROUNDED)
    table.add_column("Idx"); table.add_column("Name"); table.add_column("vCPU"); table.add_column("RAM MB"); table.add_column("Disk"); table.add_column("ID")
    for i, f in enumerate(fls): table.add_row(str(i), f.get("name",""), str(f.get("vcpus")), str(f.get("ram")), str(f.get("disk")), f["id"])
    console.print(table)
    idx = IntPrompt.ask("Choisis l'indice", default=default_idx)
    return fls[idx]["id"]

def list_secgroups(token, ep, project_id) -> List[dict]:
    neutron = ep.get("network")
    resp = GET(f"{neutron}/v2.0/security-groups", token)
    sgs = resp.json().get("security_groups", [])
    return [sg for sg in sgs if sg.get("project_id")==project_id or sg.get("tenant_id")==project_id] or sgs

def pick_network(token, ep) -> Optional[str]:
    nets = GET(f"{ep.get('network')}/v2.0/networks", token).json().get("networks", [])
    if not nets:
        console.print("[yellow]Aucun réseau[/yellow]"); return None
    table = Table(title="Réseaux", box=box.ROUNDED); table.add_column("Idx"); table.add_column("Name"); table.add_column("ID")
    for i, n in enumerate(nets): table.add_row(str(i), n.get("name",""), n["id"])
    console.print(table)
    idx = IntPrompt.ask("Choisis l'indice", default=0)
    return nets[idx]["id"]

def pick_secgroups(token, ep, project_id) -> List[str]:
    sgs = list_secgroups(token, ep, project_id)
    if not sgs:
        console.print("[yellow]Aucun security group[/yellow]"); return []
    table = Table(title="Security Groups (sépare par des virgules)", box=box.ROUNDED)
    table.add_column("Idx"); table.add_column("Name"); table.add_column("ID"); table.add_column("Rules")
    for i, sg in enumerate(sgs): table.add_row(str(i), sg.get("name",""), sg["id"], str(len(sg.get("security_group_rules", []))))
    console.print(table)
    raw = Prompt.ask("Indices (ex: 0,2) - vide = default", default="")
    if not raw.strip():
        return []
    idxs = [int(x) for x in raw.replace(" ","").split(",") if x != ""]
    return [sgs[i]["id"] for i in idxs]

def list_keypairs(token, ep) -> List[dict]:
    nova = ep.get("compute")
    return GET(f"{nova}/os-keypairs", token).json().get("keypairs", [])

def create_keypair_from_file(token, ep, name: str, pub_path: Path) -> str:
    nova = ep.get("compute")
    pub = pub_path.read_text(encoding="utf-8").strip()
    body = {"keypair": {"name": name, "public_key": pub}}
    r = POST(f"{nova}/os-keypairs", token, json=body, headers={"Content-Type":"application/json"})
    r.raise_for_status()
    return r.json()["keypair"]["name"]

def pick_or_create_keypair(token, ep) -> Optional[str]:
    kps = list_keypairs(token, ep)
    names = [kp["keypair"]["name"] for kp in kps]
    table = Table(title="SSH Keypairs", box=box.ROUNDED); table.add_column("Idx"); table.add_column("Name"); table.add_column("Fingerprint")
    for i, kp in enumerate(kps): table.add_row(str(i), kp["keypair"]["name"], kp["keypair"].get("fingerprint",""))
    console.print(table)
    if Confirm.ask("Importer une nouvelle clé publique (*.pub) ?", default=False):
        path = Path(Prompt.ask("Chemin du fichier .pub", default=str(Path.home()/".ssh/id_rsa.pub")))
        name = Prompt.ask("Nom de la keypair", default=path.stem)
        try:
            return create_keypair_from_file(token, ep, name, path)
        except Exception as e:
            console.print(f"[red]Import keypair échec: {e}[/red]")
            return None
    if names:
        idx = IntPrompt.ask("Choisis l'indice de la keypair (ou -1 pour aucune)", default=0)
        if idx >= 0:
            return names[idx]
    return None

# ---------- Neutron Port ----------
def create_port(token, ep, network_id: str, secgroup_ids: List[str], spoofing: bool, fixed_ip: Optional[str]) -> str:
    neutron = ep.get("network")
    port_body: Dict[str, Any] = {
        "port": {
            "network_id": network_id,
            "port_security_enabled": (not spoofing),
        }
    }
    if secgroup_ids:
        port_body["port"]["security_groups"] = secgroup_ids
    if fixed_ip:
        try: ipaddress.ip_address(fixed_ip)
        except Exception: raise ValueError(f"IP invalide: {fixed_ip}")
        port_body["port"]["fixed_ips"] = [{"ip_address": fixed_ip}]
    r = POST(f"{neutron}/v2.0/ports", token, json=port_body, headers={"Content-Type":"application/json"})
    if r.status_code not in (201, 202):
        raise RuntimeError(f"Create port error: {r.status_code} {r.text}")
    return r.json()["port"]["id"]

# ---------- Glance / Cinder / Nova helpers (BfV) ----------
def get_image(token, ep, image_id):
    glance = ep.get("image")
    r = GET(f"{glance}/v2/images/{image_id}", token); r.raise_for_status()
    return r.json()

def ceil_gib_from_bytes(n): return max(1, math.ceil(n / (1024**3)))

def wait_volume(token, ep, project_id, vol_id, timeout=600):
    cinder = ep.get("volumev3") or ep.get("volumev2") or ep.get("volume")
    base = cinder.rstrip("/")
    url_try = f"{base}/volumes/{vol_id}"
    if GET(url_try, token).status_code in (200,203):
        vol_url = url_try
    else:
        vol_url = f"{base}/{project_id}/volumes/{vol_id}"
    t0 = time.time()
    while time.time() - t0 < timeout:
        v = GET(vol_url, token).json().get("volume", {})
        st = v.get("status")
        if st == "available": return v
        if st in {"error","error_extending"}: raise RuntimeError(f"Volume en erreur: {v}")
        time.sleep(3)
    raise TimeoutError("Attente volume Cinder trop longue")

def create_boot_volume(token, ep, project_id, image_id, name, min_size_gb=None):
    img = get_image(token, ep, image_id)
    need_gb = img.get("min_disk", 0) or (ceil_gib_from_bytes(img["size"]) if img.get("size") else 10)
    if min_size_gb: need_gb = max(need_gb, int(min_size_gb))
    cinder = ep.get("volumev3") or ep.get("volumev2") or ep.get("volume")
    base = cinder.rstrip("/")
    body = {"volume":{"name":name, "size":need_gb, "imageRef":image_id}}
    r = POST(f"{base}/volumes", token, json=body, headers={"Content-Type":"application/json"})
    if r.status_code not in (200,202):
        r = POST(f"{base}/{project_id}/volumes", token, json=body, headers={"Content-Type":"application/json"})
        r.raise_for_status()
    vol_id = r.json()["volume"]["id"]
    wait_volume(token, ep, project_id, vol_id)
    return vol_id

def create_server_from_volume(token, ep, name, flavor_id, port_id, volume_id, key_name=None, user_data_b64=None):
    nova = ep.get("compute")
    bdm = [{
        "boot_index": "0",
        "uuid": volume_id,
        "source_type": "volume",
        "destination_type": "volume",
        "delete_on_termination": True
    }]
    server = {"server": {"name": name, "flavorRef": flavor_id, "block_device_mapping_v2": bdm, "networks": [{"port": port_id}]}}
    if key_name: server["server"]["key_name"] = key_name
    if user_data_b64: server["server"]["user_data"] = user_data_b64
    r = POST(f"{nova}/servers", token, json=server, headers={"Content-Type":"application/json"})
    r.raise_for_status()
    return r.json()

# ---------- Création VM ----------
def create_vm(token, ep, project_id):
    console.rule("[bold]Assistant: Création d'une VM")
    name = Prompt.ask("Nom de la VM", default="api-demo")

    image_id = pick_image(token, ep)
    if not image_id: return
    flavor_id = pick_flavor(token, ep)
    if not flavor_id: return
    net_id = pick_network(token, ep)
    if not net_id: return

    ip_mode_dhcp = Confirm.ask("Adresse IP via DHCP ?", default=True)
    fixed_ip = None
    if not ip_mode_dhcp:
        fixed_ip = Prompt.ask("IP manuelle (ex: 192.168.1.50)")

    sg_ids = pick_secgroups(token, ep, project_id)
    spoofing = Confirm.ask("Activer IP spoofing (désactive port_security) ?", default=False)

    key_name = None
    if Confirm.ask("Associer une SSH keypair ?", default=True):
        key_name = pick_or_create_keypair(token, ep)

    user_data_b64 = None
    if Confirm.ask("Ajouter un cloud-init (user-data.yaml) ?", default=False):
        data = Path(Prompt.ask("Chemin du YAML", default="user-data.yaml")).read_bytes()
        user_data_b64 = base64.b64encode(data).decode()

    # Port
    try:
        port_id = create_port(token, ep, net_id, sg_ids, spoofing, fixed_ip)
    except Exception as e:
        console.print(f"[red]Erreur création du port: {e}[/red]"); return

    # Flavor disk
    fls = list_flavors(token, ep)
    flavor = next((f for f in fls if f["id"] == flavor_id), {})
    flavor_disk = int(flavor.get("disk", 0) or 0)

    try:
        if flavor_disk == 0:
            console.print("[yellow]Flavor avec disk=0 → boot depuis volume requis[/yellow]")
            img = get_image(token, ep, image_id)
            suggested = img.get("min_disk", 0) or (ceil_gib_from_bytes(img["size"]) if img.get("size") else 10)
            vol_size = IntPrompt.ask("Taille du volume root (GiB)", default=int(suggested))
            vol_id = create_boot_volume(token, ep, project_id, image_id, f"{name}-root", min_size_gb=vol_size)
            resp = create_server_from_volume(token, ep, name, flavor_id, port_id, vol_id, key_name, user_data_b64)
        else:
            nova = ep.get("compute")
            server = {"server":{"name":name,"imageRef":image_id,"flavorRef":flavor_id,"networks":[{"port":port_id}]}}
            if key_name: server["server"]["key_name"] = key_name
            if user_data_b64: server["server"]["user_data"] = user_data_b64
            r = POST(f"{nova}/servers", token, json=server, headers={"Content-Type":"application/json"})
            r.raise_for_status()
            resp = r.json()
        console.print("[green]VM création demandée[/green]")
        console.print(json.dumps(resp, indent=2))
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 403 and "zero disk" in e.response.text.lower():
            console.print("[yellow]Policy zéro-disk détectée → bascule auto vers boot-from-volume[/yellow]")
            img = get_image(token, ep, image_id)
            suggested = img.get("min_disk", 0) or (ceil_gib_from_bytes(img["size"]) if img.get("size") else 10)
            vol_size = IntPrompt.ask("Taille du volume root (GiB)", default=int(suggested))
            vol_id = create_boot_volume(token, ep, project_id, image_id, f"{name}-root", min_size_gb=vol_size)
            resp = create_server_from_volume(token, ep, name, flavor_id, port_id, vol_id, key_name, user_data_b64)
            console.print("[green]VM création demandée (volume-backed)[/green]")
            console.print(json.dumps(resp, indent=2))
        else:
            console.print(f"[red]Create VM error: {e}[/red]")

# ---------- Manage VM (Start/Reboot/Shutdown/Monitoring) ----------
def table_servers(servers: List[dict]) -> Table:
    tbl = Table(title="Mes VMs", box=box.ROUNDED)
    tbl.add_column("Idx"); tbl.add_column("Name"); tbl.add_column("Status"); tbl.add_column("ID")
    for i, s in enumerate(servers):
        tbl.add_row(str(i), s.get("name",""), s.get("status","?"), s["id"])
    return tbl

def server_action(token, ep, server_id: str, action: dict):
    nova = ep.get("compute")
    r = POST(f"{nova}/servers/{server_id}/action", token, json=action, headers={"Content-Type":"application/json"})
    if r.status_code not in (202, 204):
        r.raise_for_status()

def manage_vm(token, ep, project_id):
    sv = list_servers(token, ep)
    if not sv:
        console.print("[yellow]Aucune VM[/yellow]"); return
    console.print(table_servers(sv))
    idx = IntPrompt.ask("Indice de la VM", default=0)
    server = sv[idx]; sid = server["id"]; sname = server.get("name","")
    # sous-menu
    while True:
        console.print(Panel(f"[b]{sname}[/b] ({sid})", border_style="white"))
        tbl = Table(box=box.ROUNDED, show_header=False); tbl.add_column("Key"); tbl.add_column("Action")
        tbl.add_row("[green]1[/]", "START"); tbl.add_row("[green]2[/]", "REBOOT (SOFT)")
        tbl.add_row("[green]3[/]", "REBOOT (HARD)"); tbl.add_row("[green]4[/]", "SHUTDOWN")
        tbl.add_row("[green]5[/]", "Monitoring (live)"); 
        tbl.add_row("[green]6[/]", "Config VM"); tbl.add_row("[green]Q[/]", "Retour")       # <-- nouveau

        console.print(tbl)
        choice = Prompt.ask("Choix", choices=["1","2","3","4","5","6","Q"], default="Q", show_choices=False).upper()
        if choice == "Q": break
        try:
            if choice == "1":
                server_action(token, ep, sid, {"os-start": None})  # Nova os-start :contentReference[oaicite:3]{index=3}
                console.print("[green]Start demandé[/green]")
            elif choice == "2":
                server_action(token, ep, sid, {"reboot": {"type": "SOFT"}})  # reboot soft :contentReference[oaicite:4]{index=4}
                console.print("[green]Reboot (SOFT) demandé[/green]")
            elif choice == "3":
                server_action(token, ep, sid, {"reboot": {"type": "HARD"}})  # reboot hard :contentReference[oaicite:5]{index=5}
                console.print("[green]Reboot (HARD) demandé[/green]")
            elif choice == "4":
                server_action(token, ep, sid, {"os-stop": None})  # Nova os-stop :contentReference[oaicite:6]{index=6}
                console.print("[green]Shutdown demandé[/green]")
            elif choice == "5":
                show_vm_metrics(token, ep, sid, sname)
            elif choice == "6":
                show_vm_config(token, ep, project_id, sid, sname)
        except Exception as e:
            console.print(f"[red]Erreur action: {e}[/red]")

def gnocchi_endpoint(ep: Dict[str,str]) -> Optional[str]:
    for k in ("metric", "gnocchi"):
        if ep.get(k): return ep[k].rstrip("/")
    return None

def gnocchi_get_resource(token, gno_url: str, server_id: str) -> Optional[dict]:
    try:
        r = GET(f"{gno_url}/v1/resource/instance/{server_id}", token)
        if r.status_code == 200:
            return r.json()
        qry = {"=": {"original_resource_id": server_id}}
        r = GET(f"{gno_url}/v1/resource/instance?search={json.dumps(qry)}", token)
        if r.status_code == 200 and r.json():
            return r.json()[0]
    except requests.RequestException:
        return None
    return None

def gnocchi_last_measure(token, metric_id: str, gno_url: str, granularity=60) -> Optional[Tuple[str,float]]:
    try:
        now = datetime.datetime.utcnow()
        start = (now - datetime.timedelta(minutes=10)).isoformat(timespec="seconds") + "Z"
        r = GET(f"{gno_url}/v1/metric/{metric_id}/measures?granularity={granularity}&start={start}", token)
        if r.status_code != 200:
            return None
        data = r.json()
        if not data:
            return None
        ts, _, val = data[-1]
        return ts, float(val)
    except requests.RequestException:
        return None

METRIC_LABELS = [
    ("cpu_util", "CPU util", "%"),
    ("memory.usage", "RAM usage", "MB"),
    ("disk.read.bytes.rate", "Disk Read", "B/s"),
    ("disk.write.bytes.rate", "Disk Write", "B/s"),
    ("disk.latency.read", "Disk Read Lat", "ms"),
    ("disk.latency.write", "Disk Write Lat", "ms"),
    ("disk.latency.flush", "Disk Flush Lat", "ms"),
    ("network.incoming.bytes.rate", "Net In", "B/s"),
    ("network.outgoing.bytes.rate", "Net Out", "B/s"),
]

def nova_diagnostics(token, ep, server_id: str) -> Optional[dict]:
    # Nova diagnostics (peut exiger admin/owner selon policy) :contentReference[oaicite:2]{index=2}
    try:
        nova = ep.get("compute")
        # certaines installs exigent le header microversion récent ; on tente sans puis avec.
        r = GET(f"{nova}/servers/{server_id}/diagnostics", token)
        if r.status_code == 200:
            return r.json()
        r = requests.get(
            f"{nova}/servers/{server_id}/diagnostics",
            headers={"X-Auth-Token": token, "OpenStack-API-Version": "compute 2.48"},
            timeout=30, verify=VERIFY_TLS,
        )
        if r.status_code == 200:
            return r.json()
    except requests.RequestException:
        pass
    return None

def show_vm_metrics(token, ep, server_id: str, name: str):
    # 1) Essai Gnocchi
    gno = gnocchi_endpoint(ep)
    if gno:
        res = gnocchi_get_resource(token, gno, server_id)
        if res and isinstance(res.get("metrics", {}), dict):
            metrics_map: Dict[str,str] = res["metrics"]  # name -> id :contentReference[oaicite:3]{index=3}
            tbl = Table(title=f"Monitoring — {name}", box=box.ROUNDED)
            tbl.add_column("Métrique"); tbl.add_column("Valeur"); tbl.add_column("Unité"); tbl.add_column("Horodatage")
            for mname, label, unit in METRIC_LABELS:
                mid = metrics_map.get(mname)
                if not mid:
                    continue
                last = gnocchi_last_measure(token, mid, gno)
                if last:
                    ts, val = last
                    if mname == "memory.usage" and val > 1024: val = round(val / (1024*1024), 2)
                    tbl.add_row(label, f"{val:.2f}", unit, ts)
            if len(tbl.rows):
                console.print(tbl); return
            else:
                console.print("[yellow]Aucune mesure récente via Gnocchi[/yellow]")

    # 2) Fallback Nova diagnostics
    diag = nova_diagnostics(token, ep, server_id)
    if diag:
        tbl = Table(title=f"Diagnostics (Nova) — {name}", box=box.ROUNDED)
        tbl.add_column("Clé"); tbl.add_column("Valeur")
        # affiche un sous-ensemble utile si présent
        keys = ["cpu0_time", "cpu1_time", "memory", "memory-actual","vda_read","vda_read_req","vda_write","vda_write_req",
                "rx","rx_drop","rx_errors","tx","tx_drop","tx_errors"]
        for k in keys:
            if k in diag: tbl.add_row(k, str(diag[k]))
        # fallback: tout afficher si presque rien n’est map
        if len(tbl.rows) <= 2:
            for k,v in diag.items():
                tbl.add_row(str(k), str(v))
        console.print(tbl); return

    console.print("[yellow]Métriques indisponibles : ni Gnocchi (8041) ni diagnostics Nova accessibles pour ce projet.[/yellow]")

# ---------- Stats VM ----------
def show_vm_config(token, ep, project_id, server_id: str, name: str):
    nova = ep.get("compute").rstrip("/")
    neutron = ep.get("network").rstrip("/")
    cinder = (ep.get("volumev3") or ep.get("volumev2") or ep.get("volume")).rstrip("/")

    # ---- Détails serveur (flavor -> vCPU/RAM/disk local) ----
    svr = GET(f"{nova}/servers/{server_id}", token).json().get("server", {})
    flavor_id = (svr.get("flavor") or {}).get("id")
    vcpu = ram_mb = disk_local = "?"
    if flavor_id:
        fl = GET(f"{nova}/flavors/{flavor_id}", token).json().get("flavor", {})
        vcpu = fl.get("vcpus", "?")
        ram_mb = fl.get("ram", "?")
        disk_local = fl.get("disk", "?")

    # ---- Volumes attachés -> total (GB) ----
    attachments = GET(f"{nova}/servers/{server_id}/os-volume_attachments", token).json().get("volumeAttachments", [])
    total_vol_gb = 0
    for att in attachments:
        vid = att.get("volumeId")
        if not vid:
            continue
        r = GET(f"{cinder}/volumes/{vid}", token)
        if r.status_code not in (200, 203):
            r = GET(f"{cinder}/{project_id}/volumes/{vid}", token)
        v = r.json().get("volume", {})
        total_vol_gb += int(v.get("size", 0) or 0)

    # ---- Réseaux / IP / SG / spoof ----
    # Map SG id -> name (évite plein d'appels)
    all_sgs = {sg["id"]: sg.get("name", sg["id"]) for sg in list_secgroups(token, ep, project_id)}
    ports = GET(f"{neutron}/v2.0/ports?device_id={server_id}", token).json().get("ports", [])
    ips = []
    sg_names = set()
    spoof_on = False
    for p in ports:
        # IPs
        for fip in p.get("fixed_ips", []):
            ip = fip.get("ip_address")
            if ip:
                ips.append(ip)
        # SGs
        for sg_id in p.get("security_groups", []):
            sg_names.add(all_sgs.get(sg_id, sg_id))
        # spoofing
        pse = p.get("port_security_enabled", True)
        if pse is False:
            spoof_on = True

    ips_str = ", ".join(sorted(set(ips))) if ips else "-"
    sgs_str = ", ".join(sorted(sg_names)) if sg_names else "(default)"
    spoof_str = "ON" if spoof_on else "OFF"

    # ---- Rendu compact ----
    t = Table(title=f"Configuration — {name}", box=box.ROUNDED)
    t.add_column("Champ", style="cyan", no_wrap=True)
    t.add_column("Valeur", justify="right")
    t.add_row("vCPU", str(vcpu))
    t.add_row("RAM (MB)", str(ram_mb))
    t.add_row("Disque local (GB)", str(disk_local))
    t.add_row("Volumes attachés (GB total)", str(total_vol_gb))
    t.add_row("Adresse IP", ips_str)
    t.add_row("Security group(s)", sgs_str)
    t.add_row("IP spoof", spoof_str)

    console.print(Panel(t, border_style="magenta"))

# ---------- Suppression VM ----------
def delete_vm(token, ep):
    nova = ep.get("compute")
    sv = list_servers(token, ep)
    if not sv:
        console.print("[yellow]Aucune VM[/yellow]"); return
    console.print(table_servers(sv))
    idx = IntPrompt.ask("Indice à supprimer")
    server_id = sv[idx]["id"]
    r = DELETE(f"{nova}/servers/{server_id}", token)
    if r.status_code not in (204,202):
        console.print(f"[red]Delete VM error: {r.status_code} {r.text}[/red]"); return
    console.print("[green]VM supprimée (en cours)[/green]")

# ---------- UI ----------
ACTIONS = {
    "1": ("Créer une VM", lambda t,e,p: create_vm(t,e,p)),
    "2": ("Supprimer une VM", lambda t,e,p: delete_vm(t,e)),
    "3": ("Gérer les VMs (actions & monitoring)", lambda t,e,p: manage_vm(t,e,p)),
    "R": ("Rafraîchir dashboard", None),
    "Q": ("Quitter", None),
}

def show_actions_menu():
    tbl = Table(box=box.ROUNDED, expand=True, show_header=True, header_style="bold cyan")
    tbl.add_column("Touche", justify="center", style="bold")
    tbl.add_column("Action", style="white")
    for key, (label, _) in ACTIONS.items():
        tbl.add_row(f"[green]{key}[/]", label)
    return Panel(tbl, title="Actions", border_style="cyan")

def main_menu(token, ep, project_id):
    while True:
        console.clear()
        layout = Layout()
        layout.split_column(Layout(name="top", ratio=2), Layout(name="bottom", ratio=1))
        stats_panel = render_dashboard(gather_stats(token, ep, project_id))
        layout["top"].update(stats_panel)
        layout["bottom"].update(show_actions_menu())
        console.print(Panel(Align.center("[b]VHI Manager[/b]"), border_style="white"))
        console.print(layout)
        choice = Prompt.ask("[bold]Choix[/bold]", choices=list(ACTIONS.keys()), default="R", show_choices=False).upper()
        if choice == "Q": break
        if choice == "R": continue
        label, handler = ACTIONS[choice]
        try:
            if handler: handler(token, ep, project_id)
        except Exception as e:
            console.print(f"[red]Erreur ({label}) : {e}[/red]")
        Prompt.ask("[dim]Entrée pour revenir au menu[/dim]", default="")

# ---------- Entrée ----------
def main():
    console.rule("[bold]Connexion VHI")
    token, ep, project_id = keystone_auth()
    console.print("[green]Authentifié[/green]")
    main_menu(token, ep, project_id)

if __name__ == "__main__":
    main()

