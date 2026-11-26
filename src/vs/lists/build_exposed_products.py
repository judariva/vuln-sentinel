"""Genera `config/exposed-products.yaml` a partir de CISA KEV y cvelistV5 (PLAN.md §5.2, F1a-0, R7).

Uso:
    uv run python -m vs.lists.build_exposed_products --cutoff 2026-11-26 [--input kev.json]

Sin `--input`, descarga el catálogo KEV a `.cache/lists/` y los registros cvelistV5 de los CVE de
los productos incluidos a `.cache/lists/cvelistV5/`. Con `--offline`, usa solo lo que ya esté en
caché. La salida depende solo de los bytes de entrada y de la fecha de corte.

El criterio v2 completo está en `HEADER` (va en la cabecera del YAML). Resumen:
1. Ventana: entradas de KEV con `dateAdded` en (corte - 36 meses, corte].
2. Canonicalización (reglas `CANON_RULES`): fabricante, «X and Y», abreviaturas, sufijos genéricos,
   ediciones, fusiones por abreviatura o sufijo y producto genérico resuelto por el nombre.
3. Categoría por producto canónico: palabras clave de tipo y de marca (`TYPE_RULES`,
   `BRAND_RULES`) sobre fabricante y nombres; si no hay, palabras de tipo en las descripciones de
   sus entradas (mayoría). Varias categorías por nombre → la primera de `PRECEDENCE`.
4. Umbral por familia (`THRESHOLDS`): el fabricante suma al menos ese número de entradas de esa
   categoría en la ventana (2 en firewall, vpn, load-balancer y remote-access; 3 en el resto).
5. CPE y pares del CNA desde cvelistV5 (`vs.lists.cvelist`).
6. Pata de despliegue (`vs.lists.deployment`, `--survey`): web-proxy desde Common Crawl
   (`vs.lists.deployment_cc`); identidad/SSH pendiente.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from vs.lists import cvelist, deployment, deployment_cna
from vs.lists.common import ROOT, dump_yaml, fetch, months_before, parse_date, sha256_bytes, slug

GENERATOR = "vs.lists.build_exposed_products"
GENERATOR_VERSION = "4.0.0"
# v4 (decisión de Juan del 2026-11-26, T14): la pata de despliegue entra en `producto_expuesto` con
# sus pares del CNA y sus CPE (`vs.lists.deployment_cna`). Las reglas de los productos de KEV no
# cambian (RULES_VERSION sigue en 3).
CRITERION_VERSION = 4
RULES_VERSION = 3
WINDOW_MONTHS = 36
# Umbral por familia (criterio v3, decisión de Juan del 2026-11-26): 2 para los productos de borde
# de red y de acceso remoto, 3 para el resto.
THRESHOLD_DEFAULT = 3
THRESHOLD_BY_FAMILY = {"firewall": 2, "vpn": 2, "load-balancer": 2, "remote-access": 2}
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUTPUT = ROOT / "config" / "exposed-products.yaml"

# Categorías del criterio v1 (F0). No cambian en v2.
CATEGORIES = (
    "vpn",
    "firewall",
    "load-balancer",
    "web-proxy",
    "identity",
    "hypervisor",
    "cicd",
    "mail",
    "file-transfer",
    "remote-access",
)
THRESHOLDS = {c: THRESHOLD_BY_FAMILY.get(c, THRESHOLD_DEFAULT) for c in CATEGORIES}
THRESHOLD_BY_FAMILY_TEXT = ", ".join(f"{c} {n}" for c, n in THRESHOLD_BY_FAMILY.items())
# Si el nombre de un producto casa con varias categorías, gana la primera de esta lista (de la
# función más específica a la más general).
PRECEDENCE = (
    "vpn",
    "remote-access",
    "identity",
    "load-balancer",
    "firewall",
    "file-transfer",
    "mail",
    "cicd",
    "hypervisor",
    "web-proxy",
)

# Reglas v2. Palabras de TIPO de producto: se aplican al nombre y, si el nombre no da categoría, a
# las descripciones de KEV. Sin distinguir mayúsculas y con límites de palabra.
TYPE_RULES: dict[str, tuple[str, ...]] = {
    "vpn": (
        r"vpn",
        r"ssl[- ]?vpn",
        r"secure access",
        r"secure mobile access",
        r"access gateway",
        r"remote access vpn",
    ),
    "firewall": (
        r"firewalls?",
        r"waf",
        r"web application firewall",
        r"threat defense",
        r"(?<!email )security gateways?",
        r"utm",
        r"next[- ]generation firewall",
        r"ngfw",
    ),
    "load-balancer": (
        r"load[- ]balanc\w*",
        r"adc",
        r"application delivery\w*",
        r"traffic manager",
    ),
    "web-proxy": (r"proxy", r"reverse proxy", r"web server", r"http server", r"\w*httpd"),
    "identity": (
        r"identity",
        r"identity provider",
        r"sso",
        r"single sign[- ]on",
        r"access manager",
        r"active directory",
        r"federation",
        r"adfs",
        r"radius",
    ),
    "hypervisor": (r"hypervisor", r"virtualization", r"virtual machine manager"),
    "cicd": (
        r"ci/cd",
        r"continuous integration",
        r"build server",
        r"devops",
        r"artifact repository",
        r"repository manager",
    ),
    # v3: `\w*mail\w*` casaba nombres de función en las descripciones («TestEmail» de Reolink). Pasa
    # a NAME_RULES (solo nombre de producto); aquí quedan palabras enteras.
    "mail": (r"e-?mail", r"webmail", r"mail", r"groupware", r"mail server"),
    "file-transfer": (
        r"file transfer",
        r"managed file transfer",
        r"\w*ftp\w*",
        r"mft",
        r"file sharing",
        r"file server",
    ),
    "remote-access": (
        r"remote access",
        r"remote support",
        r"remote desktop",
        r"remote management",
        r"remote monitoring",
        r"rmm",
    ),
}

# Palabras de MARCA: nombres de producto de borde usados como tipo (respuesta (3) de Juan: se
# mantienen; ampliadas en v2 para los productos de borde que KEV nombra sin palabra de tipo). Solo
# se aplican al nombre del producto, nunca a las descripciones.
BRAND_RULES: dict[str, tuple[str, ...]] = {
    "vpn": (
        r"connect secure",
        r"policy secure",
        r"zta gateways?",
        r"globalprotect",
        r"sonicwall sma ?\d*",
        r"netscaler gateway",
        r"arrayos",
    ),
    "firewall": (
        r"pan-os",
        r"fortios",
        r"fortigate",
        r"fortiweb",
        r"sonicos",
        r"firebox",
        r"screenos",
        r"cyberoamos",
        r"adaptive security appliance",
        r"firepower",
    ),
    "load-balancer": (r"big-ip", r"loadmaster", r"netscaler"),
    "web-proxy": (r"fortiproxy",),
    "identity": (),
    "hypervisor": (r"esxi?", r"vcenter", r"vsphere", r"hyper-v"),
    "cicd": (r"teamcity", r"jenkins", r"gitlab", r"artifactory", r"gitea", r"gogs"),
    "mail": (r"exchange server", r"zimbra"),
    "file-transfer": (r"serv-u", r"centrestack", r"triofox", r"aspera faspex", r"moveit"),
    "remote-access": (r"screenconnect", r"simplehelp", r"n-central"),
}

# Palabras de TIPO que solo se aplican al NOMBRE del producto (v3): palabras compuestas cuyo
# significado depende de que sean un nombre de producto y no una función o un parámetro citado en
# la descripción.
NAME_RULES: dict[str, tuple[str, ...]] = {c: () for c in CATEGORIES} | {
    "mail": (r"\w*mail\w*",),
}

# Reglas de canonicalización v2 (documentadas en el YAML; cambiar una exige subir RULES_VERSION).
CANON_RULES = [
    "R1 fabricante: si el producto de KEV empieza por el nombre de OTRO fabricante de KEV "
    "(catálogo completo), el producto pasa a ese fabricante sin el prefijo (p. ej. «Broadcom | "
    "VMware vCenter» → VMware vCenter). Cada reasignación se lista en `canonicalization`.",
    "R2 «X and Y», «X, Y, and Z» → un producto por parte. Una parte de una sola palabra "
    "genérica (manager, gateway, controller, server, client, console, director, router, "
    "conductor) hereda el prefijo de la primera parte si esta acaba en palabra genérica o en "
    "sigla («NetScaler ADC and Gateway» → NetScaler ADC, NetScaler Gateway). Una parte que solo "
    "nombra el despliegue (server, data center, cloud, on-prem) se descarta («Jira Server and "
    "Data Center» → Jira Server). v3: si alguna parte es de una sola palabra (sin abreviatura) y "
    "ninguna parte es un producto que el fabricante tiene solo en otra entrada de la ventana, ni "
    "el nombre del fabricante, ni es solo de edición (R4), la «and» es parte del nombre y no se "
    "separa («Backup and "
    "Replication», «Utah, Vancouver, and Washington DC Now Platform»).",
    "R3 el contenido entre paréntesis es una abreviatura del producto («Adaptive Security "
    "Appliance (ASA)»): se guarda aparte y no forma parte de la clave.",
    "R4 se quita el nombre del propio fabricante al principio («WordPress Core» → Core), salvo que "
    "el producto se llame igual que el fabricante o solo quede server/software. Un nombre que solo "
    "tiene palabras de edición (community, enterprise, edition(s), ce, ee) es el producto con el "
    "nombre del fabricante.",
    "R5 clave = nombre normalizado sin los sufijos genéricos finales (software, device(s), "
    "series); «appliances» y «gateways» (v3) se normalizan al singular.",
    "R6 producto genérico: si el producto de KEV es el nombre del fabricante y ese fabricante "
    "tiene otros productos en la ventana, o empieza por «Multiple», se busca al principio del "
    "nombre de la vulnerabilidad un producto conocido del fabricante (el más largo). Si no hay, "
    "«Multiple…» va a `needs_review` si casa alguna regla y a `out_of_scope` si no.",
    "R7 fusiones dentro de un fabricante: claves que comparten abreviatura; clave que acaba en "
    "«-<abreviatura>» o «-<otra clave>»; «X» y «X-server». La clave canónica es la de más entradas "
    "(a igualdad, la más corta y luego la alfabética).",
]

INHERIT_WORDS = frozenset(
    {"manager", "gateway", "controller", "server", "client", "console", "director", "router"}
    | {"conductor"}
)
SUFFIX_WORDS = ("software", "device", "devices", "series")
PLURALS = {"appliances": "appliance", "gateways": "gateway"}
DEPLOYMENT_TOKENS = frozenset({"server", "data", "center", "cloud", "on", "prem", "premise"})
EDITION_TOKENS = frozenset({"community", "enterprise", "edition", "editions", "ce", "ee"})
KEEP_IF_ONLY = frozenset({"server", "servers", "software"})
STOP_TOKENS = frozenset(
    {"and", "the", "for", "of", "software", "server", "servers", "appliance", "appliances"}
    | {"device", "devices", "series", "edition", "editions", "platform", "multiple", "products"}
    | {"firmware", "for"}
)
SPLIT_RE = re.compile(r"\s*,\s*(?:and\s+)?|\s+and\s+", re.IGNORECASE)
PAREN_RE = re.compile(r"\(([^()]*)\)")
MULTIPLE_RE = re.compile(r"^multiple\b", re.IGNORECASE)


def _compile(rules: dict[str, tuple[str, ...]]) -> dict[str, list[tuple[str, re.Pattern]]]:
    return {
        cat: [(p, re.compile(rf"(?<![a-z0-9]){p}(?![a-z0-9])", re.IGNORECASE)) for p in pats]
        for cat, pats in rules.items()
    }


_TYPE = _compile(TYPE_RULES)
_NAME = _compile(NAME_RULES)
_BRAND = _compile(BRAND_RULES)

HEADER = f"""\
Productos expuestos a Internet de uso masivo (PLAN.md §5.2, `producto_expuesto`).

FICHERO GENERADO por {GENERATOR}
(src/vs/lists/build_exposed_products.py). No se edita a mano: se cambia el criterio o las reglas
en el script, se regenera y se revisa por PR (P-10). `manual_changes` solo como excepción, con
motivo y PR.

CRITERIO v{CRITERION_VERSION}, reglas v{RULES_VERSION} (el criterio de partida se fijó en F0, antes
de mirar ningún caso; R7):
  1. Entradas de CISA KEV con `dateAdded` en los últimos {WINDOW_MONTHS} meses hasta `cutoff_date`.
  2. Canonicalización: un producto por (fabricante, producto) con las variantes de KEV en
     `aliases`, según las reglas de `canonicalization.rules`. Cada reasignación y fusión aplicada
     se lista en `canonicalization`.
  3. Categoría (`rules`): palabras de tipo (`type`), de tipo solo para nombres (`name`) y de marca
     (`brand`) sobre el fabricante y los nombres del producto canónico. Si casan varias, gana la
     primera de `precedence`. Si no casa ninguna, SOLO las palabras de tipo (`type`) sobre
     vulnerabilityName y shortDescription de sus entradas: la
     categoría más frecuente, si es única y casa en al menos la mitad de las entradas.
  4. Entra en `products` si su fabricante suma al menos `threshold[categoría]` entradas de KEV de
     esa categoría en la ventana (una entrada cuenta una vez por categoría). Si no,
     `below_threshold`. Umbral por familia (v3, decisión de Juan del 2026-11-26):
     {THRESHOLD_BY_FAMILY_TEXT}; {THRESHOLD_DEFAULT} para el resto.
  5. `needs_review` (NUNCA `products`), con su motivo: productos genéricos de KEV («Multiple
     Products») que casan alguna regla en su nombre o alguna palabra de tipo en sus descripciones
     (v3: antes también las de marca), y empates en las
     descripciones. Si ninguna regla casa por nombre y ninguna categoría llega a la mitad de las
     descripciones: `out_of_scope` (solo se listan los ids).
  6. `cpe` y `cna` salen de los registros cvelistV5 de las entradas del producto: prefijos
     cpe:2.3:<part>:<vendor>:<product> y pares vendor/product del CNA cuyos términos casan con los
     nombres del producto (regla «tokens»); si ninguno casa, los que aparecen en al menos la mitad
     de sus registros y comparten un término o salen de entradas de un solo producto (regla
     «majority»). Si no queda ninguno, `cpe_missing_reason` dice por qué.
  7. Pata de despliegue («los servidores web/proxy y de identidad de mayor despliegue»): ver
     `deployment_leg`. N y la fuente se fijaron antes de ver ningún resultado. v4: cada entrada
     lleva sus pares del CNA y sus prefijos CPE (`deployment_leg.pairs_method`: registros
     cvelistV5 de los últimos 36 meses cuyo `product` o CPE contiene el nombre) y las reglas la
     cargan como producto (`producto_expuesto`). Sin pares ni CPE, no casa nada.

Formato de cada producto:
  - id: estable (fabricante--producto canónicos), nunca se reutiliza
    category / category_source (name | descriptions) / matched (reglas que casaron)
    vendor / product: forma más frecuente; names: nombres canónicos; abbreviations
    aliases: [{{vendor, product}} tal como aparecen en KEV]
    cna: [{{vendor, product}} tal como aparecen en cvelistV5]; cna_missing_reason si vacío
    cpe: [prefijos cpe:2.3:<part>:<vendor>:<product>]; cpe_rule; cpe_missing_reason si vacío
    purl: [purl sin versión] (vacío en v2: los productos de borde no tienen purl)
    evidence: entradas de KEV que justifican el alta
"""


# --- reglas -------------------------------------------------------------------------------------


def classify(text: str, brand: bool = True) -> list[str]:
    """Categorías cuyas reglas casan con `text`, en el orden de CATEGORIES.

    `brand=True`: `text` es un nombre de producto (tipo, solo nombre y marca). `brand=False`: es
    una descripción (solo tipo).
    """
    tables = [_TYPE, _NAME, _BRAND] if brand else [_TYPE]
    return [c for c in CATEGORIES if any(p.search(text) for t in tables for _, p in t[c])]


def matched_rules(text: str) -> list[str]:
    """Reglas que casan con `text`, como «tipo:categoría:patrón»."""
    out = []
    for kind, table in (("type", _TYPE), ("name", _NAME), ("brand", _BRAND)):
        for cat in CATEGORIES:
            out += [f"{kind}:{cat}:{raw}" for raw, p in table[cat] if p.search(text)]
    return out


def pick(cats: list[str]) -> str:
    return min(cats, key=PRECEDENCE.index)


# --- canonicalización ---------------------------------------------------------------------------


def _toks(text: str) -> list[str]:
    s = slug(text)
    return s.split("-") if s else []


def split_product(product: str, known: frozenset[str] = frozenset()) -> list[str]:
    """R2: «X and Y» → [X, Y]; una parte genérica de una palabra hereda el prefijo de la primera.

    `known`: claves (R5) de los productos que el fabricante tiene solos en otras entradas. Si queda
    alguna parte de una palabra sin abreviatura y ninguna de ellas está en `known`, no se separa.
    """
    parts = [p.strip() for p in SPLIT_RE.split(product) if p and p.strip()]
    if len(parts) < 2:
        return [product]
    out = []
    first = parts[0].split() if parts else []
    head_last = first[-1] if first else ""
    inheritable = len(first) >= 2 and (
        head_last.lower() in INHERIT_WORDS or (head_last.isupper() and len(head_last) >= 2)
    )
    for i, part in enumerate(parts):
        words = part.split()
        if i > 0 and len(words) == 1 and words[0].lower() in INHERIT_WORDS and inheritable:
            part = " ".join([*first[:-1], words[0]])
        elif i > 0 and set(_toks(part)) <= DEPLOYMENT_TOKENS:
            continue
        out.append(part)
    single = [p for p in out if len(p.split()) == 1 and not PAREN_RE.search(p)]

    def resolvable(p: str) -> bool:
        toks = set(_toks(parse_part(p)[0]))
        return key_of(parse_part(p)[0]) in known or bool(toks and toks <= EDITION_TOKENS)

    if len(out) > 1 and single and not any(resolvable(p) for p in out):
        return [product]
    return out or [product]


def parse_part(part: str) -> tuple[str, list[str]]:
    """R3: (nombre sin paréntesis, abreviaturas)."""
    abbrs = [a.strip() for a in PAREN_RE.findall(part) if a.strip()]
    name = " ".join(PAREN_RE.sub(" ", part).split())
    return name or part, abbrs


def strip_vendor(name: str, vendor_names: list[str], vendor_display: str) -> str:
    """R4: quita el fabricante al principio; nombres solo de edición → nombre del fabricante."""
    if set(_toks(name)) and set(_toks(name)) <= EDITION_TOKENS:
        return vendor_display
    if any(slug(name) == slug(v) for v in vendor_names if v):
        return name
    for vn in sorted({v for v in vendor_names if v}, key=len, reverse=True):
        m = re.match(rf"^{re.escape(vn)}\s+(.+)$", name, re.IGNORECASE)
        if not m:
            continue
        rest = m.group(1).strip()
        rest_toks = set(_toks(rest))
        if rest_toks and rest_toks <= EDITION_TOKENS:
            return vendor_display
        if not rest_toks or rest_toks <= KEEP_IF_ONLY:
            return name
        return rest
    return name


def key_of(name: str) -> str:
    """R5: clave sin sufijos genéricos finales."""
    toks = [PLURALS.get(t, t) for t in _toks(name)]
    while len(toks) > 1 and toks[-1] in SUFFIX_WORDS:
        toks.pop()
    return "-".join(toks)


def _vendor_variants(vendor: str) -> list[str]:
    base = " ".join(PAREN_RE.sub(" ", vendor).split())
    out = [vendor, base]
    out += [a.strip() for a in PAREN_RE.findall(vendor)]
    first = base.split()[0] if base.split() else ""
    if len(first) >= 4:
        out.append(first)
    return out


def _display(counter: Counter) -> str:
    """Forma más frecuente; a igualdad, la menor en orden alfabético."""
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


class _UF:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def canonicalize(entries: list[dict], all_vendors: dict[str, str]) -> dict:
    """Asigna a cada entrada sus productos canónicos. Devuelve productos y registro de cambios.

    `all_vendors`: slug → nombre de fabricante (forma más frecuente en todo el catálogo).
    """
    reassign_log: list[dict] = []
    resolved_log: list[dict] = []
    # Paso 1: fabricante y partes de cada entrada.
    parsed = []  # (entry, vkey, vendor_display, [(key, name, abbrs)], generic)
    vendor_by_len = sorted(all_vendors.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    stage1 = []  # (entry, vendor KEV, vkey, vendor_display, producto tras R1)
    for e in entries:
        vendor, product = e["vendorProject"].strip(), e["product"].strip()
        vkey, vdisp = slug(vendor), vendor
        for okey, oname in vendor_by_len:
            if okey == vkey or len(oname) < 3:
                continue
            m = re.match(rf"^{re.escape(oname)}\s+(\S.*)$", product, re.IGNORECASE)
            if m:
                reassign_log.append(
                    {
                        "cve": e["cveID"],
                        "kev": f"{vendor} | {product}",
                        "to_vendor": oname,
                        "rule": "R1",
                    }
                )
                vkey, vdisp, product = okey, oname, m.group(1).strip()
                break
        stage1.append((e, vendor, vkey, vdisp, product))
    # R2 v3: productos que cada fabricante tiene solos (sin «and» ni comas) en la ventana.
    # El nombre del propio fabricante cuenta como producto suyo («MongoDB and MongoDB Server»).
    alone: dict[str, set[str]] = defaultdict(set)
    for _e, _vendor, vkey, _vdisp, _product in stage1:
        alone[vkey].add(vkey)
    for _e, vendor, vkey, vdisp, product in stage1:
        if len([p for p in SPLIT_RE.split(product) if p and p.strip()]) == 1:
            name, abbrs = parse_part(product)
            variants = [*_vendor_variants(vdisp), *_vendor_variants(vendor)]
            alone[vkey].add(key_of(name))
            alone[vkey].add(key_of(strip_vendor(name, variants, vdisp)))
            alone[vkey].update(slug(a) for a in abbrs if slug(a))
    for e, vendor, vkey, vdisp, product in stage1:
        generic = bool(MULTIPLE_RE.match(product)) or slug(product) == vkey
        parts = []
        for raw in split_product(product, frozenset(alone[vkey])):
            name, abbrs = parse_part(raw)
            name = strip_vendor(name, [*_vendor_variants(vdisp), *_vendor_variants(vendor)], vdisp)
            parts.append((key_of(name), name, abbrs))
        parsed.append([e, vkey, vdisp, parts, generic])

    # Paso 2 (R6): producto genérico → producto conocido del fabricante por el nombre.
    known: dict[str, set[str]] = defaultdict(set)
    for _e, vkey, _vd, parts, generic in parsed:
        if not generic:
            known[vkey].update(k for k, _n, _a in parts if k != vkey)
    for item in parsed:
        e, vkey, vdisp, parts, generic = item
        if not generic or not (slug(e["product"]) == vkey or MULTIPLE_RE.match(parts[0][1])):
            continue
        name = e.get("vulnerabilityName", "")
        for vn in sorted(set(_vendor_variants(vdisp) + _vendor_variants(e["vendorProject"]))):
            name = re.sub(rf"^{re.escape(vn)}\s+", "", name, flags=re.IGNORECASE) if vn else name
        s = slug(name)
        cands = [k for k in known[vkey] if s == k or s.startswith(k + "-")]
        if cands:
            best = sorted(cands, key=lambda k: (-len(k), k))[0]
            resolved_log.append(
                {
                    "cve": e["cveID"],
                    "kev": f"{e['vendorProject'].strip()} | {e['product'].strip()}",
                    "to": f"{vkey}--{best}",
                    "rule": "R6",
                }
            )
            item[3] = [(best, None, [])]
            item[4] = False
        elif not MULTIPLE_RE.match(parts[0][1]):
            item[4] = False  # producto con el nombre del fabricante: es un producto normal

    # Paso 3 (R7): fusiones dentro de cada fabricante.
    count: Counter = Counter()
    abbr_of: dict[tuple[str, str], set[str]] = defaultdict(set)
    keys_by_vendor: dict[str, set[str]] = defaultdict(set)
    for _e, vkey, _vd, parts, _generic in parsed:
        for k, _n, abbrs in parts:
            keys_by_vendor[vkey].add(k)
            count[(vkey, k)] += 1
            for a in abbrs:
                if slug(a):
                    abbr_of[(vkey, slug(a))].add(k)
    uf = _UF()
    merge_rule: dict[tuple[str, str], str] = {}
    for vkey, keys in keys_by_vendor.items():
        for k in keys:
            uf.find(f"{vkey}|{k}")
        for (av, a), ks in abbr_of.items():
            if av != vkey:
                continue
            ks = sorted(ks)
            for k in ks[1:]:
                uf.union(f"{vkey}|{ks[0]}", f"{vkey}|{k}")
                merge_rule[(vkey, k)] = merge_rule[(vkey, ks[0])] = "R7 abreviatura"
            for k in keys:
                if k == a or k.endswith("-" + a):
                    uf.union(f"{vkey}|{k}", f"{vkey}|{ks[0]}")
                    merge_rule.setdefault((vkey, k), "R7 abreviatura")
        for k1 in keys:
            for k2 in keys:
                if k1 != k2 and (k1.endswith("-" + k2) or k1 == k2 + "-server"):
                    uf.union(f"{vkey}|{k1}", f"{vkey}|{k2}")
                    merge_rule.setdefault((vkey, k1), "R7 sufijo")
                    merge_rule.setdefault((vkey, k2), "R7 sufijo")
    groups: dict[str, list[str]] = defaultdict(list)
    for vkey, keys in keys_by_vendor.items():
        for k in keys:
            groups[uf.find(f"{vkey}|{k}")].append(k)
    rep_of: dict[tuple[str, str], str] = {}
    merges = []
    for root, ks in groups.items():
        vkey = root.split("|", 1)[0]
        rep = sorted(ks, key=lambda k: (-count[(vkey, k)], len(k), k))[0]
        for k in ks:
            rep_of[(vkey, k)] = rep
        if len(ks) > 1:
            merges.append(
                {
                    "id": f"{vkey}--{rep}",
                    "merged": sorted(ks),
                    "rules": sorted({merge_rule.get((vkey, k), "R7") for k in ks if k != rep}),
                }
            )

    products: dict[tuple[str, str], dict] = {}
    for e, vkey, vdisp, parts, generic in parsed:
        n_parts = len({rep_of[(vkey, k)] for k, _n, _a in parts})
        for k, name, abbrs in parts:
            rep = rep_of[(vkey, k)]
            p = products.setdefault(
                (vkey, rep),
                {
                    "vendor": Counter(),
                    "product": Counter(),
                    "names": set(),
                    "abbrs": set(),
                    "pairs": set(),
                    "entries": {},
                    "alone": set(),
                    "generic": False,
                },
            )
            p["vendor"][vdisp] += 1
            if name:
                p["product"][name] += 1
                p["names"].add(name)
            p["abbrs"].update(abbrs)
            p["pairs"].add((e["vendorProject"].strip(), e["product"].strip()))
            p["entries"][e["cveID"]] = e
            if n_parts == 1:
                p["alone"].add(e["cveID"])
            p["generic"] = p["generic"] or generic
    for p in products.values():
        if not p["product"]:  # solo entradas resueltas por R6 sin nombre propio
            p["product"][next(iter(sorted(p["pairs"])))[1]] += 1
    return {
        "products": products,
        "log": {
            "rules": CANON_RULES,
            "vendor_reassignments": sorted(reassign_log, key=lambda r: r["cve"]),
            "resolved_generic": sorted(resolved_log, key=lambda r: r["cve"]),
            "merges": sorted(merges, key=lambda m: m["id"]),
        },
    }


# --- CPE y pares del CNA ------------------------------------------------------------------------


def _sig(tokens: list[str], vendor_tokens: set[str]) -> frozenset[str]:
    t = {x for x in tokens if x not in STOP_TOKENS}
    rest = t - vendor_tokens
    return frozenset(rest or t)


def _cpe_tokens(prefix: str) -> tuple[set[str], list[str]]:
    _cpe, _v, _part, vendor, product = prefix.split(":")
    return set(re.split(r"[_\-.]+", vendor)), [x for x in re.split(r"[_\-.]+", product) if x]


def _matches(cand: frozenset[str], names: list[frozenset[str]]) -> bool:
    return bool(cand) and any(n and (n <= cand or cand <= n) for n in names)


def match_cpe(p: dict, vkey: str, parsed: dict[str, dict]) -> dict:
    """Regla 6 del criterio: CPE y pares del CNA del producto a partir de sus registros."""
    vtoks = set(vkey.split("-")) | {t for v in p["vendor"] for t in _toks(v)}
    # Solo nombres canónicos (ya separados por R2): el nombre crudo de KEV («ASA and FTD») casaría
    # con los CPE de los dos productos.
    all_names = sorted(p["names"] | p["abbrs"]) or [_display(p["product"])]
    names = [_sig(_toks(n), vtoks) for n in all_names]
    name_tokens = set().union(*names) if names else set()
    cves = sorted(c for c in p["entries"] if c in parsed)
    if not cves:
        return {
            "cpe": [],
            "cna": [],
            "cpe_rule": None,
            "cpe_missing_reason": "sin registros cvelistV5 para sus CVE",
        }

    def pick_items(items_by_cve: dict[str, list], tokens_of) -> tuple[list, str | None]:
        direct = sorted({i for c in cves for i in items_by_cve[c] if _matches(tokens_of(i), names)})
        if direct:
            return direct, "tokens"
        freq = Counter(i for c in cves for i in set(items_by_cve[c]))
        alone = {i for c in cves if c in p["alone"] for i in items_by_cve[c]}
        maj = sorted(
            i
            for i, n in freq.items()
            if 2 * n >= len(cves) and (tokens_of(i) & name_tokens or i in alone)
        )
        return maj, ("majority" if maj else None)

    def cpe_toks(prefix: str) -> frozenset[str]:
        cv, cp = _cpe_tokens(prefix)
        return _sig(cp, cv | vtoks)

    def cna_toks(pair: tuple[str, str]) -> frozenset[str]:
        return _sig(_toks(pair[1]), set(_toks(pair[0])) | vtoks)

    cpe, cpe_rule = pick_items({c: parsed[c]["cpe"] for c in cves}, cpe_toks)
    cna, _rule = pick_items({c: [tuple(x) for x in parsed[c]["cna"]] for c in cves}, cna_toks)
    out = {"cpe": cpe, "cna": [{"vendor": v, "product": q} for v, q in cna], "cpe_rule": cpe_rule}
    if not cna:
        has_pairs = any(parsed[c]["cna"] for c in cves)
        out["cna_missing_reason"] = (
            "los registros traen pares del CNA, pero ninguno casa con los nombres del producto"
            if has_pairs
            else "el CNA publica vendor/product «n/a» o vacíos en todos sus registros"
        )
    if not cpe:
        has_any = any(parsed[c]["cpe"] for c in cves)
        out["cpe_missing_reason"] = (
            "los registros traen CPE, pero ninguno casa con los nombres del producto"
            if has_any
            else "los registros cvelistV5 no traen CPE (ni el CNA ni el ADP)"
        )
    return out


# --- construcción -------------------------------------------------------------------------------


def _in_window(kev: dict, cutoff: dt.date) -> tuple[list[dict], dt.date]:
    start = months_before(cutoff, WINDOW_MONTHS)
    out = []
    for e in kev["vulnerabilities"]:
        added = parse_date(e.get("dateAdded"))
        if added is not None and start < added <= cutoff:
            out.append(e)
    return sorted(out, key=lambda e: e["cveID"]), start


def _all_vendors(kev: dict) -> dict[str, str]:
    forms: dict[str, Counter] = defaultdict(Counter)
    for e in kev["vulnerabilities"]:
        v = e["vendorProject"].strip()
        forms[slug(v)][v] += 1
    return {k: _display(c) for k, c in forms.items() if k}


def product_text(p: dict) -> str:
    """Texto al que se aplican las reglas por nombre: «fabricante nombre» por cada nombre."""
    vendors = sorted(p["vendor"])
    names = sorted(p["names"] | p["abbrs"]) or [_display(p["product"])]
    return " | ".join(f"{v} {n}" for v in vendors for n in names)


def categorize(p: dict) -> dict:
    """Categoría de un producto canónico (puntos 3 y 5 del criterio)."""
    text = product_text(p)
    entries = list(p["entries"].values())
    if p["generic"]:
        descs = [
            f"{e.get('vulnerabilityName', '')} {e.get('shortDescription', '')}" for e in entries
        ]
        # v3: en las descripciones solo valen las palabras de tipo, como en el resto del criterio.
        hits = sorted({c for d in descs for c in classify(d, False)} | set(classify(text)))
        if hits:
            return {"status": "review", "reason": "producto genérico en KEV", "matched": hits}
        return {"status": "out"}
    cats = classify(text)
    if cats:
        return {
            "status": "ok",
            "category": pick(cats),
            "source": "name",
            "matched": matched_rules(text),
        }
    counts: Counter = Counter()
    for e in entries:
        counts.update(
            classify(f"{e.get('vulnerabilityName', '')} {e.get('shortDescription', '')}", False)
        )
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    if not ranked or 2 * ranked[0][1] < len(entries):
        return {"status": "out"}  # ninguna categoría llega a la mitad de las entradas
    best, n = ranked[0]
    if len(ranked) > 1 and ranked[1][1] == n:
        return {
            "status": "review",
            "reason": f"empate en las descripciones: {dict(ranked)}",
            "matched": [f"descriptions:{c}:{k}/{len(entries)}" for c, k in ranked],
        }
    return {
        "status": "ok",
        "category": best,
        "source": "descriptions",
        "matched": [f"descriptions:{best}:{n}/{len(entries)}"],
    }


def select(kev_bytes: bytes, cutoff: dt.date) -> dict:
    """Pasos 1–5 del criterio (sin cvelistV5). Lo usan `build` y el `main` para saber qué bajar."""
    kev = json.loads(kev_bytes)
    entries, start = _in_window(kev, cutoff)
    canon = canonicalize(entries, _all_vendors(kev))
    products = canon["products"]
    cat_of = {key: categorize(p) for key, p in products.items()}
    vendor_cat: dict[tuple[str, str], set[str]] = defaultdict(set)
    for (vkey, _k), p in products.items():
        c = cat_of[(vkey, _k)]
        if c["status"] == "ok":
            vendor_cat[(vkey, c["category"])].update(p["entries"])
    return {
        "kev": kev,
        "start": start,
        "entries": entries,
        "canon": canon,
        "cat_of": cat_of,
        "vendor_cat": {k: len(v) for k, v in vendor_cat.items()},
    }


def included_cves(kev_bytes: bytes, cutoff: dt.date) -> list[str]:
    sel = select(kev_bytes, cutoff)
    out = set()
    for key, p in sel["canon"]["products"].items():
        c = sel["cat_of"][key]
        cat = c.get("category")
        if c["status"] == "ok" and sel["vendor_cat"][(key[0], cat)] >= THRESHOLDS[cat]:
            out.update(p["entries"])
    return sorted(out)


def build(
    kev_bytes: bytes,
    cutoff: dt.date,
    records: dict[str, bytes] | None = None,
    survey: bytes | None = None,
    deployment_records: dict[str, bytes] | None = None,
    deployment_source: dict | None = None,
) -> dict:
    """`deployment_records`: registros cvelistV5 de la pata de despliegue (criterio v4);
    `deployment_source`: procedencia del volcado del que salen (`url`, `sha256`)."""
    sel = select(kev_bytes, cutoff)
    kev, products = sel["kev"], sel["canon"]["products"]
    included, review, below, out_of_scope = [], [], [], []
    used: dict[str, bytes] = {}
    for (vkey, k), p in sorted(products.items()):
        pid = f"{vkey}--{k}"
        cves = sorted(p["entries"])
        c = sel["cat_of"][(vkey, k)]
        if c["status"] == "out":
            out_of_scope.append(pid)
            continue
        if c["status"] == "review":
            review.append(
                {
                    "id": pid,
                    "vendor": _display(p["vendor"]),
                    "product": _display(p["product"]),
                    "reason": c["reason"],
                    "matched": c["matched"],
                    "kev_entries": len(cves),
                    "cves": cves,
                }
            )
            continue
        n_cat = sel["vendor_cat"][(vkey, c["category"])]
        if n_cat < THRESHOLDS[c["category"]]:
            below.append(
                {
                    "id": pid,
                    "product": _display(p["product"]),
                    "category": c["category"],
                    "vendor_category_entries": n_cat,
                    "threshold": THRESHOLDS[c["category"]],
                }
            )
            continue
        item = {
            "id": pid,
            "category": c["category"],
            "category_source": c["source"],
            "matched": c["matched"],
            "vendor": _display(p["vendor"]),
            "product": _display(p["product"]),
            "names": sorted(p["names"]),
            "abbreviations": sorted(p["abbrs"]),
            "aliases": [{"vendor": v, "product": q} for v, q in sorted(p["pairs"])],
        }
        if records is None:
            item |= {
                "cna": [],
                "cpe": [],
                "cpe_rule": None,
                "cpe_missing_reason": "generado sin registros cvelistV5",
            }
        else:
            mine = {cve: records[cve] for cve in cves if cve in records}
            used |= mine
            parsed = {cve: cvelist.parse(b) for cve, b in mine.items()}
            item |= match_cpe(p, vkey, parsed)
        item["purl"] = []
        item["evidence"] = {
            "kev_entries": len(cves),
            "vendor_category_entries": n_cat,
            "cves": cves,
        }
        included.append(item)

    inputs = [
        {
            "name": "cisa-kev",
            "url": KEV_URL,
            "license": "CC0-1.0",
            "catalog_version": kev.get("catalogVersion"),
            "sha256": sha256_bytes(kev_bytes),
        }
    ]
    if records is not None:
        wanted = sorted({c for p in included for c in p["evidence"]["cves"]})
        inputs.append(
            {
                "name": "cvelistV5",
                "url": cvelist.REPO_URL,
                "license": cvelist.LICENSE,
                "terms_url": cvelist.TERMS_URL,
                "notice": cvelist.NOTICE,
                "records": len(used),
                "records_missing": [c for c in wanted if c not in used],
                "sha256": cvelist.records_hash(used),
            }
        )
    if deployment_records is not None:
        src = deployment_source or {}
        inputs.append(
            {
                "name": "cvelistV5-deployment",
                "url": src.get("url") or deployment_cna.RELEASES_URL,
                "license": cvelist.LICENSE,
                "terms_url": cvelist.TERMS_URL,
                "notice": cvelist.NOTICE,
                "bulk_sha256": src.get("sha256"),
                "records": len(deployment_records),
                "sha256": cvelist.records_hash(deployment_records),
            }
        )
    with_cpe = sum(1 for p in included if p["cpe"])
    return {
        "criterion_version": CRITERION_VERSION,
        "generator": GENERATOR,
        "generator_version": GENERATOR_VERSION,
        "rules_version": RULES_VERSION,
        "cutoff_date": cutoff.isoformat(),
        "window": {"months": WINDOW_MONTHS, "from_exclusive": sel["start"].isoformat()},
        "threshold": dict(THRESHOLDS),
        "inputs": inputs,
        "categories": list(CATEGORIES),
        "precedence": list(PRECEDENCE),
        "rules": {
            c: {
                "type": list(TYPE_RULES[c]),
                "name": list(NAME_RULES[c]),
                "brand": list(BRAND_RULES[c]),
            }
            for c in CATEGORIES
        },
        "canonicalization": sel["canon"]["log"],
        "stats": {
            "kev_entries_total": len(kev["vulnerabilities"]),
            "kev_entries_in_window": len(sel["entries"]),
            "products_in_window": len(products),
            "products": len(included),
            "products_with_cpe": with_cpe,
            "needs_review": len(review),
            "below_threshold": len(below),
            "out_of_scope": len(out_of_scope),
        },
        "manual_changes": [],
        "products": included,
        "needs_review": review,
        "below_threshold": below,
        "deployment_leg": deployment.build(survey, deployment_records, cutoff),
        "out_of_scope": out_of_scope,
    }


def render(doc: dict) -> str:
    return dump_yaml(HEADER, doc)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cutoff", required=True, type=dt.date.fromisoformat)
    ap.add_argument("--input", type=Path, help="catálogo KEV local (si no, se descarga)")
    ap.add_argument("--survey", type=Path, help="encuesta normalizada (pata de despliegue)")
    ap.add_argument("--offline", action="store_true", help="solo registros cvelistV5 en caché")
    ap.add_argument("--refresh", action="store_true", help="vuelve a descargar")
    ap.add_argument(
        "--cvelist-bulk",
        type=Path,
        help="volcado diario de cvelistV5 (…_all_CVEs_at_midnight.zip.zip) para la pata de "
        "despliegue; sin él, se usan los registros ya en caché",
    )
    ap.add_argument("--cvelist-bulk-url", help="URL https de la release de la que sale el volcado")
    ap.add_argument("--output", type=Path, default=OUTPUT)
    args = ap.parse_args(argv)
    data = (
        args.input.read_bytes()
        if args.input
        else fetch(KEV_URL, "known_exploited_vulnerabilities.json", refresh=args.refresh)
    )
    cves = included_cves(data, args.cutoff)
    if args.offline:
        records = cvelist.load_cached(cves)
    else:
        records, missing = cvelist.fetch_records(cves, refresh=args.refresh)
        if missing:
            print(f"sin registro cvelistV5: {missing}")
    survey = args.survey.read_bytes() if args.survey else None
    dep_records, dep_source = None, None
    if survey is not None:
        names = [p["name"] for p in deployment.build(survey)["products"]]
        if args.cvelist_bulk:
            url = args.cvelist_bulk_url or deployment_cna.RELEASES_URL
            if not url.startswith("https://"):
                raise SystemExit("--cvelist-bulk-url debe ser https")
            dep_records = deployment_cna.scan_bulk(args.cvelist_bulk, names, args.cutoff)
            dep_source = {"url": url, "sha256": deployment_cna.file_sha256(args.cvelist_bulk)}
            deployment_cna.save_cache(dep_records, dep_source)
        elif (cached := deployment_cna.load_cache()) is not None:
            dep_records, dep_source = cached
    doc = build(data, args.cutoff, records, survey, dep_records, dep_source)
    args.output.write_text(render(doc), encoding="utf-8")
    print(f"{args.output}: {doc['stats']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
