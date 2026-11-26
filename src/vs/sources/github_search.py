"""Búsqueda de GitHub (SRC-012): PoC recientes, **solo para CVE candidatos B/C** (PLAN.md §4).

Términos (ADR-0020 §6, ToS §H, https://docs.github.com/en/site-policy/github-terms/github-terms-of-service):
uso dentro de los límites de la API y sin compartir tokens para superarlos. Clase `open`; el código
de cada PoC se enlaza, no se aloja ni se clona.

Límite del plan: 30 búsquedas por minuto con token (10 sin él). `RateLimiter` espera antes de
pasarse, y la ejecución tiene un tope de candidatos (`max_candidates`): si hay más, UNKNOWN
(fail-closed) en vez de buscar solo una parte sin decirlo. Un 403 o 429 (límite agotado) también
da UNKNOWN.

Los candidatos no salen de la configuración de la instancia: los fija el job de investigación
(`set_candidates`) con las CVE que las reglas dejan en B o C. Sin candidatos no se hace ninguna
petición. La fecha del dato es la cabecera `Date` de la respuesta (la búsqueda es en vivo).

Cada repositorio encontrado se inspecciona con las heurísticas `poc_suspicious` (`vs.sources.poc`)
dentro del presupuesto de inspecciones.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlencode

from vs.sources.base import Connector, LicenseClass, Record, is_cve_id, register
from vs.sources.github import RateLimiter, github_headers, github_token
from vs.sources.http import SourceError, SourceIncomplete, Transport, get_ok, parse_json
from vs.sources.nomisec import make_inspector, repo_signal
from vs.sources.poc import PocInspector

DEFAULT_API_URL = "https://api.github.com"
DEFAULT_MAX_CANDIDATES = 10
DEFAULT_PER_PAGE = 30
RATE_WITH_TOKEN = 30  # búsquedas por minuto (PLAN §4)
RATE_WITHOUT_TOKEN = 10


def _http_date(value: str | None) -> datetime:
    if not value:
        raise SourceError("búsqueda de GitHub: respuesta sin cabecera Date")
    try:
        ts = parsedate_to_datetime(value)
    except (TypeError, ValueError) as exc:
        raise SourceError(f"búsqueda de GitHub: Date no válida: {value!r}") from exc
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


@register
class GithubSearchConnector(Connector):
    name = "github_search"
    license_class = LicenseClass.OPEN
    # La búsqueda es en vivo: la respuesta tiene que ser de esta misma ejecución.
    freshness_threshold = timedelta(hours=1)
    _inspector: PocInspector | None = None

    def __init__(
        self,
        config: Mapping[str, Any] | None = None,
        *,
        transport: Transport | None = None,
        limiter: RateLimiter | None = None,
        clock=None,
    ) -> None:
        super().__init__(config, transport=transport)
        default_rate = RATE_WITH_TOKEN if github_token(self.config) else RATE_WITHOUT_TOKEN
        rate = int(self.config.get("requests_per_minute", default_rate))
        if rate > default_rate:
            raise ValueError(f"requests_per_minute ({rate}) por encima del límite ({default_rate})")
        self.limiter = limiter or RateLimiter(rate)
        self._clock = clock or (lambda: datetime.now(UTC))
        self.candidates: tuple[str, ...] = ()
        self.set_candidates(self.config.get("candidates") or ())

    def set_candidates(self, cves: Iterable[str]) -> None:
        cves = tuple(dict.fromkeys(cves))
        bad = [c for c in cves if not is_cve_id(c)]
        if bad:
            raise ValueError(f"candidatos que no son CVE: {bad}")
        self.candidates = cves

    def fetch(self) -> Iterator[dict[str, Any]]:
        api = self.config.get("api_url", DEFAULT_API_URL).rstrip("/")
        per_page = int(self.config.get("per_page", DEFAULT_PER_PAGE))
        max_candidates = int(self.config.get("max_candidates", DEFAULT_MAX_CANDIDATES))
        if len(self.candidates) > max_candidates:
            raise SourceIncomplete(
                f"búsqueda de GitHub: {len(self.candidates)} candidatos, más que el tope "
                f"{max_candidates}"
            )
        if not self.candidates:
            self.data_as_of = self._clock()
            return
        headers = github_headers(self.config)
        self._inspector = make_inspector(self)
        for cve in self.candidates:
            query = {
                "q": f'"{cve}" in:name,description,readme',
                "sort": "updated",
                "order": "desc",
                "per_page": per_page,
            }
            url = f"{api}/search/repositories?{urlencode(query)}"
            self.limiter.acquire()
            resp = get_ok(self.transport, url, headers=headers)
            when = _http_date(resp.header("Date"))
            if self.data_as_of is None or when < self.data_as_of:
                self.data_as_of = when  # la respuesta más vieja de la ejecución
            data = parse_json(resp.body, url)
            if not isinstance(data, dict) or not isinstance(data.get("items"), list):
                raise SourceError("búsqueda de GitHub: respuesta sin 'items'")
            if data.get("incomplete_results"):
                raise SourceIncomplete(f"búsqueda de GitHub: resultados incompletos para {cve}")
            total = data.get("total_count")
            if isinstance(total, int) and total > len(data["items"]):
                self.count("truncados")
            yield {"cve": cve, "items": data["items"]}
        for k, v in self._inspector.stats.items():
            self.count(f"inspeccion_{k}", v)

    def normalize(self, raw: dict[str, Any]) -> Iterable[Record]:
        seen: set[str] = set()
        for item in raw["items"]:
            name = item.get("full_name") if isinstance(item, dict) else None
            if name in seen:
                continue
            seen.add(name)
            yield repo_signal(
                self, raw["cve"], item, listed_by="github_search", inspector=self._inspector
            )
