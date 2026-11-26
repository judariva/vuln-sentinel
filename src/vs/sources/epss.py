"""FIRST EPSS (SRC-004): probabilidad de explotación, CSV diario.

Uso: «Is EPSS free to use? Yes. EPSS scores are published freely via CSV download and API with no
registration required. Attribution is requested when EPSS data is used in publications or
products.» (https://www.first.org/epss/faq, leído el 2026-11-26). Clase `open`, con atribución.

El CSV empieza con `#model_version:…,score_date:…` y luego `cve,epss,percentile`. La fecha del dato
es `score_date`. El fichero trae todas las CVE puntuadas (~410.000 filas el 2026-11-25): emitir
solo los saltos es trabajo de las reglas, no del conector.
"""

from __future__ import annotations

import csv
import io
import math
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta
from typing import Any

from vs.sources.base import Connector, Entity, LicenseClass, Record, is_cve_id, register
from vs.sources.http import SourceError, get_ok, maybe_gunzip, parse_ts

DEFAULT_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_PAGE = "https://www.first.org/epss/"


def _parse_header(line: str) -> dict[str, str]:
    if not line.startswith("#"):
        raise SourceError("EPSS: falta la cabecera '#model_version…,score_date…'")
    fields: dict[str, str] = {}
    for part in line[1:].strip().split(","):
        key, sep, val = part.partition(":")
        if sep:
            fields[key.strip()] = val.strip()
    if "score_date" not in fields or "model_version" not in fields:
        raise SourceError(f"EPSS: cabecera incompleta: {line.strip()!r}")
    return fields


def _prob(value: str, what: str) -> float:
    try:
        x = float(value)
    except ValueError as exc:
        raise SourceError(f"EPSS: {what} no numérico: {value!r}") from exc
    if math.isnan(x) or not 0.0 <= x <= 1.0:
        raise SourceError(f"EPSS: {what} fuera de [0, 1]: {value!r}")
    return x


@register
class EpssConnector(Connector):
    name = "epss"
    license_class = LicenseClass.OPEN
    # Se publica una vez al día; 48 h deja margen a un día sin publicación.
    freshness_threshold = timedelta(hours=48)

    def fetch(self) -> Iterator[dict[str, Any]]:
        url = self.config.get("url", DEFAULT_URL)
        body = maybe_gunzip(get_ok(self.transport, url).body, url)
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SourceError(f"EPSS: el CSV no es UTF-8: {exc}") from exc
        lines = text.splitlines()
        if len(lines) < 2:
            raise SourceError("EPSS: CSV vacío")
        header = _parse_header(lines[0])
        score_date = parse_ts(header["score_date"], "EPSS score_date")
        self.data_as_of = score_date
        reader = csv.DictReader(io.StringIO("\n".join(lines[1:])))
        if reader.fieldnames != ["cve", "epss", "percentile"]:
            raise SourceError(f"EPSS: columnas inesperadas: {reader.fieldnames}")
        for row in reader:
            yield {**row, "_score_date": score_date, "_model": header["model_version"]}

    def normalize(self, raw: dict[str, Any]) -> Iterable[Record]:
        cve = raw.get("cve")
        if not is_cve_id(cve):
            raise SourceError(f"EPSS: CVE no válida: {cve!r}")
        score_date: datetime = raw["_score_date"]
        yield Record(
            source=self.name,
            cve_id=cve,
            kind="epss",
            license_class=self.license_class,
            value={
                "epss": _prob(raw.get("epss") or "", "epss"),
                "percentile": _prob(raw.get("percentile") or "", "percentile"),
                "model_version": raw["_model"],
                "score_date": score_date.date().isoformat(),
            },
            entity=Entity.SIGNAL,
            source_published_at=score_date,
            url=EPSS_PAGE,
        )
