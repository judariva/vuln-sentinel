"""Puntos de entrada de los jobs (`python -m vs.jobs.<job>`, módulo de infra/terraform/).

Cada job es fino: lee la configuración del entorno (`vs.jobs.settings`), compone las piezas que ya
existen y sale con un código distinto de 0 si falla.
"""
