"""Baseline heurístico: la línea base contra la que se compara el clasificador por IA."""

from app.baseline.rules import PESOS, evaluar_reglas

__all__ = ["PESOS", "evaluar_reglas"]
