"""Stdlib-only BM25 retriever."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

_TOKEN = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


@dataclass
class Hit:
    text: str
    locator: dict
    score: float


class BM25:
    """Okapi BM25 over an in-memory record list."""

    def __init__(self, records: list[dict], *, k1: float = 1.5, b: float = 0.75):
        self.records = records
        self.k1 = k1
        self.b = b
        self.docs = [tokenize(r["text"]) for r in records]
        self.doc_len = [len(d) for d in self.docs]
        self.avgdl = (sum(self.doc_len) / len(self.docs)) if self.docs else 0.0
        self.freqs: list[dict[str, int]] = []
        df: dict[str, int] = {}
        for toks in self.docs:
            tf: dict[str, int] = {}
            for t in toks:
                tf[t] = tf.get(t, 0) + 1
            self.freqs.append(tf)
            for t in tf:
                df[t] = df.get(t, 0) + 1
        n = len(self.docs)
        self.idf = {t: math.log(1 + (n - dfi + 0.5) / (dfi + 0.5)) for t, dfi in df.items()}

    def search(self, query: str, k: int = 8) -> list[Hit]:
        q = tokenize(query)
        scored: list[tuple[float, int]] = []
        for i, tf in enumerate(self.freqs):
            dl = self.doc_len[i]
            s = 0.0
            for t in q:
                f = tf.get(t)
                if not f:
                    continue
                idf = self.idf.get(t, 0.0)
                denom = f + self.k1 * (1 - self.b + self.b * dl / (self.avgdl or 1))
                s += idf * (f * (self.k1 + 1)) / (denom or 1)
            if s > 0:
                scored.append((s, i))
        scored.sort(reverse=True)
        out: list[Hit] = []
        for s, i in scored[:k]:
            r = self.records[i]
            out.append(Hit(text=r["text"], locator=r["locator"], score=round(s, 4)))
        return out
