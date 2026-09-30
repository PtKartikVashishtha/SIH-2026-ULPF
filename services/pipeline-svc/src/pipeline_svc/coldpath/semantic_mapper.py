"""
Lexical Semantic Mapper for ULPF Cold Path (M6).

Uses TF-IDF character/word n-gram vector matching and strict type-compatibility
checks to map extracted raw tokens to standard OCSF 4001 attributes.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from typing import Any

try:
    from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore[import-untyped]
    from sklearn.metrics.pairwise import cosine_similarity  # type: ignore[import-untyped]
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    TfidfVectorizer = None  # type: ignore[assignment]
    cosine_similarity = None  # type: ignore[assignment]

# Target OCSF attributes with semantic description corpora
OCSF_VOCABULARY: dict[str, list[str]] = {
    "src_endpoint.ip": [
        "source ip address", "src ip", "srcip", "source address", "client ip",
        "sender ip", "src", "source", "saddr", "src_ip", "source_ip",
    ],
    "dst_endpoint.ip": [
        "destination ip address", "dst ip", "dstip", "dest address", "server ip",
        "target ip", "dst", "destination", "daddr", "dst_ip", "dest_ip",
    ],
    "src_endpoint.port": [
        "source port", "src port", "spt", "srcport", "client port", "sport",
        "source_port", "src_port",
    ],
    "dst_endpoint.port": [
        "destination port", "dst port", "dpt", "dstport", "server port",
        "dest port", "dport", "destination_port", "dst_port",
    ],
    "connection_info.protocol_name": [
        "network protocol", "proto", "protocol", "transport", "tcp", "udp",
        "icmp", "ip protocol",
    ],
    "action": [
        "action taken", "firewall action", "deny", "permit", "drop", "allow",
        "block", "reject", "pass", "verdict", "rule action",
    ],
    "http_request.http_method": [
        "http method", "request method", "method", "verb", "get", "post", "put", "delete", "patch", "head",
    ],
    "http_request.url.path": [
        "endpoint", "url path", "request uri", "path", "request path", "uri", "url", "route",
    ],
    "http_response.code": [
        "status code", "http status", "response code", "status", "http status code", "response status",
    ],
    "traffic.bytes_out": [
        "response size bytes", "bytes sent", "response size", "body bytes sent", "size", "bytes", "response length",
    ],
    "http_request.user_agent": [
        "user agent", "http user agent", "agent", "browser", "client user agent",
    ],
    "time": [
        "timestamp", "time", "date", "event time", "log time", "occurred at",
    ],
}

RE_PORT = re.compile(r"^\d{1,5}$")
KNOWN_PROTOCOLS = {"tcp", "udp", "icmp", "ip", "gre", "esp", "ah", "sctp"}
KNOWN_ACTIONS = {"deny", "permit", "drop", "allow", "block", "reject", "pass", "refuse"}
KNOWN_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}


def check_type_compatibility(attr: str, value: str) -> float:
    """Evaluates whether an extracted raw value matches expected semantic type."""
    val = value.strip().strip("\"'").lower()

    if attr in ("src_endpoint.ip", "dst_endpoint.ip"):
        try:
            ipaddress.ip_address(val.split("/")[0].split(":")[0])
            return 1.0
        except ValueError:
            return 0.0

    if attr in ("src_endpoint.port", "dst_endpoint.port"):
        if RE_PORT.match(val):
            port = int(val)
            return 1.0 if 0 <= port <= 65535 else 0.0
        return 0.0

    if attr == "connection_info.protocol_name":
        return 1.0 if val in KNOWN_PROTOCOLS else 0.0

    if attr == "action":
        return 1.0 if val in KNOWN_ACTIONS else 0.0

    if attr == "http_request.http_method":
        return 1.0 if val in KNOWN_HTTP_METHODS else 0.0

    if attr == "http_response.code":
        return 1.0 if val.isdigit() and 100 <= int(val) <= 599 else 0.0

    if attr == "traffic.bytes_out":
        return 1.0 if val.isdigit() and int(val) >= 0 else 0.0

    if attr == "http_request.url.path":
        return 1.0 if val.startswith("/") else 0.0

    return 0.5


class SemanticMapper:
    """Maps extracted raw field keys/values to candidate OCSF attributes with confidence scoring."""

    def __init__(self) -> None:
        self.attributes = list(OCSF_VOCABULARY.keys())
        self.doc_corpus = [" ".join(OCSF_VOCABULARY[attr]) for attr in self.attributes]

        if HAS_SKLEARN and TfidfVectorizer is not None:
            # Initialize TF-IDF vectorizer over character n-grams (3-5) and word n-grams
            self.vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5))
            self.tfidf_matrix = self.vectorizer.fit_transform(self.doc_corpus)
        else:
            self.vectorizer = None
            self.tfidf_matrix = None
            self._init_pure_python_tfidf()

    def _get_char_wb_ngrams(self, text: str, min_n: int = 3, max_n: int = 5) -> list[str]:
        words = text.lower().replace("_", " ").split()
        ngrams: list[str] = []
        for word in words:
            padded = f" {word} "
            for n in range(min_n, max_n + 1):
                for i in range(len(padded) - n + 1):
                    ngrams.append(padded[i:i + n])
        return ngrams

    def _init_pure_python_tfidf(self) -> None:
        self._doc_ngrams = [self._get_char_wb_ngrams(doc) for doc in self.doc_corpus]
        df: Counter[str] = Counter()
        for ng in self._doc_ngrams:
            for g in set(ng):
                df[g] += 1
        n_docs = len(self.doc_corpus)
        self._idf = {g: math.log((1 + n_docs) / (1 + count)) + 1.0 for g, count in df.items()}
        self._doc_vecs: list[dict[str, float]] = []
        self._doc_norms: list[float] = []
        for ng in self._doc_ngrams:
            tf = Counter(ng)
            vec = {g: cnt * self._idf.get(g, 1.0) for g, cnt in tf.items()}
            norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
            self._doc_vecs.append(vec)
            self._doc_norms.append(norm)

    def compute_lexical_similarity(self, query: str) -> dict[str, float]:
        """Calculates cosine similarity between a token key and all target OCSF attributes."""
        if HAS_SKLEARN and self.vectorizer is not None and cosine_similarity is not None:
            q_vec = self.vectorizer.transform([query.lower().replace("_", " ")])
            sims = cosine_similarity(q_vec, self.tfidf_matrix)[0]
            return {attr: float(sims[i]) for i, attr in enumerate(self.attributes)}

        q_ng = self._get_char_wb_ngrams(query)
        q_tf = Counter(q_ng)
        q_vec = {g: cnt * self._idf.get(g, 1.0) for g, cnt in q_tf.items()}
        q_norm = math.sqrt(sum(v * v for v in q_vec.values())) or 1.0
        results: dict[str, float] = {}
        for i, attr in enumerate(self.attributes):
            dot = sum(v * self._doc_vecs[i].get(g, 0.0) for g, v in q_vec.items())
            results[attr] = round(dot / (q_norm * self._doc_norms[i]), 4)
        return results

    def map_field(
        self,
        raw_key: str,
        raw_value: str,
    ) -> tuple[str, float, list[dict[str, Any]]]:
        """
        Maps a single raw key/value pair to the best candidate OCSF attribute.
        Returns: (best_attribute, composite_confidence, alternate_candidates)
        """
        lexical_sims = self.compute_lexical_similarity(raw_key)

        scored_candidates: list[tuple[str, float, float, float]] = []
        for attr in self.attributes:
            lex_score = lexical_sims[attr]
            type_score = check_type_compatibility(attr, raw_value)

            # Composite confidence: 0.6 lexical + 0.4 type compatibility
            composite = 0.6 * lex_score + 0.4 * type_score
            scored_candidates.append((attr, composite, lex_score, type_score))

        # Sort descending by composite score
        scored_candidates.sort(key=lambda x: x[1], reverse=True)
        best = scored_candidates[0]

        alternates = [
            {
                "attribute": c[0],
                "similarity_score": round(c[1], 4),
                "lexical_score": round(c[2], 4),
                "type_score": round(c[3], 4),
            }
            for c in scored_candidates[1:3]
        ]

        return best[0], round(best[1], 4), alternates

    def map_extracted_fields(
        self,
        extracted_fields: dict[str, str],
    ) -> dict[str, dict[str, Any]]:
        """Maps a collection of extracted fields to OCSF attributes with candidate structures."""
        results: dict[str, dict[str, Any]] = {}
        for raw_key, raw_val in extracted_fields.items():
            best_attr, score, alternates = self.map_field(raw_key, raw_val)
            results[raw_key] = {
                "candidate_ocsf_attribute": best_attr,
                "similarity_score": score,
                "value": raw_val,
                "alternate_candidates": alternates,
            }
        return results
