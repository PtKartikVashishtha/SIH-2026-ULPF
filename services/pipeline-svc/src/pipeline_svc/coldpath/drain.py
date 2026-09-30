"""
Drain Algorithm implementation for ULPF Cold-Path Template Mining (M6).

Based on:
He et al., "Drain: An Online Log Parsing Approach with Fixed Depth Tree".

Features:
- Fixed-depth parse tree with length and first-token routing.
- Dynamic constant vs. variable extraction (<*>).
- Transfer-learning token-overlap seeding from existing packs for rapid convergence.
- Strict cluster-capacity capping to prevent template degradation and mis-merging.
"""

from __future__ import annotations

import re

# Regular expressions for identifying variable tokens
RE_IPV4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$")
RE_NUM = re.compile(r"^\d+$")
RE_HEX = re.compile(r"^0x[0-9a-fA-F]+$")
RE_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
RE_DATE_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}")
RE_CONTAINS_DIGIT = re.compile(r"\d")


def is_variable_token(token: str) -> bool:
    """Heuristic check whether a token represents dynamic data rather than a constant keyword."""
    if token == "<*>":
        return True
    if RE_NUM.match(token) or RE_HEX.match(token) or RE_UUID.match(token):
        return True
    if RE_IPV4.match(token):
        return True
    if RE_DATE_TIME.match(token):
        return True
    # Tokens with numbers or key-value structures like "src=10.1.1.1" or "dst:8.8.8.8/443"
    if "=" in token or "/" in token:
        return True
    return bool(RE_CONTAINS_DIGIT.search(token))


class LogCluster:
    """Represents a mined log template cluster."""

    def __init__(
        self,
        cluster_id: str,
        template_tokens: list[str],
        sample_log: str,
        max_capacity: int = 500,
    ) -> None:
        self.cluster_id = cluster_id
        self.template_tokens = list(template_tokens)
        self.sample_count = 1
        self.sample_logs = [sample_log]
        self.max_capacity = max_capacity
        self.capacity_capped = False
        self.is_seed = False

    @property
    def template(self) -> str:
        return " ".join(self.template_tokens)

    def matches(self, tokens: list[str], sim_threshold: float = 0.5) -> tuple[bool, float]:
        """Calculates similarity between template and candidate log tokens."""
        if len(tokens) != len(self.template_tokens):
            return False, 0.0

        match_count = 0
        total_non_var = 0

        for t_token, c_token in zip(self.template_tokens, tokens, strict=False):
            if t_token == "<*>":
                continue
            total_non_var += 1
            if t_token == c_token:
                match_count += 1

        sim = 1.0 if total_non_var == 0 else match_count / total_non_var
        return sim >= sim_threshold, sim

    def update_template(self, tokens: list[str]) -> bool:
        """Updates cluster template by converting diverging positions into wildcards."""
        if self.sample_count >= self.max_capacity:
            self.capacity_capped = True
            return False

        self.sample_count += 1
        if len(self.sample_logs) < 5:
            self.sample_logs.append(" ".join(tokens))

        for i, (t_token, c_token) in enumerate(zip(self.template_tokens, tokens, strict=False)):
            if t_token != c_token and t_token != "<*>":
                self.template_tokens[i] = "<*>"

        return True


class DrainNode:
    """Tree node within the Drain parse tree."""

    def __init__(self) -> None:
        self.children: dict[str | int, DrainNode] = {}
        self.clusters: list[LogCluster] = []


class DrainParser:
    """
    Online Drain tree parser.
    Depth = 4: Root -> Length -> First Token -> Clusters list.
    """

    def __init__(
        self,
        depth: int = 4,
        sim_threshold: float = 0.5,
        max_cluster_capacity: int = 500,
        initial_sequence: int = 1,
        cluster_prefix: str = "drain-cluster-",
    ) -> None:
        self.depth = depth
        self.sim_threshold = sim_threshold
        self.max_cluster_capacity = max_cluster_capacity
        self.root = DrainNode()
        self.clusters: list[LogCluster] = []
        self._cluster_sequence = initial_sequence
        self.cluster_prefix = cluster_prefix

    def tokenize(self, log_line: str) -> list[str]:
        return log_line.strip().split()

    def add_seed_template(self, template: str, cluster_id: str | None = None) -> LogCluster:
        """Pre-seeds a known template for transfer-learning warm-start."""
        tokens = self.tokenize(template)
        cid = cluster_id or f"drain-cluster-seed-{len(self.clusters) + 1:04d}"
        cluster = LogCluster(
            cluster_id=cid,
            template_tokens=tokens,
            sample_log=template,
            max_capacity=self.max_cluster_capacity,
        )
        cluster.is_seed = True
        self._insert_cluster_into_tree(cluster)
        self.clusters.append(cluster)
        return cluster

    def _insert_cluster_into_tree(self, cluster: LogCluster) -> None:
        seq_len = len(cluster.template_tokens)
        first_token = cluster.template_tokens[0] if seq_len > 0 else "<*>"
        if is_variable_token(first_token):
            first_token = "<*>"

        # Level 1: Length
        if seq_len not in self.root.children:
            self.root.children[seq_len] = DrainNode()
        len_node = self.root.children[seq_len]

        # Level 2: First token
        if first_token not in len_node.children:
            len_node.children[first_token] = DrainNode()
        token_node = len_node.children[first_token]

        token_node.clusters.append(cluster)

    def parse(self, log_line: str) -> tuple[LogCluster, bool]:
        """
        Parses a log line.
        Returns: (cluster, is_new_cluster)
        """
        tokens = self.tokenize(log_line)
        seq_len = len(tokens)
        if seq_len == 0:
            dummy = LogCluster("empty", [], "")
            return dummy, False

        first_token = tokens[0]
        if is_variable_token(first_token):
            first_token = "<*>"

        # Traverse parse tree
        len_node = self.root.children.get(seq_len)
        candidate_clusters: list[LogCluster] = []
        if len_node:
            token_node = len_node.children.get(first_token)
            if token_node:
                candidate_clusters.extend(token_node.clusters)
            if first_token != "<*>" and "<*>" in len_node.children:
                wildcard_node = len_node.children["<*>"]
                candidate_clusters.extend(wildcard_node.clusters)

        # Find best matching cluster
        best_cluster: LogCluster | None = None
        best_sim = -1.0

        for cluster in candidate_clusters:
            matched, sim = cluster.matches(tokens, self.sim_threshold)
            if matched and sim > best_sim:
                best_sim = sim
                best_cluster = cluster

        if best_cluster:
            # Check capacity cap
            if best_cluster.sample_count >= best_cluster.max_capacity:
                best_cluster.capacity_capped = True
                # Capacity capped: flag and create distinct branch rather than degrading
                new_cluster = self._create_new_cluster(tokens, log_line)
                return new_cluster, True

            best_cluster.update_template(tokens)
            return best_cluster, False

        # No match found -> create new cluster
        new_cluster = self._create_new_cluster(tokens, log_line)
        return new_cluster, True

    def _create_new_cluster(self, tokens: list[str], sample_log: str) -> LogCluster:
        cid = f"{self.cluster_prefix}{self._cluster_sequence:04d}"
        self._cluster_sequence += 1

        # Replace obvious variables with wildcard
        template_tokens = ["<*>" if is_variable_token(tok) else tok for tok in tokens]
        cluster = LogCluster(
            cluster_id=cid,
            template_tokens=template_tokens,
            sample_log=sample_log,
            max_capacity=self.max_cluster_capacity,
        )
        self._insert_cluster_into_tree(cluster)
        self.clusters.append(cluster)
        return cluster

    def extract_variables(self, cluster: LogCluster, log_line: str) -> dict[str, str]:
        """Extracts variable tokens from a log line against the cluster template."""
        tokens = self.tokenize(log_line)
        extracted: dict[str, str] = {}
        if len(tokens) != len(cluster.template_tokens):
            return extracted

        var_idx = 1
        for t_tok, l_tok in zip(cluster.template_tokens, tokens, strict=False):
            if t_tok == "<*>":
                # Check if it has a prefix like "src=10.1.1.1"
                if "=" in l_tok:
                    k, v = l_tok.split("=", 1)
                    extracted[k] = v
                else:
                    extracted[f"var_{var_idx}"] = l_tok
                var_idx += 1

        return extracted
