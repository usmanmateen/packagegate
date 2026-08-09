"""CPU unit tests for neural dataset helpers and MIL shapes."""

from __future__ import annotations

import torch

from packagegate_ml.neural.datasets import label_vector_fixed
from packagegate_ml.neural.train_package import GatedAttentionMIL
from packagegate_ml.neural import BEHAVIOUR_LABELS_V1


def test_label_vector_assignment() -> None:
    v = label_vector_fixed(["process_execution", "network_access"])
    assert len(v) == len(BEHAVIOUR_LABELS_V1)
    assert v[BEHAVIOUR_LABELS_V1.index("process_execution")] == 1.0
    assert v[BEHAVIOUR_LABELS_V1.index("environment_access")] == 0.0


def test_mil_handles_zero_slices() -> None:
    mil = GatedAttentionMIL(emb_dim=16, structured_dim=4, hidden=8)
    emb = torch.zeros(0, 16)
    struct = torch.randn(4)
    logit, weights = mil(emb, struct, torch.tensor(0.0))
    assert logit.ndim == 0
    assert weights.numel() == 0


def test_mil_attention_sums_to_one() -> None:
    mil = GatedAttentionMIL(emb_dim=16, structured_dim=3, hidden=8)
    emb = torch.randn(5, 16)
    logit, weights = mil(emb, torch.randn(3), torch.tensor(1.0))
    assert abs(float(weights.detach().sum()) - 1.0) < 1e-5
    assert logit.ndim == 0
