"""Audit Dataset V1 package-name shortcut baseline — real bias vs implementation leakage."""

from __future__ import annotations

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from packagegate_ml.training.shortcut_features import (
    opaque_random_id_features,
    v1_legacy_name_morphology_from_sample_id,
)


def _fit_pr_auc(x_train, y_train, x_test, y_test) -> float:
    model = Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "clf",
                LogisticRegression(
                    max_iter=4000,
                    class_weight="balanced",
                    random_state=0,
                ),
            ),
        ]
    )
    model.fit(x_train, y_train)
    proba = model.predict_proba(x_test)[:, 1]
    return float(average_precision_score(y_test, proba))


def test_v1_name_shortcut_is_lexical_morphology_not_crypto_hash() -> None:
    """Document exact V1 feature construction (mislabelled ``name_hash`` historically)."""
    feats = v1_legacy_name_morphology_from_sample_id("@evil@pkg@999.9.9")
    assert set(feats) == {"name_len", "version_len", "at_count", "digit_count"}
    # split('@')[0] on scoped-ish IDs is empty — this is what V1 literally did
    assert feats["name_len"] == 0.0
    assert feats["version_len"] == float(len("999.9.9"))
    assert feats["at_count"] == 3.0
    assert feats["digit_count"] == 5.0


def test_opaque_random_id_baseline_near_prevalence() -> None:
    """Opaque hash→float IDs must not recover labels (else leakage / implementation bug)."""
    rng = np.random.default_rng(7)
    # Synthetic separable lexical structure (malicious: more '@' and digits)
    train_ids = []
    train_y = []
    for i in range(200):
        if i < 80:
            train_ids.append(f"@{i % 9}x@m{i}@9.9.{i}")
            train_y.append(1)
        else:
            train_ids.append(f"lodash-like-{i}@1.2.{i % 10}")
            train_y.append(0)
    test_ids = []
    test_y = []
    for i in range(80):
        if i < 30:
            test_ids.append(f"@{i % 7}y@n{i}@8.8.{i}")
            test_y.append(1)
        else:
            test_ids.append(f"express-like-{i}@4.1.{i % 5}")
            test_y.append(0)

    y_train = np.array(train_y)
    y_test = np.array(test_y)
    prevalence = float(y_test.mean())

    # Lexical morphology SHOULD separate this synthetic corpus
    x_tr = np.array(
        [list(v1_legacy_name_morphology_from_sample_id(s).values()) for s in train_ids]
    )
    x_te = np.array(
        [list(v1_legacy_name_morphology_from_sample_id(s).values()) for s in test_ids]
    )
    lexical_pr = _fit_pr_auc(x_tr, y_train, x_te, y_test)
    assert lexical_pr > 0.85, lexical_pr

    # Opaque random IDs must stay near prevalence across seeds
    scores = []
    for seed in range(5):
        x_tr_o = np.array(
            [
                list(opaque_random_id_features(s, seed=seed).values())
                for s in train_ids
            ]
        )
        x_te_o = np.array(
            [
                list(opaque_random_id_features(s, seed=seed).values())
                for s in test_ids
            ]
        )
        scores.append(_fit_pr_auc(x_tr_o, y_train, x_te_o, y_test))
    mean_pr = float(np.mean(scores))
    # Allow generous noise on small sets; must not approach lexical performance
    assert mean_pr < prevalence + 0.25, (mean_pr, prevalence, scores)
    assert mean_pr < 0.75, (mean_pr, scores)


def test_opaque_features_ignore_label_assignment_order() -> None:
    """Feature values depend only on sample_id (+seed), never on label or row order."""
    a = opaque_random_id_features("pkg@1.0.0", seed=1)
    b = opaque_random_id_features("pkg@1.0.0", seed=1)
    c = opaque_random_id_features("pkg@1.0.0", seed=2)
    assert a == b
    assert a != c
