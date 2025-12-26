from app.models_loader import normal_filter, attack_models
from app.feature_mapper import (
    map_payload_stage1,
    map_payload_stage2,
)
from app.config import NORMAL_THRESHOLD, ATTACK_THRESHOLDS, MARGIN

def safe_prob(model, X):
    p = model.predict_proba(X)
    return p[0][1] if p.shape[1] == 2 else 0.0


def detect(payload: dict):
    # Stage-1
    X1 = map_payload_stage1(payload)
    p_normal = safe_prob(normal_filter, X1)

    if p_normal >= NORMAL_THRESHOLD:
        return {
            "is_attack": False,
            "attack_type": "Normal",
            "confidence": p_normal,
        }

    # Stage-2
    X2 = map_payload_stage2(payload)

    scores = {
        name: safe_prob(model, X2)
        for name, model in attack_models.items()
    }

    valid = {
        k: v for k, v in scores.items()
        if v >= ATTACK_THRESHOLDS[k]
    }

    if not valid:
        return {
            "is_attack": True,
            "attack_type": "Unknown",
            "confidence": max(scores.values()),
            "probabilities": scores,
        }

    ranked = sorted(valid.items(), key=lambda x: x[1], reverse=True)

    if len(ranked) > 1 and ranked[0][1] - ranked[1][1] < MARGIN:
        return {
            "is_attack": True,
            "attack_type": "Unknown",
            "confidence": ranked[0][1],
            "probabilities": scores,
        }

    return {
        "is_attack": True,
        "attack_type": ranked[0][0],
        "confidence": ranked[0][1],
        "probabilities": scores,
    }
