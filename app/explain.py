def generate_basic_explanation(row):

    reasons = []

    if row["suspicious_url"] == 1:
        reasons.append(
            "Suspicious URL detected"
        )

    if row["suspicious_agent"] == 1:
        reasons.append(
            "Bot-like user agent detected"
        )

    if row["hour"] < 5:
        reasons.append(
            "Unusual access hour"
        )

    if row["is_internal_traffic"] == 1:
        reasons.append(
            "Internal traffic anomaly"
        )

    if len(reasons) == 0:
        reasons.append(
            "No major threat indicators"
        )

    return reasons