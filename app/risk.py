def get_risk(probability):

    if probability >= 0.9:
        return "Critical"

    elif probability >= 0.7:
        return "High"

    elif probability >= 0.4:
        return "Medium"

    else:
        return "Low"