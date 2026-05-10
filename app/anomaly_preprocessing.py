import pandas as pd


keywords = [
    "login",
    "admin",
    "phpmyadmin",
    "wp-login"
]

bots = [
    "curl",
    "python",
    "bot",
    "scanner"
]


def suspicious_url(url):

    url = str(url).lower()

    for k in keywords:

        if k in url:
            return 1

    return 0


def suspicious_agent(agent):

    agent = str(agent).lower()

    for b in bots:

        if b in agent:
            return 1

    return 0


def preprocess_anomaly_data(

    df,

    label_encoder
):

    df = df.copy()

    # Fill NULL values

    df["url"] = df["url"].fillna(
        "no_url"
    )

    df["user_agent"] = df[
        "user_agent"
    ].fillna(
        "unknown_agent"
    )

    # Feature engineering

    df["suspicious_url"] = df[
        "url"
    ].apply(
        suspicious_url
    )

    df["suspicious_agent"] = df[
        "user_agent"
    ].apply(
        suspicious_agent
    )

    df["traffic_ratio"] = (

        df["bytes_sent"]

        /

        (df["bytes_received"] + 1)
    )

    # Boolean conversion

    df["is_internal_traffic"] = (

        df["is_internal_traffic"]

        .astype(int)
    )

    # Protocol encoding

    df["protocol"] = df[
        "protocol"
    ].apply(

        lambda x:

        label_encoder.transform([x])[0]

        if x in label_encoder.classes_

        else -1
    )

    features = [

        "src_port",

        "dst_port",

        "protocol",

        "bytes_sent",

        "bytes_received",

        "is_internal_traffic",

        "suspicious_url",

        "suspicious_agent",

        "traffic_ratio"
    ]

    return df, df[features]