import pandas as pd

from sklearn.preprocessing import LabelEncoder


# Suspicious URL keywords

suspicious_keywords = [

    "admin",
    "login",
    "phpmyadmin",
    "config",
    "wp-login"
]


# Bot keywords

bot_keywords = [

    "curl",
    "python",
    "bot",
    "scanner"
]


# Detect suspicious URLs

def has_suspicious_url(url):

    url = str(url).lower()

    for keyword in suspicious_keywords:

        if keyword in url:
            return 1

    return 0


# Detect suspicious user agents

def suspicious_agent(agent):

    agent = str(agent).lower()

    for keyword in bot_keywords:

        if keyword in agent:
            return 1

    return 0


# Main preprocessing function

def preprocess_data(

    df,

    training=True,

    label_encoder=None
):

    # Copy dataframe

    df = df.copy()

    # Fill null values

    df["url"] = df["url"].fillna(
        "no_url"
    )

    df["user_agent"] = df[
        "user_agent"
    ].fillna(
        "unknown_agent"
    )

    # Convert timestamp

    df["timestamp"] = pd.to_datetime(

        df["timestamp"],

        errors="coerce"
    )

    # Fill invalid timestamps

    df["timestamp"] = df[
        "timestamp"
    ].fillna(

        pd.Timestamp("2024-01-01")
    )

    # Extract hour

    df["hour"] = df[
        "timestamp"
    ].dt.hour

    # Feature engineering

    df["suspicious_url"] = df[
        "url"
    ].apply(
        has_suspicious_url
    )

    df["suspicious_agent"] = df[
        "user_agent"
    ].apply(
        suspicious_agent
    )

    # Traffic ratio

    df["traffic_ratio"] = (

        df["bytes_sent"]

        /

        (df["bytes_received"] + 1)
    )

    # Boolean conversion

    df["is_internal_traffic"] = df[
        "is_internal_traffic"
    ].astype(int)

    # Protocol encoding

    if training:

        le = LabelEncoder()

        df["protocol"] = le.fit_transform(
            df["protocol"]
        )

    else:

        le = label_encoder

        df["protocol"] = le.transform(
            df["protocol"]
        )

    # Drop unnecessary columns

    drop_cols = [

        "src_ip",
        "dst_ip",
        "timestamp",
        "url",
        "user_agent"
    ]

    existing_cols = [

        col for col in drop_cols

        if col in df.columns
    ]

    df = df.drop(
        existing_cols,
        axis=1
    )

    # Convert columns to numeric

    for col in df.columns:

        if col != "label":

            df[col] = pd.to_numeric(

                df[col],

                errors="coerce"
            )

    # Fill NaN values

    df = df.fillna(0)

    # Return processed dataframe

    if training:

        return df, le

    return df