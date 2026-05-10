required_columns = [

    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "bytes_sent",
    "bytes_received",
    "is_internal_traffic",
    "timestamp",
    "url",
    "user_agent"
]


def validate_csv(df):

    missing_columns = []

    for col in required_columns:

        if col not in df.columns:
            missing_columns.append(col)

    if len(missing_columns) > 0:

        return {
            "valid": False,
            "missing_columns": missing_columns
        }

    return {
        "valid": True
    }