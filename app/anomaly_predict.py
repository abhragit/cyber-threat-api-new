import joblib

from app.anomaly_preprocessing import (
    preprocess_anomaly_data
)

# Load model

iso_model = joblib.load(
    "app/anomaly_model.pkl"
)

# Load encoder

label_encoder = joblib.load(
    "app/anomaly_protocol_encoder.pkl"
)


def predict_anomaly(df):

    original_df = df.copy()

    # Preprocess

    processed_df, test_X = (
        preprocess_anomaly_data(
            df,
            label_encoder
        )
    )

    # Predict

    predictions = iso_model.predict(
        test_X
    )

    # Scores

    scores = iso_model.decision_function(
        test_X
    )

    # Convert output labels

    final_output = []

    for p in predictions:

        if p == -1:

            final_output.append(
                "Anomalous"
            )

        else:

            final_output.append(
                "Normal"
            )

    # Add outputs

    original_df[
        "anomaly_status"
    ] = final_output

    original_df[
        "anomaly_score"
    ] = scores

    # Generate reasons

    all_reasons = []

    for _, row in processed_df.iterrows():

        reasons = []

        if row["suspicious_url"] == 1:

            reasons.append(
                "Suspicious URL detected"
            )

        if row["suspicious_agent"] == 1:

            reasons.append(
                "Suspicious automation agent"
            )

        if row["traffic_ratio"] > 10:

            reasons.append(
                "Abnormal traffic ratio"
            )

        if row["dst_port"] in [
            22,
            23,
            3389
        ]:

            reasons.append(
                "High-risk destination port"
            )

        if len(reasons) == 0:

            reasons.append(
                "Behavior deviates from normal traffic"
            )

        all_reasons.append(
            reasons
        )

    # Add reasons

    original_df[
        "reasons"
    ] = all_reasons

    return original_df