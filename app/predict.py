import joblib

from app.preprocessing import preprocess_data
from app.risk import get_risk
from app.explain import generate_basic_explanation

model = joblib.load(
    "app/cyber_model.pkl"
)

label_encoder = joblib.load(
    "app/label_encoder.pkl"
)

feature_columns = joblib.load(
    "app/feature_columns.pkl"
)


def predict_csv(df):
    original_df = df.copy()

    processed_df = preprocess_data(

        df,

        training=False,

        label_encoder=label_encoder
    )

    # Match training columns

    processed_df = processed_df.reindex(

        columns=feature_columns,

        fill_value=0
    )

    # Predictions

    predictions = model.predict(
        processed_df
    )

    probabilities = model.predict_proba(
        processed_df
    )

    # Add outputs

    original_df["prediction"] = predictions

    original_df[
        "malicious_probability"
    ] = probabilities[:, 1]

    original_df["risk_level"] = original_df[
        "malicious_probability"
    ].apply(get_risk)

    # Explanations

    processed_df["explanation"] = processed_df.apply(

        generate_basic_explanation,

        axis=1
    )

    original_df["explanation"] = processed_df[
        "explanation"
    ]

    # IMPORTANT

    return original_df
