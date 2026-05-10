from fastapi import FastAPI
from fastapi import UploadFile
from fastapi import File

import pandas as pd

from app.validation import validate_csv
from app.predict import predict_csv
from fastapi.encoders import jsonable_encoder
from app.anomaly_predict import (
    predict_anomaly
)

app = FastAPI()


@app.get("/")
def home():
    return {
        "message": "Cyber Threat API Running"
    }


@app.post("/predict")
async def predict(
        file: UploadFile = File(...)
):
    df = pd.read_csv(file.file)

    validation_result = validate_csv(df)

    if not validation_result["valid"]:
        return {
            "error": "Invalid CSV",
            "missing_columns":
                validation_result[
                    "missing_columns"
                ]
        }

    results = predict_csv(df)

    return jsonable_encoder(

        results.fillna("").to_dict(

            orient="records"
        )
    )


@app.post("/anomaly")
async def anomaly(

        file: UploadFile = File(...)
):
    df = pd.read_csv(
        file.file
    )

    results = predict_anomaly(
        df
    )

    results = results.fillna("N/A")

    return results.to_dict(
        orient="records"
    )