# ============================================================
# MALWARE INSIDE ENCRYPTED SESSIONS API
# ============================================================

import time
import joblib
import pandas as pd

from typing import Dict, Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


# ============================================================
# 1. LOAD MODEL
# ============================================================

MODEL_FILE = "final_module5_malware_model.joblib"

model_pipeline: Dict[str, Any] = {}

try:

    artifacts = joblib.load(
        MODEL_FILE
    )

    model_pipeline["model"] = artifacts["model"]

    model_pipeline["features"] = artifacts["features"]

    model_pipeline["threshold"] = artifacts.get(
        "threshold",
        0.5
    )

    model_pipeline["model_name"] = artifacts.get(
        "model_name",
        "Unknown"
    )

    print(
        "Malware model loaded successfully."
    )

except Exception as e:

    print(
        "ERROR loading Malware model:"
    )

    print(e)


# ============================================================
# 2. FASTAPI
# ============================================================

app = FastAPI(
    title="Encrypted Session Malware Detection API",
    version="1.0"
)


# ============================================================
# 3. REQUEST SCHEMA
# ============================================================

class FlowRequest(BaseModel):

    protocol: str

    duration: float
    packet_count: int
    byte_count: float

    packet_rate: float
    byte_rate: float

    packet_size_mean: float
    packet_size_std: float
    packet_size_cv: float

    first_packet_size: float
    last_packet_size: float

    iat_mean: float
    iat_std: float
    iat_max: float
    iat_cv: float

    periodicity_score: float

    tls_present: int
    tls_version: float
    server_hello: int

    ja3_hash_freq: float = 0.0
    ja3s_hash_freq: float = 0.0


# ============================================================
# 4. FEATURE EXTRACTION
# ============================================================

def extract_features(
    payload: FlowRequest,
    feature_names
):

    # Convert request to dictionary

    data = payload.model_dump()

    # Remove fields that are NOT model features

    data.pop(
        "protocol",
        None
    )

    # Create dataframe

    feature_row = {}

    for feature in feature_names:

        if feature in data:

            feature_row[feature] = data[feature]

        else:

            # Missing feature
            # Default value

            feature_row[feature] = 0.0

    return pd.DataFrame(
        [feature_row],
        columns=feature_names
    )


# ============================================================
# 5. HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return {

        "status": "healthy",

        "model_loaded":
            "model" in model_pipeline,

        "model_name":
            model_pipeline.get(
                "model_name",
                None
            ),

        "features_loaded":
            len(
                model_pipeline.get(
                    "features",
                    []
                )
            ),

        "threshold":
            model_pipeline.get(
                "threshold",
                None
            )
    }


# ============================================================
# 6. PREDICT
# ============================================================

@app.post("/predict")
def predict(
    payload: FlowRequest
):

    # --------------------------------------------------------
    # Check model
    # --------------------------------------------------------

    if "model" not in model_pipeline:

        raise HTTPException(
            status_code=500,
            detail="Malware model is not loaded."
        )


    # --------------------------------------------------------
    # Start timer
    # --------------------------------------------------------

    start = time.perf_counter()


    # --------------------------------------------------------
    # Extract features
    # --------------------------------------------------------

    features = extract_features(

        payload,

        model_pipeline[
            "features"
        ]

    )


    # --------------------------------------------------------
    # Model
    # --------------------------------------------------------

    model = model_pipeline[
        "model"
    ]


    # --------------------------------------------------------
    # Probability
    # --------------------------------------------------------

    if hasattr(
        model,
        "predict_proba"
    ):

        probability = float(
            model.predict_proba(
                features
            )[0][1]
        )

    else:

        probability = 0.0


    # --------------------------------------------------------
    # Threshold
    # --------------------------------------------------------

    threshold = float(
        model_pipeline.get(
            "threshold",
            0.5
        )
    )


    prediction = int(
        probability >= threshold
    )


    # --------------------------------------------------------
    # Latency
    # --------------------------------------------------------

    latency = (
        time.perf_counter()
        - start
    ) * 1000


    # --------------------------------------------------------
    # Severity
    # --------------------------------------------------------

    if probability >= 0.90:

        severity = "HIGH"

    elif probability >= 0.70:

        severity = "MEDIUM"

    else:

        severity = "LOW"


    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    return {

        "threat_class":
            "MALWARE_ENCRYPTED_SESSION"
            if prediction == 1
            else "BENIGN_ENCRYPTED_SESSION",

        "prediction":
            "MALWARE"
            if prediction == 1
            else "BENIGN",

        "malware_probability":
            round(
                probability,
                4
            ),

        "confidence":
            round(
                probability
                if prediction == 1
                else 1 - probability,
                4
            ),

        "threshold":
            threshold,

        "severity":
            severity,

        "evidence": {

            "tls_present":
                payload.tls_present,

            "tls_version":
                payload.tls_version,

            "server_hello":
                payload.server_hello,

            "packet_count":
                payload.packet_count,

            "byte_count":
                payload.byte_count,

            "packet_rate":
                payload.packet_rate,

            "byte_rate":
                payload.byte_rate,

            "iat_mean":
                payload.iat_mean,

            "iat_cv":
                payload.iat_cv,

            "periodicity_score":
                payload.periodicity_score,

            "ja3_hash_frequency":
                payload.ja3_hash_freq,

            "ja3s_hash_frequency":
                payload.ja3s_hash_freq
        },

        "latency_ms":
            round(
                latency,
                2
            )
    }


# ============================================================
# 7. RUN SERVER
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8001
    )