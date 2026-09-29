from datetime import datetime
from typing import Dict, List, Optional

from schemas.flow_schema import FlowRecord


class AlertBuilder:
    def __init__(self):
        pass

    def build_alert(
        self,
        flow: FlowRecord,
        detection_result: Dict[str, object],
        evidence: List[str]
    ) -> Dict[str, object]:
        """
        Build a standardized exfiltration alert.
        """

        risk_score = int(
            detection_result.get("risk_score", 0)
        )

        severity = str(
            detection_result.get("severity", "LOW")
        )

        is_suspicious = bool(
            detection_result.get(
                "is_suspicious",
                False
            )
        )

        # Convert the risk score into a normalized
        # value between 0 and 1.
        confidence = risk_score / 100.0

        alert = {
            "timestamp": flow.timestamp.isoformat(),

            "flow_id": flow.flow_id,

            "threat_class": "DATA_EXFILTRATION",

            "confidence": round(
                confidence,
                2
            ),

            "risk_score": risk_score,

            "severity": severity,

            "is_suspicious": is_suspicious,

            "source_ip": flow.src_ip,

            "destination_ip": flow.dst_ip,

            "source_port": flow.src_port,

            "destination_port": flow.dst_port,

            "protocol": flow.protocol,

            "evidence": evidence
        }

        return alert