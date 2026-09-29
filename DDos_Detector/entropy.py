"""
Defensive Shannon Entropy Engine:
H(X) = -sum(p(x) * log2(p(x)))
"""
import math
from typing import Dict, Iterable, Union


def calculate_shannon_entropy(
    source_distribution: Union[Dict[str, int], Iterable[int]]
) -> float:
    """
    Computes Shannon entropy in bits from raw source IP packet/flow frequency counts.

    Edge Cases Handled:
    - Empty sequence or dict: Returns 0.0 bits.
    - Total count <= 0: Returns 0.0 bits.
    - Single source: p = 1.0 -> log2(1.0) = 0.0 -> Returns 0.0 bits.
    - Uniform multi-source: Correctly returns log2(N).
    """
    if not source_distribution:
        return 0.0

    counts = (
        source_distribution.values()
        if isinstance(source_distribution, dict)
        else source_distribution
    )
    valid_counts = [c for c in counts if c > 0]

    total: float = float(sum(valid_counts))
    if total <= 0.0 or len(valid_counts) <= 1:
        return 0.0

    entropy = 0.0
    for count in valid_counts:
        p = count / total
        entropy -= p * math.log2(p)

    return round(max(0.0, entropy), 4)