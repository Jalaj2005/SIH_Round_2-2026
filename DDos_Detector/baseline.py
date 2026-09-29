"""
Rolling statistical baseline using stable sample mean and standard deviation.
Includes traffic poisoning prevention.
"""
from collections import deque
import math
from typing import Tuple


class RollingTrafficBaseline:
    def __init__(
        self,
        window_size: int = 30,
        min_samples: int = 5,
        default_mean: float = 1000.0,
    ):
        self.window_size = window_size
        self.min_samples = min_samples
        self.default_mean = default_mean
        self.history = deque(maxlen=window_size)

    def update(self, current_rate: float, is_attack: bool = False) -> None:
        """
        Updates baseline history.
        Poisoning guard: skips windows flagged as confirmed attacks.
        """
        if not is_attack and current_rate >= 0:
            self.history.append(float(current_rate))

    def get_stats(self) -> Tuple[float, float]:
        """Returns (rolling_mean, rolling_std)."""
        n = len(self.history)
        if n < self.min_samples:
            return self.default_mean, 100.0

        mean = sum(self.history) / n
        variance = (
            sum((x - mean) ** 2 for x in self.history) / (n - 1)
            if n > 1
            else 0.0
        )
        std = math.sqrt(max(0.0, variance))
        return mean, std

    def compute_z_score(self, current_rate: float) -> Tuple[float, float, float]:
        """Calculates rate z-score against rolling baseline."""
        mean, std = self.get_stats()
        effective_std = std if std >= 1.0 else 1.0
        z_score = (current_rate - mean) / effective_std
        return round(z_score, 2), round(mean, 2), round(effective_std, 2)