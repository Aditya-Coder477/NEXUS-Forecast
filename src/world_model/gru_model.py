"""
PyTorch Multi-Task GRU World Model Architecture for NEXUS-Forecast.
Processes historical states (batch_size, 10, 22) through a 2-layer unidirectional GRU,
producing a temporal latent state that feeds:
1. Future State Head (Linear -> 22) for K in [1, 3, 6]
2. Future Attack Likelihood Head (Linear -> 1) for K in [1, 3, 6]
3. Future Attack Stage Head (Linear -> 9) for K in [1, 3, 6]
"""

import torch
import torch.nn as nn
from typing import Dict, List, Any

class GRUWorldModel(nn.Module):
    def __init__(
        self,
        input_size: int = 22,
        hidden_size: int = 128,
        num_layers: int = 2,
        dropout: float = 0.2,
        bidirectional: bool = False,
        forecast_horizons: List[int] = [1, 3, 6],
        num_stages: int = 9
    ):
        super().__init__()
        assert not bidirectional, "Forecasting World Model must be causal (bidirectional=False)!"
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.forecast_horizons = forecast_horizons
        self.num_stages = num_stages

        # 1. Temporal GRU Encoder (pure architectural substitution from LSTM)
        self.gru = nn.GRU(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
            bidirectional=False
        )

        # Latent projection / LayerNorm for stability (identical to LSTM)
        self.latent_norm = nn.LayerNorm(hidden_size)
        self.dropout = nn.Dropout(dropout)

        # 2. Multi-Task Prediction Heads per Forecast Horizon K (identical to LSTM)
        # State Heads: regression to predict S_{t+K} in 22 dimensions
        self.state_heads = nn.ModuleDict({
            str(k): nn.Sequential(
                nn.Linear(hidden_size, hidden_size // 2),
                nn.ReLU(),
                nn.Dropout(dropout / 2),
                nn.Linear(hidden_size // 2, input_size)
            )
            for k in forecast_horizons
        })

        # Attack Probability Heads: binary classification logits for P(attack at t+K)
        self.attack_heads = nn.ModuleDict({
            str(k): nn.Sequential(
                nn.Linear(hidden_size, hidden_size // 4),
                nn.ReLU(),
                nn.Linear(hidden_size // 4, 1)
            )
            for k in forecast_horizons
        })

        # Stage Classification Heads: 9-class logits over canonical NEXUS stages
        self.stage_heads = nn.ModuleDict({
            str(k): nn.Sequential(
                nn.Linear(hidden_size, hidden_size // 2),
                nn.ReLU(),
                nn.Linear(hidden_size // 2, num_stages)
            )
            for k in forecast_horizons
        })

    def forward(self, x: torch.Tensor) -> Dict[str, Dict[int, torch.Tensor]]:
        """
        Forward pass.
        Args:
            x: Input tensor of shape (batch_size, 10, input_size)
        Returns:
            Dictionary containing:
            - 'state': {k: tensor of shape (batch_size, 22)}
            - 'attack': {k: tensor of shape (batch_size, 1)} (raw logits)
            - 'stage': {k: tensor of shape (batch_size, num_stages)} (raw logits)
            - 'latent': tensor of shape (batch_size, hidden_size)
        """
        # gru_out: (batch_size, seq_len, hidden_size)
        gru_out, h_n = self.gru(x)

        # Extract final hidden state of the last time step S_t
        final_h = gru_out[:, -1, :]  # Shape: (batch_size, hidden_size)
        latent = self.dropout(self.latent_norm(final_h))

        state_preds = {}
        attack_preds = {}
        stage_preds = {}

        for k in self.forecast_horizons:
            k_str = str(k)
            state_preds[k] = self.state_heads[k_str](latent)
            attack_preds[k] = self.attack_heads[k_str](latent).squeeze(-1) # (batch_size,)
            stage_preds[k] = self.stage_heads[k_str](latent)

        return {
            "state": state_preds,
            "attack": attack_preds,
            "stage": stage_preds,
            "latent": latent
        }

    def predict_future(self, x: torch.Tensor) -> Dict[str, Any]:
        """Inference helper producing calibrated probabilities and predictions."""
        self.eval()
        with torch.no_grad():
            outputs = self.forward(x)
            attack_probs = {k: torch.sigmoid(outputs["attack"][k]).cpu().numpy() for k in self.forecast_horizons}
            attack_classes = {k: (attack_probs[k] >= 0.50).astype(int) for k in self.forecast_horizons}
            stage_probs = {k: torch.softmax(outputs["stage"][k], dim=-1).cpu().numpy() for k in self.forecast_horizons}
            stage_classes = {k: stage_probs[k].argmax(axis=-1) for k in self.forecast_horizons}
            states = {k: outputs["state"][k].cpu().numpy() for k in self.forecast_horizons}

        return {
            "attack_probabilities": attack_probs,
            "attack_predictions": attack_classes,
            "stage_probabilities": stage_probs,
            "stage_predictions": stage_classes,
            "predicted_states": states
        }
