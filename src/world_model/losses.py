"""
Multi-Task Loss Module for NEXUS-Forecast LSTM World Model.
Combines:
1. State Loss: SmoothL1Loss across future horizons K in [1, 3, 6]
2. Attack Loss: BCEWithLogitsLoss with train-derived pos_weight
3. Stage Loss: CrossEntropyLoss over canonical stages
"""

import torch
import torch.nn as nn
from typing import Dict, List, Optional

class MultiTaskWorldModelLoss(nn.Module):
    def __init__(
        self,
        forecast_horizons: List[int] = [1, 3, 6],
        state_weight: float = 1.0,
        attack_weight: float = 1.0,
        stage_weight: float = 0.5,
        pos_weights: Optional[Dict[int, float]] = None
    ):
        super().__init__()
        self.forecast_horizons = forecast_horizons
        self.state_weight = state_weight
        self.attack_weight = attack_weight
        self.stage_weight = stage_weight

        # State regression loss
        self.state_criterion = nn.SmoothL1Loss()

        # Attack classification loss with horizon-specific positive class weighting
        self.attack_criteria = nn.ModuleDict()
        for k in forecast_horizons:
            pw = pos_weights.get(k, 1.0) if pos_weights else 1.0
            # Clamp pos_weight between 0.5 and 10.0 for stability
            pw_clamped = min(max(pw, 0.5), 10.0)
            self.attack_criteria[str(k)] = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([pw_clamped]))

        # Stage classification loss
        self.stage_criterion = nn.CrossEntropyLoss()

    def forward(
        self,
        preds: Dict[str, Dict[int, torch.Tensor]],
        targets: Dict[str, Dict[int, torch.Tensor]]
    ) -> Dict[str, torch.Tensor]:
        """
        Computes weighted total loss and individual loss components.
        """
        total_state_loss = torch.tensor(0.0, device=preds["latent"].device)
        total_attack_loss = torch.tensor(0.0, device=preds["latent"].device)
        total_stage_loss = torch.tensor(0.0, device=preds["latent"].device)

        loss_breakdown = {}

        for k in self.forecast_horizons:
            k_str = str(k)
            # 1. State regression loss
            s_loss = self.state_criterion(preds["state"][k], targets["state"][k])
            total_state_loss = total_state_loss + s_loss
            loss_breakdown[f"state_loss_k{k}"] = s_loss.item()

            # 2. Attack binary classification loss
            criterion = self.attack_criteria[k_str].to(preds["attack"][k].device)
            a_loss = criterion(preds["attack"][k], targets["attack"][k])
            total_attack_loss = total_attack_loss + a_loss
            loss_breakdown[f"attack_loss_k{k}"] = a_loss.item()

            # 3. Stage multi-class classification loss
            st_loss = self.stage_criterion(preds["stage"][k], targets["stage"][k])
            total_stage_loss = total_stage_loss + st_loss
            loss_breakdown[f"stage_loss_k{k}"] = st_loss.item()

        # Normalize by number of horizons
        num_k = float(len(self.forecast_horizons))
        mean_state_loss = total_state_loss / num_k
        mean_attack_loss = total_attack_loss / num_k
        mean_stage_loss = total_stage_loss / num_k

        total_loss = (
            self.state_weight * mean_state_loss +
            self.attack_weight * mean_attack_loss +
            self.stage_weight * mean_stage_loss
        )

        loss_breakdown["total_state_loss"] = mean_state_loss.item()
        loss_breakdown["total_attack_loss"] = mean_attack_loss.item()
        loss_breakdown["total_stage_loss"] = mean_stage_loss.item()
        loss_breakdown["total_loss"] = total_loss

        return loss_breakdown
