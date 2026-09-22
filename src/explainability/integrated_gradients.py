"""
Native PyTorch Integrated Gradients for NEXUS-Forecast Temporal World Model (Phase 17).
Computes path-integral feature and temporal attribution on 3D sequence tensors:
Input:  [1, 10, 22] (or [B, 10, 22])
Output: [10, 22] attribution matrix along with completeness validation.

Supports:
1. Target "attack": GRU attack logit for horizon K in [1, 3, 6].
2. Target "stage": GRU stage classification logit for class c in [0..8].
"""

import torch
import numpy as np
from typing import Dict, Any, Optional, Tuple


class IntegratedGradientsExplainer:
    def __init__(self, model: torch.nn.Module, device: torch.device):
        self.model = model
        self.device = device
        self.model.eval()

    def attribute(
        self,
        input_tensor: torch.Tensor,       # Shape: (1, 10, 22) or (10, 22)
        baseline_tensor: torch.Tensor,    # Shape: (1, 10, 22) or (10, 22)
        horizon: int = 1,                 # K in [1, 3, 6]
        target_type: str = "attack",      # "attack" or "stage"
        stage_class: Optional[int] = None,# Required if target_type == "stage"
        steps: int = 50,
        tolerance: float = 0.05           # 5% relative tolerance for completeness
    ) -> Dict[str, Any]:
        """
        Computes Integrated Gradients for input_tensor relative to baseline_tensor.
        Returns:
            attribution: (10, 22) numpy array
            completeness: dict with verification metrics
        """
        if input_tensor.ndim == 2:
            input_tensor = input_tensor.unsqueeze(0)
        if baseline_tensor.ndim == 2:
            baseline_tensor = baseline_tensor.unsqueeze(0)

        x = input_tensor.to(self.device).float()
        x_base = baseline_tensor.to(self.device).float()

        # 1. Forward pass at input and baseline to calculate expected difference
        with torch.no_grad():
            out_x = self.model(x)
            out_base = self.model(x_base)

            if target_type == "attack":
                fx = float(out_x["attack"][horizon].cpu().numpy()[0])
                fx_base = float(out_base["attack"][horizon].cpu().numpy()[0])
            elif target_type == "stage":
                if stage_class is None:
                    stage_class = int(torch.argmax(out_x["stage"][horizon], dim=-1).cpu().numpy()[0])
                fx = float(out_x["stage"][horizon][0, stage_class].cpu().numpy())
                fx_base = float(out_base["stage"][horizon][0, stage_class].cpu().numpy())
            else:
                raise ValueError(f"Unknown target_type: {target_type}")

        expected_diff = fx - fx_base

        # 2. Path interpolation: alphas from 1/steps to 1.0
        alphas = torch.linspace(1.0 / steps, 1.0, steps, device=self.device)
        # Create interpolated batch: shape (steps, 10, 22)
        # x_diff: (1, 10, 22)
        x_diff = x - x_base
        
        # Batch interpolation
        interpolated = x_base + alphas.view(-1, 1, 1) * x_diff # (steps, 10, 22)
        interpolated.requires_grad_(True)

        # Forward pass through GRU model
        out_interp = self.model(interpolated)
        if target_type == "attack":
            logits = out_interp["attack"][horizon] # (steps,)
        else:
            logits = out_interp["stage"][horizon][:, stage_class] # (steps,)

        # Backward pass to compute gradients
        grad_outputs = torch.ones_like(logits)
        grads = torch.autograd.grad(
            outputs=logits,
            inputs=interpolated,
            grad_outputs=grad_outputs,
            create_graph=False,
            retain_graph=False
        )[0] # (steps, 10, 22)

        # 3. Average gradients along path and scale by (x - x_base)
        avg_grads = torch.mean(grads, dim=0, keepdim=True) # (1, 10, 22)
        ig_tensor = (x_diff * avg_grads).squeeze(0) # (10, 22)
        ig_matrix = ig_tensor.detach().cpu().numpy() # (10, 22)

        # 4. Completeness Check: sum(IG) ≈ F(X) - F(X')
        actual_sum = float(np.sum(ig_matrix))
        abs_error = abs(actual_sum - expected_diff)
        rel_error = abs_error / (abs(expected_diff) + 1e-5)
        is_complete = bool(rel_error <= tolerance or abs_error <= 0.05)

        completeness_info = {
            "expected_difference": round(expected_diff, 6),
            "attribution_sum": round(actual_sum, 6),
            "absolute_error": round(abs_error, 6),
            "relative_error": round(rel_error, 6),
            "tolerance": tolerance,
            "passed": is_complete,
            "status": "PASS" if is_complete else "FAIL"
        }

        return {
            "attribution_matrix": ig_matrix, # Shape: (10, 22)
            "target_type": target_type,
            "horizon": horizon,
            "stage_class": stage_class,
            "target_output": fx,
            "baseline_output": fx_base,
            "steps": steps,
            "completeness": completeness_info
        }
