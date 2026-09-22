"""
Autoregressive Rollout Module for NEXUS-Forecast World Model.
Simulates multi-step forward state trajectories:
Given historical states S_{t-9}...S_t:
1. Predict S_{t+1} using the direct head or state transition.
2. Feed predicted S_{t+1} into the historical buffer.
3. Iteratively roll forward to predict S_{t+2} ... S_{t+6}.
4. Compare Direct Horizon Prediction vs. Autoregressive Rollout.
"""

import torch
import numpy as np
from typing import Dict, List, Any
from sklearn.metrics import mean_absolute_error, mean_squared_error

class WorldModelRollout:
    def __init__(self, model: torch.nn.Module, device: torch.device):
        self.model = model
        self.device = device

    def simulate_rollout(
        self,
        initial_seq: np.ndarray, # Shape: (1, 10, 22)
        rollout_steps: int = 6
    ) -> np.ndarray:
        """
        Executes an autoregressive multi-step state rollout.
        Returns:
            trajectory: Shape: (rollout_steps, 22) of predicted future state vectors.
        """
        self.model.eval()
        buffer = torch.tensor(initial_seq, dtype=torch.float32, device=self.device) # (1, 10, 22)
        trajectory = []

        with torch.no_grad():
            for step in range(rollout_steps):
                # Predict next immediate state S_{t+1} using K=1 head
                outputs = self.model(buffer)
                next_state = outputs["state"][1] # (1, 22)
                trajectory.append(next_state.cpu().numpy()[0])

                # Autoregressive update: drop earliest window S_{t-9}, append predicted next_state
                # buffer: (1, 10, 22) -> buffer[:, 1:, :] is (1, 9, 22)
                next_state_unsqueezed = next_state.unsqueeze(1) # (1, 1, 22)
                buffer = torch.cat([buffer[:, 1:, :], next_state_unsqueezed], dim=1)

        return np.array(trajectory) # (rollout_steps, 22)

    def evaluate_rollout_vs_direct(
        self,
        X_test: np.ndarray,                 # Shape: (N, 10, 22)
        y_test_states: Dict[int, np.ndarray], # Horizon k -> Shape: (N, 22)
        horizons: List[int] = [1, 3, 6],
        sample_size: int = 200
    ) -> Dict[str, Any]:
        """
        Compares Direct Horizon Prediction vs Autoregressive Rollout on test samples.
        """
        self.model.eval()
        n_samples = min(len(X_test), sample_size)
        indices = np.random.RandomState(42).choice(len(X_test), n_samples, replace=False)

        direct_maes = {k: [] for k in horizons}
        rollout_maes = {k: [] for k in horizons}

        with torch.no_grad():
            for idx in indices:
                x_sample = X_test[idx:idx+1] # (1, 10, 22)
                x_tensor = torch.tensor(x_sample, dtype=torch.float32, device=self.device)

                # 1. Direct prediction
                direct_out = self.model(x_tensor)["state"]

                # 2. Autoregressive rollout up to 6 steps
                rollout_traj = self.simulate_rollout(x_sample, rollout_steps=6) # (6, 22)

                for k in horizons:
                    actual_k = y_test_states[k][idx]
                    pred_direct = direct_out[k].cpu().numpy()[0]
                    # In rollout_traj, 0-indexed: index 0 is +1, index 2 is +3, index 5 is +6
                    pred_rollout = rollout_traj[k - 1]

                    direct_maes[k].append(mean_absolute_error(actual_k, pred_direct))
                    rollout_maes[k].append(mean_absolute_error(actual_k, pred_rollout))

        comparison = {}
        for k in horizons:
            comparison[f"k{k}"] = {
                "horizon": f"+{k*30}s",
                "direct_mae": round(float(np.mean(direct_maes[k])), 4),
                "rollout_mae": round(float(np.mean(rollout_maes[k])), 4),
                "delta": round(float(np.mean(rollout_maes[k]) - np.mean(direct_maes[k])), 4)
            }

        return comparison
