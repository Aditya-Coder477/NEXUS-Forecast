"""
Training pipeline and Early Stopping for NEXUS-Forecast LSTM World Model.
Monitors validation performance and checkpoints the best model weights.
"""

import os
import copy
import torch
import numpy as np
from typing import Dict, Any, Optional
from torch.utils.data import DataLoader
from .losses import MultiTaskWorldModelLoss

class WorldModelTrainer:
    def __init__(
        self,
        model: torch.nn.Module,
        criterion: MultiTaskWorldModelLoss,
        optimizer: torch.optim.Optimizer,
        device: torch.device,
        epochs: int = 35,
        patience: int = 7,
        scheduler: Optional[Any] = None
    ):
        self.model = model
        self.criterion = criterion
        self.optimizer = optimizer
        self.device = device
        self.epochs = epochs
        self.patience = patience
        self.scheduler = scheduler

        self.history = {
            "train_loss": [],
            "val_loss": [],
            "train_attack_loss": [],
            "val_attack_loss": [],
            "train_state_loss": [],
            "val_state_loss": [],
            "val_f1_k1": []
        }
        self.best_val_loss = float("inf")
        self.best_model_weights = None
        self.best_epoch = 0

    def fit(self, train_loader: DataLoader, val_loader: DataLoader) -> Dict[str, Any]:
        """Runs the complete training loop with validation checks and early stopping."""
        self.model.to(self.device)
        epochs_no_improve = 0

        print(f">> Starting LSTM World Model Training on {self.device} (Max Epochs={self.epochs}, Patience={self.patience})...")

        for epoch in range(1, self.epochs + 1):
            # --- Training ---
            self.model.train()
            train_losses = []
            train_att_losses = []
            train_st_losses = []

            for batch in train_loader:
                x = batch["x"].to(self.device)
                targets = {
                    "state": {k: v.to(self.device) for k, v in batch["state"].items()},
                    "attack": {k: v.to(self.device) for k, v in batch["attack"].items()},
                    "stage": {k: v.to(self.device) for k, v in batch["stage"].items()}
                }

                self.optimizer.zero_grad()
                preds = self.model(x)
                loss_dict = self.criterion(preds, targets)
                loss = loss_dict["total_loss"]
                loss.backward()

                # Gradient clipping for LSTM stability
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
                self.optimizer.step()

                train_losses.append(loss.item())
                train_att_losses.append(loss_dict["total_attack_loss"])
                train_st_losses.append(loss_dict["total_state_loss"])

            # --- Validation ---
            self.model.eval()
            val_losses = []
            val_att_losses = []
            val_st_losses = []
            all_val_preds_k1 = []
            all_val_targets_k1 = []

            with torch.no_grad():
                for batch in val_loader:
                    x = batch["x"].to(self.device)
                    targets = {
                        "state": {k: v.to(self.device) for k, v in batch["state"].items()},
                        "attack": {k: v.to(self.device) for k, v in batch["attack"].items()},
                        "stage": {k: v.to(self.device) for k, v in batch["stage"].items()}
                    }
                    preds = self.model(x)
                    loss_dict = self.criterion(preds, targets)

                    val_losses.append(loss_dict["total_loss"].item())
                    val_att_losses.append(loss_dict["total_attack_loss"])
                    val_st_losses.append(loss_dict["total_state_loss"])

                    # Collect K=1 predictions for monitoring
                    p_k1 = (torch.sigmoid(preds["attack"][1]) >= 0.50).int().cpu().numpy()
                    all_val_preds_k1.extend(p_k1)
                    all_val_targets_k1.extend(targets["attack"][1].int().cpu().numpy())

            mean_train_loss = float(np.mean(train_losses))
            mean_val_loss = float(np.mean(val_losses))
            mean_train_att = float(np.mean(train_att_losses))
            mean_val_att = float(np.mean(val_att_losses))
            mean_train_st = float(np.mean(train_st_losses))
            mean_val_st = float(np.mean(val_st_losses))

            from sklearn.metrics import f1_score
            val_f1_k1 = float(f1_score(all_val_targets_k1, all_val_preds_k1, pos_label=1, zero_division=0))

            self.history["train_loss"].append(mean_train_loss)
            self.history["val_loss"].append(mean_val_loss)
            self.history["train_attack_loss"].append(mean_train_att)
            self.history["val_attack_loss"].append(mean_val_att)
            self.history["train_state_loss"].append(mean_train_st)
            self.history["val_state_loss"].append(mean_val_st)
            self.history["val_f1_k1"].append(val_f1_k1)

            if self.scheduler:
                self.scheduler.step(mean_val_loss)

            print(
                f"   [Epoch {epoch:02d}/{self.epochs}] "
                f"Train Loss: {mean_train_loss:.4f} (Att: {mean_train_att:.4f}, State: {mean_train_st:.4f}) | "
                f"Val Loss: {mean_val_loss:.4f} (Att: {mean_val_att:.4f}, State: {mean_val_st:.4f}) | "
                f"Val F1 (K=1): {val_f1_k1:.4f}"
            )

            # Early Stopping Check
            if mean_val_loss < self.best_val_loss:
                self.best_val_loss = mean_val_loss
                self.best_model_weights = copy.deepcopy(self.model.state_dict())
                self.best_epoch = epoch
                epochs_no_improve = 0
            else:
                epochs_no_improve += 1
                if epochs_no_improve >= self.patience:
                    print(f"\n   [Early Stopping] No improvement in validation loss for {self.patience} epochs. Stopping at epoch {epoch}.")
                    break

        # Load best weights
        if self.best_model_weights is not None:
            self.model.load_state_dict(self.best_model_weights)
            print(f"   -> Loaded best model weights from Epoch {self.best_epoch} (Val Loss: {self.best_val_loss:.4f}).")

        return {
            "best_epoch": self.best_epoch,
            "best_val_loss": self.best_val_loss,
            "history": self.history
        }

    def save_checkpoint(self, save_path: str):
        """Saves model weights."""
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        torch.save({
            "model_state_dict": self.model.state_dict(),
            "best_val_loss": self.best_val_loss,
            "best_epoch": self.best_epoch,
            "history": self.history
        }, save_path)
        print(f"   -> Saved best model checkpoint to {save_path}")
