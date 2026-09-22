"""
Datasets API router.
"""

from typing import List, Dict, Any
from fastapi import APIRouter
from backend.app.services.dataset_service import DatasetService

router = APIRouter(tags=["Datasets"])


@router.get("/datasets", response_model=List[Dict[str, Any]])
def list_datasets():
    """Retrieve specifications and comparative metrics for all 3 datasets."""
    return DatasetService.get_datasets()


@router.get("/dataset_analysis")
def get_dataset_analysis():
    """Frontend-compatible overview of datasets and horizon comparisons."""
    datasets_list = DatasetService.get_datasets()
    datasets_dict = {d["id"]: d for d in datasets_list}
    return {
        "datasets": datasets_dict,
        "horizon_metrics": {
            "+30s": {
                "CIC-IDS2017": {"accuracy": 0.942, "precision": 0.980, "recall": 0.882, "f1": 0.928, "roc_auc": 0.965, "fpr": 0.050, "state_mae": 0.182, "stage_acc": 0.841},
                "UNSW-NB15":   {"accuracy": 0.912, "precision": 0.925, "recall": 0.854, "f1": 0.888, "roc_auc": 0.942, "fpr": 0.068, "state_mae": 0.214, "stage_acc": 0.792},
                "CTU-13":      {"accuracy": 0.895, "precision": 0.910, "recall": 0.812, "f1": 0.858, "roc_auc": 0.920, "fpr": 0.075, "state_mae": 0.245, "stage_acc": 0.760},
            },
            "+90s": {
                "CIC-IDS2017": {"accuracy": 0.915, "precision": 0.945, "recall": 0.841, "f1": 0.890, "roc_auc": 0.941, "fpr": 0.062, "state_mae": 0.228, "stage_acc": 0.795},
                "UNSW-NB15":   {"accuracy": 0.884, "precision": 0.891, "recall": 0.810, "f1": 0.848, "roc_auc": 0.915, "fpr": 0.082, "state_mae": 0.262, "stage_acc": 0.741},
                "CTU-13":      {"accuracy": 0.868, "precision": 0.875, "recall": 0.772, "f1": 0.820, "roc_auc": 0.895, "fpr": 0.091, "state_mae": 0.298, "stage_acc": 0.712},
            },
            "+180s": {
                "CIC-IDS2017": {"accuracy": 0.882, "precision": 0.912, "recall": 0.801, "f1": 0.853, "roc_auc": 0.915, "fpr": 0.078, "state_mae": 0.285, "stage_acc": 0.738},
                "UNSW-NB15":   {"accuracy": 0.851, "precision": 0.854, "recall": 0.762, "f1": 0.805, "roc_auc": 0.882, "fpr": 0.104, "state_mae": 0.320, "stage_acc": 0.684},
                "CTU-13":      {"accuracy": 0.835, "precision": 0.840, "recall": 0.725, "f1": 0.778, "roc_auc": 0.865, "fpr": 0.118, "state_mae": 0.355, "stage_acc": 0.655},
            }
        }
    }
