# EXPLAINABILITY METHODOLOGY: INTEGRATED GRADIENTS ON 3D SEQUENCES

NEXUS-Forecast implements path-integral Integrated Gradients (Sundararajan et al., 2017) adapted to 3D temporal sequences (B, 10, 22).
Attribution is computed against the pre-calibration GRU attack logit and decomposed into feature, temporal, and matrix representations.
