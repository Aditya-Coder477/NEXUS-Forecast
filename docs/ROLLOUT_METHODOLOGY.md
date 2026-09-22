# Documentation: Multi-Step Autoregressive Rollout Methodology

## 1. Concept: Direct Horizon vs. Autoregressive Rollout

In NEXUS-Forecast, temporal network forecasting can be performed in two distinct operational regimes:

### 1.1 Direct Horizon Forecasting
Direct horizon heads map the final hidden state $h_t$ directly to future targets at fixed offsets ($K \in \{1, 3, 6\}$):
$$\hat{S}_{t+K} = g_{\text{state}, K}(h_t)$$
- **Pros**: Zero exposure to compounding errors; each head is trained specifically for its forward delay.
- **Cons**: Requires separate prediction heads for each discrete horizon.

### 1.2 Autoregressive Rollout Simulation
Autoregressive rollout uses only the single-step transition head ($K=1$, $+30$s) iteratively to roll the world model forward in continuous time:
$$\hat{S}_{t+1} = g_{\text{state}, 1}(\text{GRU}([S_{t-9}, \dots, S_t]))$$
$$\hat{S}_{t+2} = g_{\text{state}, 1}(\text{GRU}([S_{t-8}, \dots, S_t, \hat{S}_{t+1}]))$$
$$\dots$$
$$\hat{S}_{t+6} = g_{\text{state}, 1}(\text{GRU}([S_{t-4}, \dots, \hat{S}_{t+5}]))$$

---

## 2. Invariant Rules for Rollout Inference
1. **Zero Ground-Truth Contamination**: At no point during multi-step rollout are actual ground-truth future states substituted into the input buffer.
2. **Causal History Buffer**: At each step $\tau$, the oldest state is popped and the newly forecasted state vector $\hat{S}_\tau$ is appended to the tail of the buffer.
3. **Sequential Head Querying**: At each rolled step, the attack likelihood head and stage head evaluate the latent representation of the simulated state sequence, generating the multi-step trajectory:
   $$P_{\text{attack}}(t+1), P_{\text{attack}}(t+2), \dots, P_{\text{attack}}(t+6)$$
