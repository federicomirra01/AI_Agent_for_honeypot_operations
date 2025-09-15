from typing import Dict, List, Optional, Any, Tuple
from configuration import state
import logging
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _extract_level(levels: List[Dict[str, Any]], ip: str) -> Dict[str, Optional[int]]:
    """
    Find the level info for a specific IP from a list of per-honeypot dicts.
    Returns only the keys present (level_new/level_prev), else empty dict.
    """
    out: Dict[str, Optional[int]] = {}
    for item in levels or []:
        if item.get("ip") == ip:
            # Copy only if present and not None
            if item.get("level_new") is not None:
                out["level_new"] = item["level_new"]
            if item.get("level_prev") is not None:
                out["level_prev"] = item["level_prev"]
            break
    return out

def _pick_levels(lv: Dict[str, Any], fallback_last: Optional[int], fallback_prev: Optional[int]) -> Tuple[Optional[int], Optional[int]]:
    """
    Decide last_level and prev_level for the *current observation*.
    Priority:
      - last_level := level_new if present, else level_prev if present, else fallback_last
      - prev_level := level_prev if present, else fallback_prev (do NOT force to last_level)
    """
    last_level = lv.get("level_new", lv.get("level_prev", fallback_last))
    prev_level = lv.get("level_prev", fallback_prev)
    return last_level, prev_level


def _build_exposure_registry(episodic_memory, limit=20, current_ce=None, current_levels=None):
    """
    Build exposure registry across recent iterations and seed with the *current* snapshot.
    Uses an epoch set per IP to ensure consistent counting, and derives levels
    from (level_new, level_prev) with sensible fallbacks.
    """
    # Temporary working structure
    temp: Dict[str, Dict[str, Any]] = {}
    recent = episodic_memory.get_recent_iterations(limit=limit) or []

    def ensure(ip: str, service: Optional[str] = None):
        if ip not in temp:
            temp[ip] = {
                "service": service,
                "epoch_set": set(),      # collect distinct epochs
                "last_level": None,
                "prev_level": None,
            }
        elif service and not temp[ip].get("service"):
            temp[ip]["service"] = service

    # 1) Fold history
    for item in recent:
        data = getattr(item, "value", item)  # handle wrapper
        ce = data.get("currently_exposed") or {}
        ip = ce.get("ip")
        if not ip:
            continue

        svc = ce.get("service")
        epoch = ce.get("epoch")
        levels = data.get("honeypots_exploitation", {}) or {}
        levels = getattr(levels, "value", levels)
        lv = _extract_level(levels, ip)

        ensure(ip, svc)
        r = temp[ip]
        if epoch is not None:
            r["epoch_set"].add(int(epoch))

        # Update levels with preference to explicit epoch info
        new_last, new_prev = _pick_levels(lv, r["last_level"], r["prev_level"])
        # If we learned a *new* last_level, shift prev_level accordingly ONLY if the current lv didn't specify level_prev.
        if new_last is not None and new_last != r["last_level"]:
            # If level_prev explicitly present, trust it; else roll prev forward.
            if "level_prev" in lv:
                r["prev_level"] = new_prev
            else:
                r["prev_level"] = r["last_level"]
            r["last_level"] = new_last
        else:
            # Even if last_level unchanged, still accept an explicit level_prev
            if "level_prev" in lv:
                r["prev_level"] = new_prev

    # 2) Seed current snapshot (so epoch 1 is captured when store is empty)
    if current_ce and current_ce.get("ip"):
        ip = current_ce["ip"]
        svc = current_ce.get("service")
        epoch = current_ce.get("epoch")
        ensure(ip, svc)

        r = temp[ip]
        if epoch is not None:
            r["epoch_set"].add(int(epoch))

        lv = _extract_level(current_levels or [], ip)
        new_last, new_prev = _pick_levels(lv, r["last_level"], r["prev_level"])

        if new_last is not None and new_last != r["last_level"]:
            if "level_prev" in lv:
                r["prev_level"] = new_prev
            else:
                r["prev_level"] = r["last_level"]
            r["last_level"] = new_last
        else:
            if "level_prev" in lv:
                r["prev_level"] = new_prev

    # 3) Consolidate output
    registry: Dict[str, Dict[str, Any]] = {}
    for ip, r in temp.items():
        epochs = sorted(r["epoch_set"])
        if epochs:
            first_epoch = epochs[0]
            last_epoch = epochs[-1]
            epochs_exposed = len(epochs)          # no off-by-one, no duplicate count
        else:
            first_epoch = 0
            last_epoch = 0
            epochs_exposed = 0

        registry[ip] = {
            "service": r.get("service"),
            "first_epoch": first_epoch,
            "last_epoch": last_epoch,
            "epochs_exposed": epochs_exposed,
            "last_level": r.get("last_level"),
            "prev_level": r.get("prev_level"),
        }

    return registry


def save_iteration(state: state.HoneypotStateReact, config) -> Dict[str, Any]:
    """
    Save iteration summary with structured data for benchmark metrics collection.
    
    Args:
        state: Current honeypot state with all relevant data
        config: Configuration dictionary with episodic memory store
    
    Returns:
        Dict with success status and iteration info
    """
    epoch_num = config.get("configurable", {}).get("epoch_num")
    ce = None
    if state.currently_exposed:
        ce = {
            "ip" : state.currently_exposed.get("ip"),
            "service" : state.currently_exposed.get("service"),
            "current_level":state.currently_exposed.get("current_level"),
            "epoch" : epoch_num
        }
    
    
    episodic_memory = config.get("configurable", {}).get("store")
    exposure_registry = _build_exposure_registry(
        episodic_memory,
        limit=20,
        current_ce=ce,
        current_levels=state.honeypots_exploitation
        )

    iteration_data = {
        #"memory_context": state.memory_context,
        "currently_exposed": ce,
        "exposure_registry":exposure_registry,
        "rules_added": state.rules_added_current_epoch if state.rules_added_current_epoch else [],
        "honeypots_exploitation": state.honeypots_exploitation,
        "lockdown_status": state.lockdown_status,
        "rules_removed": state.rules_removed_current_epoch if state.rules_removed_current_epoch else [],
        "firewall_reasoning": state.firewall_reasoning,
        "inferred_attack_graph": state.inferred_attack_graph,
        "reasoning_inference": state.reasoning_inference,
        "reasoning_exploitation":state.reasoning_exploitation,
        "exploitation_strategy":state.exploitation_strategy,
        "security_events_summary": state.security_events_summary
    }

    # Save to episodic memory
    iteration_id = episodic_memory.save_iteration(iteration_data)
    total_iterations = episodic_memory.get_iteration_count()
    logger.info(f"Iteration saved with ID {iteration_id}. Total iterations: {total_iterations}")
    
    return {
        "success": True,
        "iteration_id": iteration_id,
        "total_iterations": total_iterations,
    }



