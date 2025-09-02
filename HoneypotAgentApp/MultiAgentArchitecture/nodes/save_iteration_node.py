from typing import Dict,  Any
from configuration import state
import logging
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _extract_level(levels, ip):
    l = {}
    for item in levels:
        if item.get("ip") == ip:
            if "level_new" in item and item["level_new"] is not None:
                l["level_new"] = item["level_new"]
            if "level_prev" in item and item["level_prev"] is not None:
                l["level_prev"] = item["level_prev"]
    
    return l


def _build_exposure_registry(episodic_memory, limit=20, current_ce=None, current_levels=None):
    """
    Build exposure registry across recent iterations and seed with the *current* snapshot
    so epoch 1 is included even when the store is empty.
    """
    registry: Dict[str, Dict[str, Any]] = {}
    recent = episodic_memory.get_recent_iterations(limit=limit) or []

    # Fold over previous epochs (if any)
    for item in recent:
        data = item.value if hasattr(item, "value") else item
        ce = data.get("currently_exposed")
        if not ce or not ce.get("ip"):
            continue

        ip = ce["ip"]
        svc = ce.get("service")
        epoch = ce.get("epoch")

        levels = data.get("honeypots_exploitation", {}) or {}
        levels = levels.value if hasattr(levels, "value") else levels

        lv = _extract_level(levels, ip)
        last_level = lv.get("level_new", lv.get("level_prev"))
        prev_level = lv.get("level_prev")

        if ip not in registry:
            registry[ip] = {
                "service": svc,
                "first_epoch": epoch if epoch is not None else 0,
                "last_epoch": epoch if epoch is not None else 0,
                "epochs_exposed": 1,
                "last_level": last_level,
                "prev_level": prev_level,
            }
        else:
            r = registry[ip]
            r["last_epoch"] = max(r["last_epoch"], epoch if epoch is not None else r["last_epoch"])
            r["epochs_exposed"] += 1
            if last_level is not None:
                r["prev_level"] = r["last_level"]
                r["last_level"] = last_level

    # 🔹 Seed with the *current* snapshot so epoch 1 is captured
    if current_ce and current_ce.get("ip"):
        ip = current_ce["ip"]
        svc = current_ce.get("service")
        epoch = current_ce.get("epoch")
        lv = _extract_level(current_levels or {}, ip)
        last_level = lv.get("level_new", lv.get("level_prev"))
        prev_level = lv.get("level_prev")

        if ip not in registry:
            registry[ip] = {
                "service": svc,
                "first_epoch": epoch if epoch is not None else 0,
                "last_epoch": epoch if epoch is not None else 0,
                "epochs_exposed": 0,
                "last_level": last_level,
                "prev_level": prev_level,
            }
        else:
            r = registry[ip]
            # If we've already seen this IP in history, just ensure last_epoch is up-to-date
            r["last_epoch"] = max(r["last_epoch"], epoch if epoch is not None else r["last_epoch"])
            r["epochs_exposed"] = r["last_epoch"] - r["first_epoch"] + 1
            # Only update levels if we have fresher info.
            if last_level is not None:
                r["prev_level"] = r.get("last_level")
                r["last_level"] = last_level

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
        "exploitation_strategy":state.exploitation_strategy
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



