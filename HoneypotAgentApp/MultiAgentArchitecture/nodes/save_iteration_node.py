from typing import Dict, List, Optional, Any, Tuple
from configuration import state
import logging
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _extract_epoch_from_item(item: Dict[str, Any]) -> int:
    # Prefer top-level "epoch"; else from currently_exposed.epoch; else 0.
    if item.get("epoch") is not None:
        return int(item["epoch"])
    ce = item.get("currently_exposed") or {}
    if ce.get("epoch") is not None:
        return int(ce["epoch"])
    return 0

def _key_for_entry(ce: Dict[str, Any], key_mode: str) -> Tuple:
    """
    key_mode: "ip" | "ip_service"
    - "ip":   group all services for the same IP together
    - "ip_service": treat a service change on same IP as a distinct track
    """
    ip = ce.get("ip")
    svc = ce.get("service")
    if not ip:
        return tuple()  # empty => not exposed this epoch
    return (ip,) if key_mode == "ip" else (ip, svc)

def build_exposure_registry_from_ce(
    episodic_memory, 
    key_mode: str = "ip", 
    include_current: Optional[Dict[str, Any]] = None,
    current_epoch: Optional[int] = None
    ) -> Dict[str, Dict[str, Any]]:
    """
    Replay history using only `currently_exposed` saved each epoch.

    Returns:
      {
        "<key>": {
          "service": <first non-null service we saw for this key>,
          "first_epoch": int,
          "last_epoch": int,
          "epochs_exposed": int
        },
        ...
      }
    Where <key> is the IP string if key_mode="ip", else "ip|service".
    """
    # 1) Load all iterations (best) or a large recent window.
    try:
        history = episodic_memory.get_all_iterations()
    except AttributeError:
        history = episodic_memory.get_recent_iterations(limit=30) or []

    items: List[Dict[str, Any]] = [getattr(x, "value", x) for x in history]

    if include_current is not None and current_epoch is not None:
        items.append({"epoch":current_epoch, "currently_exposed":include_current})

    items.sort(key=_extract_epoch_from_item)

    registry: Dict[str, Dict[str, Any]] = {}
    seen_in_epoch: Dict[str, int] = {}  # key_str -> last epoch we counted

    for it in items:
        epoch = _extract_epoch_from_item(it)
        ce = it.get("currently_exposed") or {}
        key = _key_for_entry(ce, key_mode)

        # Nothing exposed this epoch (e.g., lockdown) -> skip
        if not key:
            continue

        # Build a stable string key for dict usage
        if key_mode == "ip":
            key_str = key[0]
        else:
            key_str = f"{key[0]}|{key[1]}"

        # Initialize track
        if key_str not in registry:
            registry[key_str] = {
                "service": ce.get("service"),
                "first_epoch": epoch,
                "last_epoch": epoch,
                "epochs_exposed": 0,  # will increment below
            }
            seen_in_epoch[key_str] = None # type: ignore

        # Increment once per epoch per key
        last_counted_epoch = seen_in_epoch.get(key_str)
        if last_counted_epoch != epoch:
            registry[key_str]["epochs_exposed"] += 1
            registry[key_str]["last_epoch"] = epoch
            seen_in_epoch[key_str] = epoch

        # Fill service if not set yet and we have one now
        if not registry[key_str].get("service") and ce.get("service"):
            registry[key_str]["service"] = ce["service"]

    # If you prefer a dict keyed by IP only, return with IP keys.
    # If you want the original shape (keyed by IP) but still counted by ip_service,
    # you can collapse here by summing epochs or keeping the longest track.
    return registry

def save_iteration(state: state.HoneypotStateReact, config) -> Dict[str, Any]:
    epoch_num = config.get("configurable", {}).get("epoch_num")

    ce = None
    if state.currently_exposed:
        ce = {
            "ip": state.currently_exposed.get("ip"), # type: ignore
            "service": state.currently_exposed.get("service"), # type: ignore
            "current_level": state.currently_exposed.get("current_level"), # type: ignore
            "epoch": epoch_num,
        }

    episodic_memory = config.get("configurable", {}).get("store")

    # Build registry purely from currently_exposed history
    exposure_registry = build_exposure_registry_from_ce(episodic_memory, key_mode="ip", include_current=ce, current_epoch=epoch_num)

    iteration_data = {
        "epoch": epoch_num,                         # <--- important
        "currently_exposed": ce,                    # <--- source of truth
        "exposure_registry": exposure_registry,     # <--- persisted summary (nice to have)
        "rules_added": state.rules_added_current_epoch or [],
        "rules_removed": state.rules_removed_current_epoch or [],
        "honeypots_exploitation": state.honeypots_exploitation,
        "lockdown_status": state.lockdown_status,
        "firewall_reasoning": state.firewall_reasoning,
        "inferred_attack_graph": state.inferred_attack_graph,
        "reasoning_inference": state.reasoning_inference,
        "reasoning_exploitation": state.reasoning_exploitation,
        "exploitation_strategy": state.exploitation_strategy,
        "security_events_summary": state.security_events_summary,
    }

    iteration_id = episodic_memory.save_iteration(iteration_data)
    total_iterations = episodic_memory.get_iteration_count()
    logger.info(f"Iteration saved with ID {iteration_id}. Total iterations: {total_iterations}")

    return {"success": True, "iteration_id": iteration_id, "total_iterations": total_iterations}


