from typing import Dict,  Any
from configuration import state
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def save_iteration(state: state.HoneypotStateReact, config) -> Dict[str, Any]:
    """
    Save iteration summary with structured data for benchmark metrics collection.
    
    Args:
        state: Current honeypot state with all relevant data
        config: Configuration dictionary with episodic memory store
    
    Returns:
        Dict with success status and iteration info
    """
    iteration_data = {
        "memory_context": state.memory_context,
        "currently_exposed": state.currently_exposed,
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

    episodic_memory = config.get("configurable", {}).get("store")
    # Save to episodic memory
    iteration_id = episodic_memory.save_iteration(iteration_data)
    total_iterations = episodic_memory.get_iteration_count()
    logger.info(f"Iteration saved with ID {iteration_id}. Total iterations: {total_iterations}")
    
    return {
        "success": True,
        "iteration_id": iteration_id,
        "total_iterations": total_iterations,
    }



