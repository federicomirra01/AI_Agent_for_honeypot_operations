from langgraph.store.memory import InMemoryStore
from typing import Dict, List, Any
import time
from datetime import datetime


class EpisodicMemory:

    def __init__(self):
        self.store = InMemoryStore()
        self.namespace = ("honeypot", "episodes")
        self.meta_namespace = ("honeypot", "meta")
        self.iteration_counter = 0

    def save_iteration(self, last_message_content: str) -> str:
        """Save the last message from current iteration"""
        self.iteration_counter += 1
        iteration_id = f"iteration_{self.iteration_counter }"
        
        iteration_data = {
            "id": iteration_id,
            "iteration_number": self.iteration_counter,
            "timestamp": int(time.time()),
            "datetime": datetime.now().isoformat(),
            "last_message": last_message_content
        }

        self.store.put(self.namespace, iteration_id, iteration_data)

        self.store.put(self.meta_namespace, "latest_iteration", self.iteration_counter)

        return iteration_id
    
    def get_recent_iterations(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Retrieve the most recent iterations"""
        iterations = []

        try:
            latest = self.store.get(self.meta_namespace, "latest_iteration")
            if not latest:
                return []
            
            latest = latest.value if hasattr(latest, 'value') else latest
            start_iteration = max(1, latest - limit + 1)

            for i in range(start_iteration, latest + 1):
                iteration_id = f"iteration_{i}"
                iteration_data = self.store.get(self.namespace, iteration_id)
                if iteration_data:
                    iterations.append(iteration_data)
        except Exception as e:
            print(f"Error retrieving iterations: {e}")
        
        return iterations.values() if hasattr(iterations, 'values') else iterations
    
    def get_iteration_count(self) -> int:
        """Get the total number of iterations"""
        try:
            latest = self.store.get(self.meta_namespace, "latest_iteration")
            if latest: 
                latest = latest.value if hasattr(latest, 'value') else latest
            else:
                latest = 0


            return latest 
        except Exception as e:
            print(f"Error retrieving iteration count: {e}")
            return 0
        
    def clear_memory(self):
        """Clear all stored iterations"""
        try:
            # Reset counter
            self.iteration_counter = 0
            self.store.put(self.meta_namespace, "latest_iteration", 0)

            print("Memory counter reset")
        except Exception as e:
            print(f"Error clearing memory: {e}")