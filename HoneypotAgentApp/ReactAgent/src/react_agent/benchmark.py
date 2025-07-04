"""
Honeypot Benchmark Orchestrator Module

This module provides all necessary components to orchestrate automated benchmarking
of the honeypot firewall agent system.

Usage:
    from honeypot_benchmark_orchestrator import BenchmarkRunner, BenchmarkConfig
    
    runner = BenchmarkRunner(custom_config={'max_epochs': 5})
    results = runner.run()
"""
import os
import fcntl
from pathlib import Path
import json
import time
import docker
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
import threading
from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty

# Configure module logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BenchmarkPhase(Enum):
    """Enum defining all benchmark phases"""
    INIT = "initialization"
    ATTACK = "attack_execution"
    MONITOR_WAIT = "monitoring_accumulation"
    AGENT_ANALYSIS = "agent_analysis"
    FIREWALL_UPDATE = "firewall_update_wait"
    METRICS_COLLECT = "metrics_collection"
    EPOCH_COMPLETE = "epoch_complete"


@dataclass
class EpochMetrics:
    """Data class to store metrics for a single epoch"""
    epoch_number: int
    start_time: float
    end_time: float = 0.0
    phase_timings: Dict[str, float] = field(default_factory=dict)
    
    # Attack metrics
    services_detected: List[str] = field(default_factory=list)
    services_successfully_exploited: List[str] = field(default_factory=list)
    exploits_attempted: List[str] = field(default_factory=list)
    flags_captured: List[Dict[str, str]] = field(default_factory=list)
    attack_success_rate: float = 0.0
    
    # Agent metrics
    firewall_rules_added: List[str] = field(default_factory=list)
    firewall_rules_removed: List[int] = field(default_factory=list)
    honeypots_exposed: List[Dict[str, Any]] = field(default_factory=list)
    attack_graph_coverage: Dict[str, float] = field(default_factory=dict)
    
  
    
    # Final state
    final_honeypot_status: Dict[str, Dict] = field(default_factory=dict)
    lockdown_activated: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


@dataclass
class BenchmarkConfig:
    """Configuration for benchmark execution"""
    # Execution settings
    max_epochs: int = 10
    attacker_image: str = "attacker:latest"
    attacker_container_name: str = "attackercontainer-attacker"
    
    # Timing configuration (seconds)
    attack_duration: int = 60
    monitor_accumulation_wait: int = 3
    firewall_update_wait: int = 1
    between_epoch_wait: int = 3
    
    # Network configuration
    attacker_network: str = "192.168.100.0/24"
    honeypot_network: str = "172.20.0.0/24"
    firewall_api_url: str = "http://192.168.200.2:5000"
    monitor_api_url: str = "http://192.168.200.2:6000"
    
    # Benchmark modes
    allow_full_compromise: bool = True
    stop_on_lockdown: bool = True
    clear_memory_between_epochs: bool = False
    
    # Output configuration
    results_dir: str = "./benchmark_results"
    save_detailed_logs: bool = True
    log_level: str = "INFO"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


class AttackerController:
    """Manages attacker container lifecycle and execution"""
    
    def __init__(self, config: BenchmarkConfig):
        self.config = config
        self.docker_client = docker.from_env()
        self.container = None
        self.logger = logging.getLogger(f"{__name__}.AttackerController")
    
    def start(self) -> bool:
        """Start the attacker container"""
        try:
            containers = self.docker_client.containers.list()

            for container in containers:
                if ('attacker' in container.image.tags[0].lower() if container.image.tags else False) or \
                (container.name == self.config.attacker_container_name) or \
                ('attacker' in container.name.lower()):
                    self.container = container
                    self.logger.info(f"Found existing attacker container: {container.name}")
                    break
            if not self.container:
                self.logger.error("No attacker container found. Please ensure it is running")
            
            if self.container.status != 'running':
                self.logger.info(f"Starting container {self.container.name}...")
                self.container.start()
                time.sleep(3)
            
            test_result = self.container.exec_run("echo 'Container ready'", stdout=True)
            if test_result.exit_code == 0:
                self.logger.info("Successfully connected to attacker container")
                return True
            else:
                self.logger.error("Container connection test failed")
                return False
        except Exception as e:
            self.logger.error(f"Failed to connect to attacker container: {e}")
            return False
    
    def execute_attack(self, epoch_num: int) -> Dict[str, Any]:
        """Execute attack script in container"""
        if not self.container:
            return {"error": "Container not started"}
        
        results = {
            "services_detected": [],
            "exploits_attempted": [],
            "services_successfully_exploited": [],
            "flags_captured": [],
            "total_flags": 0,
            "total_services_detected": 0,
            "total_exploits_attempted": 0,
            "output": "",
            "exit_code": -1,
            "timed_out": False
        }

        timeout = self.config.attack_duration
        results_file = "/tmp/benchmark_results/attack_results.json"
        
        try:

            if os.path.exists(results_file):
                os.remove(results_file)
                self.logger.info("Cleared previous attack results file")


            output_queue = Queue()
            exec_result = None
            execution_complete = threading.Event()

            def run_container():
                nonlocal exec_result
                try:
                    exec_result = self.container.exec_run(
                        f"python3 /attacker/scripts/manager_exploit.py {epoch_num}",
                        stdout=True,
                        stderr=True,
                        stream=True
                    )
                    
                    # Stream output to queue
                    for chunk in exec_result.output:
                        if chunk:
                            output_queue.put(chunk.decode('utf-8'))
                    output_queue.put(None)  # Signal completion
                    
                except Exception as e:
                    output_queue.put(f"Container execution error: {e}")
                    output_queue.put(None)
                finally:
                    execution_complete.set()

            container_thread = threading.Thread(target=run_container)
            container_thread.start()

            output_lines = []
            start_time = time.time()

            while True:
                elapsed = time.time() - start_time
                remaining = timeout - elapsed
                
                if remaining <= 0:
                    # Timeout reached - force stop
                    self.logger.warning(f"Attack timeout ({timeout}s) reached - terminating process")
                    self._force_stop_container_process()
                    results["timed_out"] = True
                    break
                
                try:
                    # Wait for output with remaining time
                    chunk = output_queue.get(timeout=min(remaining, 1.0))
                    if chunk is None:  # Completion signal
                        break
                        
                    output_lines.append(chunk)
                    for line in chunk.split('\n'):
                        if line.strip():
                            self.logger.info(f"[ATTACK-{epoch_num}] {line}")
                            
                except Empty:
                    # Queue timeout - check if process still running
                    if execution_complete.is_set():
                        break
                    continue

            container_thread.join(timeout=5)
            if container_thread.is_alive():
                self.logger.warning("Container thread still alive after cleanup timeout")
           
            # At this point, the iterator is exhausted = process completed
            results["output"] = ''.join(output_lines)
            
            # Get exit code (available after stream completion)
            results["exit_code"] = exec_result.exit_code if exec_result else -1

            if results["timed_out"]:
                self.logger.info(f"Attack process terminated due to timeout after {timeout}s")
            else:
                self.logger.info(f"Attack process completed with exit code: {results['exit_code']}")
        
            # Continue with file processing only if not timed out
            if not results["timed_out"]:
                # [Rest of your existing file reading logic here]
                pass
        

            # At this point, the container process has completed
            self.logger.info(f"Attack process completed with exit code: {exec_result.exit_code}")

            max_wait_time = 5
            poll_interval = 1
            elapsed_time = 0

            while elapsed_time < max_wait_time:
                if os.path.exists(results_file):
                    try:
                        with open(results_file, 'r') as f:
                            file_content = f.read()

                            if file_content.strip():
                                summary = json.loads(file_content)
                                benchmark_data = summary.get("BENCHMARK_SUMMARY", {})
                                results["services_detected"] = benchmark_data.get("services_detected", [])
                                results["exploits_attempted"] = benchmark_data.get("exploits_attempted", [])
                                results["services_successfully_exploited"] = benchmark_data.get("services_successfully_exploited", [])
                                results["flags_captured"] = benchmark_data.get("flags_captured", [])
                                results["total_flags"] = benchmark_data.get("total_flags", 0)
                                results["total_services_detected"] = benchmark_data.get("total_services_detected", 0)
                                results["total_exploits_attempted"] = benchmark_data.get("total_exploits_attempted", 0)
                                
                                self.logger.info(f"Successfully read attack results from file: {len(results['flags_captured'])} flags captured")
                                break
                    except PermissionError as e:
                        self.logger.warning(f"Permission denied deleting previous results file: {e}")
                        self.logger.info("Container will overwrite the file")
                    except OSError as e:
                        self.logger.warning(f"Could not clear previous results file: {e}")
                    except (json.JSONDecodeError, PermissionError) as e:
                        self.logger.warning(f"Error reading results file (attampt {elapsed_time}s): {e}")
                    except FileNotFoundError as e:
                        self.logger.warning(f"File not found: {e}")
                else:
                    logger.warning(f"File path does not exists {results_file}")
                time.sleep(poll_interval)
                elapsed_time += poll_interval

            if elapsed_time >= max_wait_time:
                self.logger.warning(f"Timeout waiting for results file after {max_wait_time}s")
        
        except Exception as e:
            self.logger.error(f"Error executing attack: {e}")
            results["error"] = str(e)
        
        return results

    def _force_stop_container_process(self):
        """Force stop any running processes in the container"""
        try:
            # Kill the specific process
            kill_result = self.container.exec_run(
                "pkill -f manager_exploit.py",
                stdout=True,
                stderr=True
            )
            self.logger.info(f"Process kill attempt: exit code {kill_result.exit_code}")
            
            # Alternative: restart the container if needed
            # self.container.restart()
            
        except Exception as e:
            self.logger.error(f"Error stopping container process: {e}")

    def stop(self):
        """Stop and remove attacker container"""
        if self.container:
            try:
                self.container.stop()
                self.container.remove()
                self.logger.info("Stopped and removed attacker container")
            except Exception as e:
                self.logger.error(f"Error stopping container: {e}")


class MetricsCollector:
    """Collects and processes metrics from various sources"""
    
    def __init__(self, config: BenchmarkConfig, episodic_memory=None):
        self.config = config
        self.episodic_memory = episodic_memory
        self.logger = logging.getLogger(f"{__name__}.MetricsCollector")
    
    def collect_firewall_state(self) -> Dict[str, Any]:
        """Collect current firewall rules"""
        try:
            response = subprocess.run(
                ["curl", "-s", f"{self.config.firewall_api_url}/rules"],
                capture_output=True,
                text=True
            )
            
            if response.returncode == 0:
                return json.loads(response.stdout)
            else:
                return {}
                
        except Exception as e:
            self.logger.error(f"Error collecting firewall state: {e}")
            return {}
    
    def parse_agent_metrics(self) -> Dict[str, Any]:
        """Extract metrics from agent execution result"""
        metrics = {
            "rules_added": [],
            "rules_removed": [],
            "honeypots_exposed": "",
            "attack_graph_status": {},
            "decision": "",
            "lockdown_activated": False
        }
        
        # Parse the final message for ITERATION SUMMARY
        if not self.episodic_memory:
            self.logger.warning("No episodic memory provided, returning default metrics")
            return metrics
        recent_iterations = self.episodic_memory.get_recent_iterations(limit=1)[0]
        if not recent_iterations:
            self.logger.warning("No recent iterations found in episodic memory")
            return metrics
        
        
        iteration_data = recent_iterations.value if hasattr(recent_iterations, 'value') else recent_iterations
        logger.info(f"Memory from agent: {iteration_data}")
        try:
            if 'rules_applied' in iteration_data:
                metrics["rules_added"] = iteration_data['rules_applied']
            
            if 'attack_graph_progressions' in iteration_data:
                metrics["attack_graph_status"] = iteration_data['attack_graph_progressions']
            
            if 'currently_exposed' in iteration_data:
                metrics["honeypots_exposed"] = iteration_data['currently_exposed'].split(', ') if isinstance(iteration_data['currently_exposed'], str) else iteration_data['currently_exposed']
            
            if 'decision_rationale' in iteration_data:
                metrics["decision"] = iteration_data['decision_rationale']
            
            if 'lockdown_status' in iteration_data:
                metrics["lockdown_activated"] = iteration_data['lockdown_status'] == 'ACTIVE'
            
        except Exception as e:
            self.logger.error(f"Error extracting metrics from memory: {e}")
        
    
        return metrics
    
    def parse_attack_results(self, attack_results: Dict[str, Any]) -> Dict[str, Any]:
        """Parse attack results and calculate metrics"""
        parsed_metrics = {
            "services_detected": [],
            "exploits_attempted": [],
            "services_successfully_exploited": [],
            "flags_captured": [],
            "attack_success_rate": 0.0
        }
        
        try:
            if "error" in attack_results:
                self.logger.warning(f"Attack had errors: {attack_results['error']}")
                return parsed_metrics
            
            # Extract services
            parsed_metrics["services_detected"] = attack_results.get("services_detected", [])
            parsed_metrics["exploits_attempted"] = attack_results.get("exploits_attempted", [])
            parsed_metrics["services_successfully_exploited"] = attack_results.get("services_successfully_exploited", [])
            parsed_metrics["flags_captured"] = attack_results.get("flags_captured", [])
            
            
            # Calculate success rate
            total_services = len(parsed_metrics["exploits_attempted"])
            successful_services = len(parsed_metrics["flags_captured"])
            
            if total_services > 0:
                parsed_metrics["attack_success_rate"] = (successful_services / total_services) * 100
            else:
                parsed_metrics["attack_success_rate"] = 0.0
            
            self.logger.info(f"Attack metrics: {len(parsed_metrics["flags_captured"])} flags, {total_services} services attempted, {parsed_metrics['attack_success_rate']:.1f}% success rate")
            
        except Exception as e:
            self.logger.error(f"Error parsing attack results: {e}")
        
        return parsed_metrics
    
class BenchmarkOrchestrator:
    """Main orchestrator for benchmark execution"""
    
    def __init__(self, config: BenchmarkConfig, agent_executor: Optional[Callable] = None, episodic_memory=None):
        self.config = config
        self.agent_executor = agent_executor
        self.attacker = AttackerController(config)
        self.metrics_collector = MetricsCollector(config, episodic_memory)
        self.epochs_data: List[EpochMetrics] = []
        self.current_epoch: Optional[EpochMetrics] = None
        self.logger = self._setup_logging()
        
        # Create results directory
        self.results_path = Path(self.config.results_dir) / datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results_path.mkdir(parents=True, exist_ok=True)
        
        # Status tracking
        self.is_running = False
        self.should_stop = False
    
    def _setup_logging(self) -> logging.Logger:
        """Setup orchestrator logging"""
        logger = logging.getLogger(f"{__name__}.Orchestrator")
        logger.setLevel(getattr(logging, self.config.log_level))
        
        # File handler for detailed logs
        if self.config.save_detailed_logs:
            file_handler = logging.FileHandler(
                Path(self.config.results_dir) / "orchestrator.log"
            )
            file_handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        return logger
    
    def set_agent_executor(self, executor: Callable):
        """Set the agent execution function"""
        self.agent_executor = executor
    
    def _phase_transition(self, new_phase: BenchmarkPhase):
        """Record phase transition"""
        phase_name = new_phase.value
        timestamp = time.time()
        
        if self.current_epoch:
            self.current_epoch.phase_timings[phase_name] = timestamp
        
        self.logger.info(f"=== Phase: {phase_name.upper()} ===")
    
    def run_epoch(self, epoch_num: int) -> EpochMetrics:
        """Execute a single benchmark epoch"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"EPOCH {epoch_num} STARTING")
        self.logger.info(f"{'='*60}\n")
        
        # Initialize epoch
        epoch_metrics = EpochMetrics(
            epoch_number=epoch_num,
            start_time=time.time()
        )
        self.current_epoch = epoch_metrics
        
        try:
            # Phase 1: Initialize
            self._phase_transition(BenchmarkPhase.INIT)
            initial_firewall_state = self.metrics_collector.collect_firewall_state()
            
            # Phase 2: Execute attack
            self._phase_transition(BenchmarkPhase.ATTACK)
            self.logger.info(f"Starting attacker script with a fallback timeout of {self.config.attack_duration}s...")
            
            attack_results = self.attacker.execute_attack(epoch_num)

            # NEW: Parse attack results and update epoch metrics
            attack_metrics = self.metrics_collector.parse_attack_results(attack_results)
            epoch_metrics.services_detected = attack_metrics["services_detected"]
            epoch_metrics.services_successfully_exploited = attack_metrics["services_successfully_exploited"]
            epoch_metrics.exploits_attempted = attack_metrics["exploits_attempted"]
            epoch_metrics.flags_captured = attack_metrics["flags_captured"]
            epoch_metrics.attack_success_rate = attack_metrics["attack_success_rate"]
                
            # Phase 3: Wait for monitoring data
            self._phase_transition(BenchmarkPhase.MONITOR_WAIT)
            self.logger.info(f"Accumulating monitoring data for {self.config.monitor_accumulation_wait}s...")
            time.sleep(self.config.monitor_accumulation_wait)
            
            # Phase 4: Execute agent
            self._phase_transition(BenchmarkPhase.AGENT_ANALYSIS)
            if self.agent_executor:
                self.agent_executor(epoch_num)
                agent_metrics = self.metrics_collector.parse_agent_metrics()
                
                # Update epoch metrics
                epoch_metrics.attack_graph_coverage = agent_metrics["attack_graph_status"]
                epoch_metrics.lockdown_activated = agent_metrics["lockdown_activated"]
                epoch_metrics.honeypots_exposed = agent_metrics["honeypots_exposed"]
                epoch_metrics.firewall_rules_added = agent_metrics["rules_added"]
                epoch_metrics.firewall_rules_removed = agent_metrics["rules_removed"]
            else:
                self.logger.warning("No agent executor configured - skipping agent phase")
            
            # Phase 5: Wait for firewall updates
            self._phase_transition(BenchmarkPhase.FIREWALL_UPDATE)
            self.logger.info(f"Waiting {self.config.firewall_update_wait}s for firewall updates...")
            time.sleep(self.config.firewall_update_wait)
            
            # Phase 6: Collect metrics
            self._phase_transition(BenchmarkPhase.METRICS_COLLECT)
            
            # Collect all metrics
            final_firewall_state = self.metrics_collector.collect_firewall_state()
            
            # Complete epoch
            self._phase_transition(BenchmarkPhase.EPOCH_COMPLETE)
            epoch_metrics.end_time = time.time()
            
            # Save epoch results
            self._save_epoch_results(epoch_metrics)
            
        except Exception as e:
            self.logger.error(f"Error in epoch {epoch_num}: {e}")
            epoch_metrics.end_time = time.time()
        
        return epoch_metrics
    
    def _save_epoch_results(self, epoch_metrics: EpochMetrics):
        """Save epoch results to disk"""
        epoch_file = self.results_path / f"epoch_{epoch_metrics.epoch_number:03d}.json"
        
        with open(epoch_file, 'w') as f:
            json.dump(epoch_metrics.to_dict(), f, indent=2)
        
        self.logger.info(f"Saved epoch results to {epoch_file}")
    
    def should_continue(self, epoch_metrics: EpochMetrics) -> bool:
        """Determine if benchmark should continue"""
        if self.should_stop:
            return False
        
        if epoch_metrics.lockdown_activated and self.config.stop_on_lockdown:
            self.logger.info("Lockdown activated - stopping benchmark")
            return False
        
        # Check if all honeypots are fully compromised
        percentages = []
        for v in epoch_metrics.attack_graph_coverage.values():
            percentages.append(v['percentage'])
        if epoch_metrics.attack_graph_coverage:
            all_compromised = all(
                coverage >= 100.0 
                for coverage in percentages
            )
            
            if all_compromised and not self.config.allow_full_compromise:
                self.logger.info("All honeypots fully compromised - stopping benchmark")
                return False
        
        return True
    
    def stop(self):
        """Signal benchmark to stop after current epoch"""
        self.should_stop = True
        self.logger.info("Stop signal received - will stop after current epoch")
    
    def cleanup(self):
        """Cleanup resources"""
        self.logger.info("Cleaning up benchmark resources")
        self.attacker.stop()
        self.is_running = False


class BenchmarkRunner:
    """High-level runner for easy notebook integration"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, episodic_memory=None):
        """Initialize runner with optional config overrides"""
        config_dict = {
            "max_epochs": 10,
            "attack_duration": 60,
            "monitor_accumulation_wait": 30,
            "firewall_update_wait": 10,
            "between_epoch_wait": 20,
            "stop_on_lockdown": True,
            "results_dir": "./benchmark_results"
        }
        
        if config:
            config_dict.update(config)
        
        self.config = BenchmarkConfig(**config_dict)
        self.orchestrator = BenchmarkOrchestrator(self.config, episodic_memory=episodic_memory)
        self.results = None
    
    def set_agent_executor(self, executor: Callable):
        """Set the agent execution function"""
        self.orchestrator.set_agent_executor(executor)
    
    def run(self, agent_executor: Optional[Callable] = None) -> Dict[str, Any]:
        """Run the complete benchmark"""
        if agent_executor:
            self.set_agent_executor(agent_executor)
        
        self.orchestrator.logger.info("Starting benchmark run")
        self.orchestrator.is_running = True
        
        # Start attacker
        if not self.orchestrator.attacker.start():
            return {"error": "Failed to start attacker container"}
        
        try:
            # Run epochs
            for epoch_num in range(1, self.config.max_epochs + 1):
                if self.orchestrator.should_stop:
                    break
                
                epoch_metrics = self.orchestrator.run_epoch(epoch_num)
                self.orchestrator.epochs_data.append(epoch_metrics)
                
                if not self.orchestrator.should_continue(epoch_metrics):
                    break
                
                # Wait between epochs
                if epoch_num < self.config.max_epochs:
                    self.orchestrator.logger.info(
                        f"Waiting {self.config.between_epoch_wait}s before next epoch..."
                    )
                    time.sleep(self.config.between_epoch_wait)
            
            # Generate final report
            self.results = self._generate_report()
            
        finally:
            # Always cleanup
            self.orchestrator.cleanup()
        
        return self.results
    
    def stop(self):
        """Stop the benchmark after current epoch"""
        self.orchestrator.stop()
    
    def get_current_status(self) -> Dict[str, Any]:
        """Get current benchmark status"""
        if not self.orchestrator.is_running:
            return {"status": "not_running"}
        
        return {
            "status": "running",
            "current_epoch": self.orchestrator.current_epoch.epoch_number 
                           if self.orchestrator.current_epoch else None,
            "epochs_completed": len(self.orchestrator.epochs_data),
            "latest_metrics": self.orchestrator.epochs_data[-1].to_dict() 
                            if self.orchestrator.epochs_data else None
        }
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate final benchmark report"""
        epochs_data = self.orchestrator.epochs_data
        
        report = {
            "config": self.config.to_dict(),
            "start_time": epochs_data[0].start_time if epochs_data else 0,
            "end_time": epochs_data[-1].end_time if epochs_data else 0,
            "total_epochs": len(epochs_data),
            "epochs": [e.to_dict() for e in epochs_data],
            "summary": self._generate_summary(epochs_data)
        }
        
        # Save report
        report_file = self.orchestrator.results_path / "benchmark_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.orchestrator.logger.info(f"Saved report to {report_file}")
        
        return report
    
    def _generate_summary(self, epochs_data: List[EpochMetrics]) -> Dict[str, Any]:
        """Generate summary statistics"""
        try:
            if not epochs_data:
                return {}
            
            total_flags = sum(len(e.flags_captured) for e in epochs_data)
            unique_honeypots = set()
            max_coverage = {}
            
            for epoch in epochs_data:
                for ip, coverage in epoch.attack_graph_coverage.items():
                    unique_honeypots.add(ip)
                    max_coverage[ip] = max(max_coverage.get(ip, 0), coverage['percentage'])
            
            return {
                "total_flags_captured": total_flags,
                "unique_honeypots_touched": len(unique_honeypots),
                "honeypots_fully_compromised": sum(1 for c in max_coverage.values() if c >= 100),
                "average_epoch_duration": sum(e.end_time - e.start_time for e in epochs_data) / len(epochs_data),
                "lockdown_triggered": any(e.lockdown_activated for e in epochs_data),
                "lockdown_epoch": next((e.epoch_number for e in epochs_data if e.lockdown_activated), None),
                "final_attack_graph_state": max_coverage
            }
        except Exception as e:
            logger.error(f"Exception: {e}")


def create_benchmark_report(results: Dict[str, Any], output_format: str = "markdown") -> str:
    """Create a formatted report from benchmark results"""
    
    if output_format == "markdown":
        report = f"""# Honeypot Benchmark Report

## Configuration
- Total Epochs: {results['total_epochs']}
- Attack Duration: {results['config']['attack_duration']}s
- Stop on Lockdown: {results['config']['stop_on_lockdown']}

## Summary
- Total Flags Captured: {results['summary']['total_flags_captured']}
- Unique Honeypots Touched: {results['summary']['unique_honeypots_touched']}
- Honeypots Fully Compromised: {results['summary']['honeypots_fully_compromised']}
- Average Epoch Duration: {results['summary']['average_epoch_duration']:.2f}s
- Lockdown Triggered: {results['summary']['lockdown_triggered']}

## Attack Graph Final State
"""
        for ip, coverage in results['summary']['final_attack_graph_state'].items():
            report += f"- {ip}: {coverage}%\n"
        
        return report
    
    elif output_format == "json":
        return json.dumps(results, indent=2)
    
    else:
        return str(results)