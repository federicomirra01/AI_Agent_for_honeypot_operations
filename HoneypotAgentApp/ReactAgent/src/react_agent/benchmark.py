"""
Honeypot Benchmark Orchestrator Module

This module provides all necessary components to orchestrate automated benchmarking
of the honeypot firewall agent system.

Usage:
    from honeypot_benchmark_orchestrator import BenchmarkRunner, BenchmarkConfig
    
    runner = BenchmarkRunner(custom_config={'max_epochs': 5})
    results = runner.run()
"""

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
from multiprocessing import Process, Queue

def run_attack_wrapper(attacker, epoch_num, output_queue):
    result = attacker.execute_attack(epoch_num)
    output_queue.put(result)

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
    services_scanned: List[str] = field(default_factory=list)
    exploits_attempted: List[str] = field(default_factory=list)
    flags_captured: List[Dict[str, str]] = field(default_factory=list)
    attack_success_rate: float = 0.0
    
    # Agent metrics
    threats_detected: int = 0
    firewall_rules_added: List[str] = field(default_factory=list)
    firewall_rules_removed: List[int] = field(default_factory=list)
    honeypots_exposed: List[Dict[str, Any]] = field(default_factory=list)
    attack_graph_coverage: Dict[str, float] = field(default_factory=dict)
    
    # System metrics
    total_packets: int = 0
    malicious_packets: int = 0
    blocked_attempts: int = 0
    
    # Final state
    final_honeypot_status: Dict[str, Dict] = field(default_factory=dict)
    agent_decision: str = ""
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
    
    # Agent configuration
    agent_mode: str = "local"  # "local" or "langsmith"
    langsmith_api_key: Optional[str] = None
    
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
            "services_found": [],
            "exploits_attempted": [],
            "flags": [],
            "output": "",
            "exit_code": -1
        }
        
        try:
            # Execute attack script
            exec_result = self.container.exec_run(
                "python3 /attacker/scripts/manager_exploit.py",
                stdout=True,
                stderr=True,
                stream=True,
                demux=True
            )
            
            output_lines = []
            error_lines = []
            
            # Process streaming output
            for stdout_chunk, stderr_chunk in exec_result.output:
                if stdout_chunk:
                    line = stdout_chunk.decode('utf-8')
                    output_lines.append(line)
                    print(f"[ATTACK-{epoch_num}] {line}", end='')
                    
                    # Parse for metrics
                    if "flag{" in line:
                        flag_match = line[line.find("flag{"):line.find("}")+1]
                        results["flags"].append({
                            "flag": flag_match,
                            "service": self._extract_service_from_line(line),
                            "timestamp": time.time()
                        })
                    elif "Detected vulnerable services:" in line:
                        results["services_found"] = self._parse_services(output_lines)
                
                if stderr_chunk:
                    error_line = stderr_chunk.decode('utf-8')
                    error_lines.append(error_line)
                    self.logger.debug(f"[ATTACK-ERR] {error_line}")
            
            results["output"] = "".join(output_lines)
            results["errors"] = "".join(error_lines)
            results["exit_code"] = exec_result.exit_code
            
        except Exception as e:
            self.logger.error(f"Error executing attack: {e}")
            results["error"] = str(e)
        
        return results
    
    def _extract_service_from_line(self, line: str) -> str:
        """Extract service name from output line"""
        services = ["GITLAB", "DOCKER", "STRUTS", "CVE"]
        for service in services:
            if service in line.upper():
                return service
        return "UNKNOWN"
    
    def _parse_services(self, output_lines: List[str]) -> List[str]:
        """Parse detected services from output"""
        # Implementation depends on your output format
        return []
    
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
    
    def __init__(self, config: BenchmarkConfig):
        self.config = config
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
    
    def parse_agent_metrics(self, agent_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract metrics from agent execution result"""
        metrics = {
            "threats_detected": 0,
            "rules_added": [],
            "rules_removed": [],
            "honeypots_exposed": [],
            "attack_graph_status": {},
            "decision": "",
            "lockdown_activated": False
        }
        
        # Parse the final message for ITERATION SUMMARY
        if not agent_result.get('messages'):
            return metrics
            
        last_message = agent_result['messages'][-1]
        if not hasattr(last_message, 'content'):
            return metrics
            
        content = last_message.content
        
        # Extract attack graph progression
        if "ATTACK GRAPH PROGRESSION:" in content:
            lines = content.split('\n')
            for line in lines:
                if "Honeypot" in line and "%" in line:
                    # Parse: - **Honeypot 1 (172.20.0.10):** [66%] - [SSH] - [Status]
                    try:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            ip_match = parts[0].strip().split('(')[-1].split(')')[0]
                            percent_part = parts[1].strip()
                            percent_match = percent_part.split('%')[0].strip('[')
                            metrics["attack_graph_status"][ip_match] = float(percent_match)
                    except Exception as e:
                        self.logger.debug(f"Error parsing honeypot line: {e}")
        
        # Extract honeypot exposure info
        if "Currently Exposed:" in content:
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if "Currently Exposed:" in line:
                    exposed_info = line.split("Currently Exposed:")[-1].strip()
                    if exposed_info != "NONE":
                        metrics["honeypots_exposed"].append(exposed_info)
        
        # Check lockdown status
        if "LOCKDOWN STATUS: ACTIVE" in content:
            metrics["lockdown_activated"] = True
        
        # Extract firewall actions
        if "Rules Applied:" in content:
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if "Rules Applied:" in line:
                    # Parse the rules from subsequent lines
                    j = i + 1
                    while j < len(lines) and lines[j].strip().startswith('-'):
                        rule = lines[j].strip().lstrip('-').strip()
                        if "add_allow_rule" in rule or "add_block_rule" in rule:
                            metrics["rules_added"].append(rule)
                        elif "remove_firewall_rule" in rule:
                            metrics["rules_removed"].append(rule)
                        j += 1
        
        return metrics


class BenchmarkOrchestrator:
    """Main orchestrator for benchmark execution"""
    
    def __init__(self, config: BenchmarkConfig, agent_executor: Optional[Callable] = None):
        self.config = config
        self.agent_executor = agent_executor
        self.attacker = AttackerController(config)
        self.metrics_collector = MetricsCollector(config)
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
            attack_thread = threading.Thread(
                target=lambda: self.attacker.execute_attack(epoch_num)
            )
            attack_thread.start()

            self.logger.info(f"Attack script running with a fallback timeout of {self.config.attack_duration}s...")

            attack_thread.join(timeout=self.config.attack_duration)

            if attack_thread.is_alive():
                self.logger.warning("Attack did not finish in time. Proceeding after timeout fallback.")
            else:
                self.logger.info("Attack script completed before timeout.")

            
            # Phase 3: Wait for monitoring data
            self._phase_transition(BenchmarkPhase.MONITOR_WAIT)
            self.logger.info(f"Accumulating monitoring data for {self.config.monitor_accumulation_wait}s...")
            time.sleep(self.config.monitor_accumulation_wait)
            
            # Phase 4: Execute agent
            self._phase_transition(BenchmarkPhase.AGENT_ANALYSIS)
            if self.agent_executor:
                agent_result = self.agent_executor(epoch_num)
                agent_metrics = self.metrics_collector.parse_agent_metrics(agent_result)
                
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
        if epoch_metrics.attack_graph_coverage:
            all_compromised = all(
                coverage >= 100.0 
                for coverage in epoch_metrics.attack_graph_coverage.values()
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
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
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
        self.orchestrator = BenchmarkOrchestrator(self.config)
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
        if not epochs_data:
            return {}
        
        total_flags = sum(len(e.flags_captured) for e in epochs_data)
        unique_honeypots = set()
        max_coverage = {}
        
        for epoch in epochs_data:
            for ip, coverage in epoch.attack_graph_coverage.items():
                unique_honeypots.add(ip)
                max_coverage[ip] = max(max_coverage.get(ip, 0), coverage)
        
        return {
            "total_flags_captured": total_flags,
            "unique_honeypots_touched": len(unique_honeypots),
            "honeypots_fully_compromised": sum(1 for c in max_coverage.values() if c >= 100),
            "average_epoch_duration": sum(e.end_time - e.start_time for e in epochs_data) / len(epochs_data),
            "lockdown_triggered": any(e.lockdown_activated for e in epochs_data),
            "lockdown_epoch": next((e.epoch_number for e in epochs_data if e.lockdown_activated), None),
            "final_attack_graph_state": max_coverage
        }


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