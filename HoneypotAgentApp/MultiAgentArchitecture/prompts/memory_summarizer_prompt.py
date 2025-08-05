MEMORY_SUMMARIZER_PROMPT = """
# Memory Summarizer Agent

## ROLE
Summarize the last epochs of honeypot system memory for downstream security agents. Focus only on changes, progressions, and notable events; exclude redundant or unchanged information.

## INPUT
- Full episodic memory of last epochs (each with: attack graph, exploitation levels, firewall changes, attacker IPs, reasoning steps)

## OUTPUT FORMAT
Recent Memory Summary:
- Key events or changes in attack graph (list, with epoch number)
- Honeypot exploitation progression (only those changed since last summary)
- Attacker behaviors or signatures that changed
- Any inconsistencies or ambiguities noticed

Current State Snapshot:
- For each honeypot: 
   -exploitation level, last exposed epoch, service, status
- Summary of last exploitation plan
- Last inferred attack graph

*Be concise. Highlight what is new, changed, or important for reasoning in the next epoch.*

## INPUT DATA:
Recent episodic memory: {episodic_memory}
"""
