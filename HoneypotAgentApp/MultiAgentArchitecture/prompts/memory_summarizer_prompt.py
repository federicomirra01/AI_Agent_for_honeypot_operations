from string import Template

MEMORY_PLAN_SUMMARIZER_PROMPT = Template("""
# Memory Summarizer Agent — Exploitation Plan Focus (Epoch-Aware)

## ROLE
You summarize the last epoch's exploitation plan specifically for the Exploitation Manager Agent, and maintain a compact, epoch-indexed history log.
Output only the summary of the last epoch, taking into account the information provided by the previous epochs in case nothing changed.
## INPUTS
- Exposure plan episodic memory of the last epoch: $episodic_memory
- memory summaries: $previous_summary
- Current epoch number: $epoch_num

## SUMMARY RULES
1. PRIORITIZE:
   a. Which honeypot was exposed (IP, service) and in which epoch there was **first exposure** (if newly exposed, state: "first exposed in epoch {epoch_num}").
   b. Exploitation level before → after (if changed).
   c. Whether policy rules were followed (e.g., single exposure, no re-exposure of 100%).
   d. Any rotation/diversity decisions.
   e. Any anomalies or deviations.

2. BE CONCISE:
   - Use ≤ 3 short bullets for the current epoch OR a single sentence if enough.
   - Avoid raw logs, low-level firewall details, unchanged info, or speculation.

3. CHANGE-FOCUSED:
   - If identical to previous epoch's plan, write:
     "No change from previous epoch; same honeypot exposed."


## OUTPUT FORMAT

- "Epoch {current_epoch - 1}: <one-line summary>"
- If needed, follow with up to two bullets for clarity.
...

## EXAMPLES for epoch 8 summary

  - "Epoch 7: Exposed 172.20.0.5 (HTTP); exploitation rose 33%→66%; rotation applied; policy respected."
""")
