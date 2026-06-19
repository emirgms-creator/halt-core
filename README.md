# 🛑 Halt Core

**The Zero-Trust Operating System Layer for Autonomous AI Agents.**

Current AI agents are fundamentally flawed. Giving a Large Language Model direct execution access to your terminal or database is like putting a 5-year-old in the driver's seat of a Formula 1 car. They hallucinate, they get tricked by prompt injections, and they make catastrophic mistakes.

**Halt Core** is the safety belt, the airbag, and the emergency brake. It is a sub-millisecond middleware SDK that intercepts, evaluates, and blocks destructive AI agent commands *before* they touch your system.

---

## ⚡ Features

*   **Sub-Millisecond Execution:** Stateless rules (deny-lists) execute in ~0.05ms. Your agents won't even feel the latency.
*   **Stateful Memory Tracking:** AI attacks are often multi-step (e.g., download payload -> make executable -> run). Halt Core remembers the agent's session history and blocks dangerous execution chains.
*   **Semantic Intent Engine (Powered by Microsoft Phi-4):** Bad actors obfuscate commands. Halt Core routes suspicious commands through a local, air-gapped Small Language Model (SLM) to read the *true intent* behind the code.
*   **Zero-Trust "Fail-Secure" Architecture:** If the local LLM daemon goes offline, Halt Core defaults to blocking the action. Security over convenience, always.
*   **Developer-First SDK:** Integrate into any LangChain, CrewAI, or custom Python agent pipeline with exactly two lines of code.

---

## 🛠️ Installation

Halt Core runs locally to ensure maximum data privacy. Your agent's logs never leave your servers.

### 1. Prerequisites
You need [Ollama](https://ollama.com/) installed to run the local semantic engine. Once installed, pull the Phi-4-mini model:

    ollama run phi4-mini

### 2. Install Halt Core
Install the SDK directly via pip:

    pip install halt-core

---

## 🚀 Quick Start

Integrating Halt Core into your existing AI worker is effortless. Pass the agent's intended action to the `evaluate` function before executing it on your host machine.

    from halt_core import evaluate

    # 1. Your AI agent generates a command (e.g., a destructive SQL query)
    agent_command = "DROP TABLE production_users;"

    # 2. Intercept with Halt Core
    decision = evaluate(
        action_type="sql", 
        command=agent_command, 
        agent_id="agent_dba_01"
    )

    # 3. Act on the decision
    if decision["safe"]:
        print("Action Approved. Executing...")
        # Execute the command on your system
    else:
        print(f"🛑 ACTION BLOCKED: {decision['reason']}")
        print(f"💡 Remediation sent back to AI: {decision['remediation']}")

### Expected Output:

    {
      "safe": false,
      "reason": "Action rejected because SQL command contains blocked destructive keyword(s): DROP.",
      "remediation": "Do not execute destructive operations. Use 'SELECT' or consult the administrator. Please try again safely.",
      "latency_ms": 0.106
    }

---

## 🧠 How the Architecture Works

1.  **Fast Lane (Rules & State):** The command is first checked against modular static rules and the in-memory state tracker.
2.  **Deep Inspection (Phi-4):** If the command bypasses static rules but looks structurally complex, it is forwarded to the local `phi4-mini` model.
3.  **Feedback Loop:** Halt Core doesn't just block; it provides structured `remediation` strings. You can feed this string back into your LLM prompt so your agent can learn from its mistake and self-correct.

---

## 🔒 License
MIT License. Built for the future of safe Artificial General Intelligence.