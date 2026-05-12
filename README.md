#  CyberSec Expert System
### Cyber Security Threat Detection Expert System
**Built with: Prolog (SWI-Prolog) + Python (CustomTkinter + PySwip)**

---

##  Project Files

```
cybersec_expert_system/
├── knowledge_base.pl     ← Prolog knowledge base (30 facts, 20 rules)
├── prolog_engine.py      ← Python-Prolog bridge (PySwip)
├── gui.py                ← Main GUI application (run this!)
├── requirements.txt      ← Python dependencies
└── README.md             ← This file
```

---

##  Setup Instructions

### Step 1 — Install SWI-Prolog
Download from: https://www.swi-prolog.org/download/stable
-  Check "Add to PATH" during installation
- Verify: open CMD and type `swipl --version`

### Step 2 — Install Python dependencies
```bash
pip install -r requirements.txt
```
Or manually:
```bash
pip install customtkinter pyswip
```

### Step 3 — Run the application
```bash
python gui.py
```

---

##  How It Works

```
User selects symptoms in GUI
         ↓
Python (PySwip) asserts symptoms as Prolog facts
         ↓
Prolog inference engine fires matching rules
         ↓
Threat, severity, and recommendation returned
         ↓
GUI displays results with explanations
```

---

##  Knowledge Base Summary

| Category        | Count |
|----------------|-------|
| Prolog Facts    | 30    |
| Prolog Rules    | 20    |
| Threats Covered | 9     |

### Threats Detected:
1.  Phishing
2.  Malware
3.  Ransomware
4.  Weak Password
5.  Unsafe WiFi
6.  Social Engineering
7.  Keylogger
8.  Spyware
9.  Man-in-the-Middle (MitM) Attack

---

##  Academic Requirements Met

-  30 Prolog Facts (exceeds 25–30 minimum)
-  20 Prolog Rules (exceeds 15–20 minimum)
-  Query Processing (PySwip integration)
-  Decision Explanation Capability
-  Python GUI (CustomTkinter)
-  Python-Prolog Integration (PySwip)
-  Severity Classification
-  Recommendations for each threat

---

##  Demo Mode

If SWI-Prolog is not installed, the app runs in **Demo Mode** using Python-based rules.
The GUI works identically — good for testing the interface.

---
