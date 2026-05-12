"""
prolog_engine.py
Cyber Security Expert System — Python-Prolog Bridge
Uses PySwip to interface with SWI-Prolog
"""

import os
from pyswip import Prolog


# Path to the Prolog knowledge base
KB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "knowledge_base.pl")

class CyberSecEngine:
    def __init__(self):
        self.prolog = Prolog()
        self.prolog.consult(KB_PATH)

    def _assert_symptoms(self, symptoms: list[str]):
        """Assert user-selected symptoms as temporary Prolog facts."""
        for s in symptoms:
            self.prolog.assertz(f"symptom({s})")

    def _retract_symptoms(self, symptoms: list[str]):
        """Retract all asserted symptoms after query."""
        for s in symptoms:
            try:
                self.prolog.retract(f"symptom({s})")
            except Exception:
                pass

    def analyze(self, symptoms: list[str]) -> dict:
        """
        Main analysis function.
        Takes a list of symptom atoms, queries Prolog, and returns result dict.
        """
        self._assert_symptoms(symptoms)

        result = {
            "threat": "no_threat_detected",
            "severity": "none",
            "recommendation": "No immediate threat found. Practice safe browsing.",
            "explanation": "No matching threat patterns found for provided symptoms."
        }

        try:
            # Query for threat
            threats_found = list(self.prolog.query("threat(X)"))
            if threats_found:
                threat = str(threats_found[0]["X"])
                result["threat"] = threat

                # Get severity
                sev_query = list(self.prolog.query(f"severity({threat}, S)"))
                if sev_query:
                    result["severity"] = str(sev_query[0]["S"])

                # Get recommendation
                rec_query = list(self.prolog.query(f"recommendation({threat}, R)"))
                if rec_query:
                    result["recommendation"] = str(rec_query[0]["R"])

                # Get explanation
                exp_query = list(self.prolog.query(f"explain({threat})"))
                # explain/1 uses write/1, so explanation is printed; 
                # we provide text-based explanation alternatively:
                result["explanation"] = self._get_explanation_text(threat)

        except Exception as e:
            result["error"] = str(e)

        finally:
            self._retract_symptoms(symptoms)

        return result

    def _get_explanation_text(self, threat: str) -> str:
        """Return human-readable explanation for each threat."""
        explanations = {
            "phishing": (
                "Phishing is a cyber attack where criminals impersonate trusted entities "
                "via email or SMS to steal credentials or install malware. Key indicators "
                "include unknown senders, suspicious links, and urgency tactics."
            ),
            "malware": (
                "Malware is malicious software designed to damage systems or gain "
                "unauthorized access. Common symptoms include slow performance, "
                "unexpected popups, and disabled antivirus software."
            ),
            "ransomware": (
                "Ransomware encrypts your files and demands payment for decryption. "
                "It is one of the most destructive threats. NEVER pay the ransom — "
                "it does not guarantee file recovery."
            ),
            "weak_password": (
                "Weak passwords are easily cracked using brute force or dictionary attacks. "
                "A strong password requires 12+ characters with uppercase, lowercase, "
                "numbers, and special symbols."
            ),
            "unsafe_wifi": (
                "Public or open WiFi networks lack proper encryption, allowing attackers "
                "to intercept your data traffic. Always use a VPN when on public networks."
            ),
            "social_engineering": (
                "Social engineering manipulates people psychologically into revealing "
                "confidential information. Legitimate IT staff will NEVER ask for your "
                "password over phone or email."
            ),
            "keylogger": (
                "Keyloggers secretly record every keystroke you make, capturing passwords "
                "and sensitive data. They often run silently as background processes."
            ),
            "spyware": (
                "Spyware secretly monitors your activities, including webcam and microphone "
                "access, without your knowledge or consent."
            ),
            "mitm_attack": (
                "A Man-in-the-Middle (MitM) attack intercepts communication between two "
                "parties on unsecured networks, allowing the attacker to eavesdrop or "
                "alter data in transit."
            ),
            "no_threat_detected": (
                "Based on the provided symptoms, no specific cyber threat pattern was matched. "
                "Continue practicing safe browsing habits and keep all software updated."
            ),
        }
        return explanations.get(threat, "No detailed explanation available.")

    def get_all_threats(self) -> list[str]:
        """Returns list of all detectable threats from knowledge base."""
        return [
            "phishing", "malware", "ransomware", "weak_password",
            "unsafe_wifi", "social_engineering", "keylogger", "spyware",
            "mitm_attack"
        ]


