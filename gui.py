"""
gui.py
Cyber Security Threat Detection Expert System
Main GUI Application — Built with CustomTkinter
"""

import customtkinter as ctk
from tkinter import messagebox
import threading
import sys
import os

# ─── Try importing Prolog engine ───────────────────────────────────────────────
try:
    from prolog_engine import CyberSecEngine
    PROLOG_AVAILABLE = True
except ImportError:
    PROLOG_AVAILABLE = False

# ─── App Configuration ─────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# ─── Color Palette ─────────────────────────────────────────────────────────────
COLORS = {
    "bg_dark":      "#0a0e1a",
    "bg_panel":     "#0f1629",
    "bg_card":      "#141c33",
    "accent_blue":  "#1e90ff",
    "accent_cyan":  "#00d4ff",
    "accent_green": "#00ff88",
    "accent_red":   "#ff3b5c",
    "accent_orange":"#ff8c00",
    "accent_yellow":"#ffd700",
    "text_primary": "#e8f4fd",
    "text_dim":     "#7a8ba0",
    "critical":     "#ff0040",
    "high":         "#ff4500",
    "medium":       "#ff8c00",
    "low":          "#ffd700",
    "none":         "#00ff88",
}

SEVERITY_COLORS = {
    "critical": COLORS["critical"],
    "high":     COLORS["high"],
    "medium":   COLORS["medium"],
    "low":      COLORS["low"],
    "none":     COLORS["none"],
}

THREAT_ICONS = {
    "phishing":           "🎣",
    "malware":            "🦠",
    "ransomware":         "🔒",
    "weak_password":      "🔑",
    "unsafe_wifi":        "📡",
    "social_engineering": "🎭",
    "keylogger":          "⌨️",
    "spyware":            "👁️",
    "mitm_attack":        "🕵️",
    "no_threat_detected": "✅",
}

# ─── Symptom Categories & their Prolog atoms ──────────────────────────────────
SYMPTOM_GROUPS = {
    "📧  Email / Phishing": [
        ("Unknown or suspicious sender",      "unknown_sender"),
        ("Email contains suspicious link",    "suspicious_link"),
        ("Urgency / pressure in email",       "urgency_in_email"),
        ("Unexpected attachment received",    "unexpected_attachment"),
        ("Email redirects to login page",     "redirects_to_login"),
        ("URL doesn't match the company",     "url_mismatch"),
        ("Prize / reward offer in email",     "prize_offer"),
        ("Email asks for personal info",      "personal_info_requested"),
        ("Email from CEO-lookalike account",  "email_from_ceo_lookalike"),
        ("Wire transfer urgently requested",  "urgent_wire_transfer_requested"),
    ],
    "🦠  Malware / System": [
        ("PC is running very slowly",         "slow_performance"),
        ("Random popups appearing",           "unexpected_popups"),
        ("CPU usage is unusually high",       "high_cpu_usage"),
        ("Antivirus got disabled by itself",  "disabled_antivirus"),
        ("PC crashes randomly",               "random_crashes"),
        ("Ran an .exe from email/web",        "downloaded_exe_from_email"),
        ("Files are encrypted / locked",      "files_encrypted"),
        ("Ransom message on screen",          "ransom_message_displayed"),
        ("Files suddenly inaccessible",       "files_inaccessible"),
        ("Desktop wallpaper changed itself",  "desktop_wallpaper_changed"),
    ],
    "🔑  Password Security": [
        ("Password is less than 8 characters","password_too_short"),
        ("Password has no special characters","no_special_characters"),
        ("Password has no uppercase letters", "no_uppercase"),
        ("Using a very common password",      "common_password_used"),
    ],
    "📡  Network / WiFi": [
        ("Connected to public WiFi",          "connected_to_public_wifi"),
        ("No VPN is active",                  "no_vpn_active"),
        ("Network name is unknown/random",    "unknown_network_name"),
        ("Device auto-connected to WiFi",     "auto_connected"),
        ("SSL certificate warning appeared",  "ssl_certificate_warning"),
        ("Currently on public WiFi",          "on_public_wifi"),
    ],
    "🎭  Social Engineering": [
        ("Caller claims to be IT support",    "caller_claims_to_be_it_support"),
        ("Someone asked for your password",   "asked_for_password"),
        ("Unknown process running in background","unknown_process_running"),
        ("Typed text appears in other apps",  "typed_text_appears_elsewhere"),
        ("Webcam light on unexpectedly",      "webcam_light_on_unexpectedly"),
        ("Microphone active without reason",  "microphone_active_without_reason"),
    ],
}


class CyberSecApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("🛡️  CyberSec Expert System — Threat Detection")
        self.geometry("1200x800")
        self.minsize(1000, 700)
        self.configure(fg_color=COLORS["bg_dark"])

        # Engine
        self.engine = None
        if PROLOG_AVAILABLE:
            try:
                self.engine = CyberSecEngine()
            except Exception as e:
                messagebox.showwarning("Prolog Warning",
                    f"Could not load Prolog engine:\n{e}\n\nRunning in demo mode.")

        # Symptom checkboxes dict
        self.symptom_vars = {}

        self._build_ui()

    # ─────────────────────────────────────────────────────────────────────────
    # UI Builder
    # ─────────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        """Build the full application layout."""
        # Main container
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_body()
        self._build_footer()

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color=COLORS["bg_panel"],
                              corner_radius=0, height=80)
        header.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        header.grid_columnconfigure(1, weight=1)
        header.grid_propagate(False)

        # Shield icon + title
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.grid(row=0, column=0, padx=24, pady=16, sticky="w")

        ctk.CTkLabel(title_frame, text="🛡️", font=ctk.CTkFont(size=36)).grid(
            row=0, column=0, rowspan=2, padx=(0, 12))
        ctk.CTkLabel(title_frame, text="CyberSec Expert System",
                     font=ctk.CTkFont(family="Courier New", size=20, weight="bold"),
                     text_color=COLORS["accent_cyan"]).grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(title_frame, text="AI-Powered Threat Detection  |  Prolog + Python",
                     font=ctk.CTkFont(size=11),
                     text_color=COLORS["text_dim"]).grid(row=1, column=1, sticky="w")

        # Status badge
        status_color = COLORS["accent_green"] if PROLOG_AVAILABLE else COLORS["accent_orange"]
        status_text  = "● PROLOG ENGINE ONLINE" if PROLOG_AVAILABLE else "● DEMO MODE"
        ctk.CTkLabel(header, text=status_text,
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=status_color).grid(row=0, column=2, padx=24)

    def _build_body(self):
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=16, pady=(12, 0))
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        self._build_symptom_panel(body)
        self._build_result_panel(body)

    def _build_symptom_panel(self, parent):
        """Left panel — symptom checkboxes."""
        left = ctk.CTkFrame(parent, fg_color=COLORS["bg_panel"], corner_radius=12)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        # Panel header
        ph = ctk.CTkFrame(left, fg_color=COLORS["bg_card"], corner_radius=8)
        ph.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 0))
        ctk.CTkLabel(ph, text="⚠️  Select Observed Symptoms",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=COLORS["text_primary"]).pack(side="left", padx=16, pady=10)

        # Scrollable symptom area
        scroll = ctk.CTkScrollableFrame(left, fg_color="transparent",
                                        scrollbar_button_color=COLORS["accent_blue"])
        scroll.grid(row=1, column=0, sticky="nsew", padx=12, pady=12)
        scroll.grid_columnconfigure(0, weight=1)

        for group_name, symptoms in SYMPTOM_GROUPS.items():
            # Group label
            grp_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"], corner_radius=6)
            grp_frame.pack(fill="x", pady=(6, 2))
            ctk.CTkLabel(grp_frame, text=group_name,
                         font=ctk.CTkFont(size=12, weight="bold"),
                         text_color=COLORS["accent_cyan"]).pack(anchor="w", padx=12, pady=6)

            # Checkboxes
            for label, atom in symptoms:
                var = ctk.BooleanVar(value=False)
                self.symptom_vars[atom] = var
                cb = ctk.CTkCheckBox(
                    scroll, text=label, variable=var,
                    font=ctk.CTkFont(size=12),
                    text_color=COLORS["text_primary"],
                    fg_color=COLORS["accent_blue"],
                    hover_color=COLORS["accent_cyan"],
                    border_color=COLORS["accent_blue"],
                    checkmark_color="#ffffff",
                )
                cb.pack(anchor="w", padx=24, pady=2)

        # Buttons row
        btn_frame = ctk.CTkFrame(left, fg_color="transparent")
        btn_frame.grid(row=2, column=0, padx=12, pady=12, sticky="ew")
        btn_frame.grid_columnconfigure((0, 1), weight=1)

        self.analyze_btn = ctk.CTkButton(
            btn_frame, text="🔍  Analyze Threat",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=COLORS["accent_blue"],
            hover_color="#1565c0",
            height=44,
            command=self._run_analysis,
        )
        self.analyze_btn.grid(row=0, column=0, padx=(0, 6), sticky="ew")

        ctk.CTkButton(
            btn_frame, text="🗑️  Clear All",
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["bg_card"],
            hover_color="#1e2a40",
            border_color=COLORS["text_dim"],
            border_width=1,
            height=44,
            command=self._clear_all,
        ).grid(row=0, column=1, padx=(6, 0), sticky="ew")

    def _build_result_panel(self, parent):
        """Right panel — results display."""
        right = ctk.CTkFrame(parent, fg_color=COLORS["bg_panel"], corner_radius=12)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(4, weight=1)

        # Panel header
        ph = ctk.CTkFrame(right, fg_color=COLORS["bg_card"], corner_radius=8)
        ph.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 0))
        ctk.CTkLabel(ph, text="📊  Analysis Results",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=COLORS["text_primary"]).pack(side="left", padx=16, pady=10)

        # Threat name card
        self.threat_card = ctk.CTkFrame(right, fg_color=COLORS["bg_card"],
                                        corner_radius=10, height=100)
        self.threat_card.grid(row=1, column=0, sticky="ew", padx=12, pady=(12, 6))
        self.threat_card.grid_propagate(False)
        self.threat_card.grid_columnconfigure(1, weight=1)

        self.threat_icon_lbl = ctk.CTkLabel(self.threat_card, text="🛡️",
                                             font=ctk.CTkFont(size=40))
        self.threat_icon_lbl.grid(row=0, column=0, padx=(16, 8), pady=8)

        info_col = ctk.CTkFrame(self.threat_card, fg_color="transparent")
        info_col.grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(info_col, text="DETECTED THREAT",
                     font=ctk.CTkFont(size=10),
                     text_color=COLORS["text_dim"]).pack(anchor="w")
        self.threat_name_lbl = ctk.CTkLabel(info_col, text="Awaiting Analysis...",
                                             font=ctk.CTkFont(size=18, weight="bold"),
                                             text_color=COLORS["text_primary"])
        self.threat_name_lbl.pack(anchor="w")

        # Severity bar
        sev_frame = ctk.CTkFrame(right, fg_color=COLORS["bg_card"], corner_radius=8)
        sev_frame.grid(row=2, column=0, sticky="ew", padx=12, pady=6)
        ctk.CTkLabel(sev_frame, text="SEVERITY LEVEL",
                     font=ctk.CTkFont(size=10),
                     text_color=COLORS["text_dim"]).pack(anchor="w", padx=14, pady=(8, 2))
        self.severity_lbl = ctk.CTkLabel(sev_frame, text="—",
                                          font=ctk.CTkFont(size=22, weight="bold"),
                                          text_color=COLORS["text_dim"])
        self.severity_lbl.pack(anchor="w", padx=14, pady=(0, 10))

        # Recommendation box
        rec_frame = ctk.CTkFrame(right, fg_color=COLORS["bg_card"], corner_radius=8)
        rec_frame.grid(row=3, column=0, sticky="ew", padx=12, pady=6)
        ctk.CTkLabel(rec_frame, text="💡  RECOMMENDED ACTIONS",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=COLORS["accent_yellow"]).pack(anchor="w", padx=14, pady=(10, 4))
        self.rec_text = ctk.CTkTextbox(rec_frame, height=100,
                                        fg_color="transparent",
                                        font=ctk.CTkFont(size=12),
                                        text_color=COLORS["text_primary"],
                                        wrap="word", state="disabled")
        self.rec_text.pack(fill="x", padx=14, pady=(0, 10))

        # Explanation box
        exp_frame = ctk.CTkFrame(right, fg_color=COLORS["bg_card"], corner_radius=8)
        exp_frame.grid(row=4, column=0, sticky="nsew", padx=12, pady=(6, 12))
        exp_frame.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(exp_frame, text="📖  THREAT EXPLANATION (Decision Basis)",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=COLORS["accent_cyan"]).grid(row=0, column=0,
                                                             sticky="w", padx=14, pady=(10, 4))
        self.exp_text = ctk.CTkTextbox(exp_frame, fg_color="transparent",
                                        font=ctk.CTkFont(size=12),
                                        text_color=COLORS["text_primary"],
                                        wrap="word", state="disabled")
        self.exp_text.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 10))
        exp_frame.grid_columnconfigure(0, weight=1)

    def _build_footer(self):
        footer = ctk.CTkFrame(self, fg_color=COLORS["bg_panel"],
                              corner_radius=0, height=36)
        footer.grid(row=2, column=0, sticky="ew")
        footer.grid_propagate(False)
        ctk.CTkLabel(footer,
                     text="Expert System Project  |  Knowledge Base: 30 Facts · 20 Rules  |  Prolog + Python (PySwip)",
                     font=ctk.CTkFont(size=10),
                     text_color=COLORS["text_dim"]).pack(side="left", padx=20, pady=8)

    # ─────────────────────────────────────────────────────────────────────────
    # Logic
    # ─────────────────────────────────────────────────────────────────────────

    def _run_analysis(self):
        """Collect selected symptoms and query Prolog engine."""
        selected = [atom for atom, var in self.symptom_vars.items() if var.get()]

        if not selected:
            messagebox.showinfo("No Symptoms Selected",
                                "Please select at least one symptom to analyze.")
            return

        self.analyze_btn.configure(state="disabled", text="⏳  Analyzing...")
        threading.Thread(target=self._analyze_thread, args=(selected,),
                         daemon=True).start()

    def _analyze_thread(self, selected_symptoms):
        try:
            if self.engine:
                result = self.engine.analyze(selected_symptoms)
            else:
                result = self._demo_analyze(selected_symptoms)
            self.after(100, self._display_result, result)
        except Exception as e:
            self.after(100, self._display_error, str(e))

    def _display_result(self, result: dict):
        """Update UI with analysis results."""
        threat   = result.get("threat", "no_threat_detected")
        severity = result.get("severity", "none")
        rec      = result.get("recommendation", "—")
        exp      = result.get("explanation", "—")

        # Format threat name
        threat_display = threat.replace("_", " ").title()
        icon = THREAT_ICONS.get(threat, "⚠️")
        color = SEVERITY_COLORS.get(severity, COLORS["text_dim"])

        self.threat_icon_lbl.configure(text=icon)
        self.threat_name_lbl.configure(text=threat_display, text_color=color)
        self.severity_lbl.configure(
            text=f"{'●' * {'critical':4,'high':3,'medium':2,'low':1,'none':0}.get(severity,0)}  {severity.upper()}",
            text_color=color
        )

        self._set_textbox(self.rec_text, rec)
        self._set_textbox(self.exp_text, exp)

        self.analyze_btn.configure(state="normal", text="🔍  Analyze Threat")

    def _display_error(self, error: str):
        messagebox.showerror("Analysis Error", f"An error occurred:\n{error}")
        self.analyze_btn.configure(state="normal", text="🔍  Analyze Threat")

    def _set_textbox(self, widget, text):
        widget.configure(state="normal")
        widget.delete("0.0", "end")
        widget.insert("0.0", text)
        widget.configure(state="disabled")

    def _clear_all(self):
        for var in self.symptom_vars.values():
            var.set(False)
        self.threat_icon_lbl.configure(text="🛡️")
        self.threat_name_lbl.configure(text="Awaiting Analysis...",
                                       text_color=COLORS["text_primary"])
        self.severity_lbl.configure(text="—", text_color=COLORS["text_dim"])
        self._set_textbox(self.rec_text, "")
        self._set_textbox(self.exp_text, "")

    # ─────────────────────────────────────────────────────────────────────────
    # Demo Mode (runs without Prolog for testing UI)
    # ─────────────────────────────────────────────────────────────────────────

    def _demo_analyze(self, symptoms: list) -> dict:
        """Simple Python-based demo if Prolog is unavailable."""
        rules = [
            ({"unknown_sender", "suspicious_link"}, "phishing", "medium",
             "Do NOT click any links. Report the email. Verify sender identity.",
             "Phishing detected: email from unknown sender with suspicious link."),
            ({"unexpected_popups", "slow_performance"}, "malware", "high",
             "Run antivirus scan immediately. Disconnect from internet.",
             "Malware detected: slow system performance with unexpected popups."),
            ({"files_encrypted", "ransom_message_displayed"}, "ransomware", "critical",
             "Disconnect from network immediately. Contact IT security. Restore from backup.",
             "Ransomware: files are encrypted and ransom message displayed."),
            ({"password_too_short"}, "weak_password", "low",
             "Change password. Use 12+ characters with mixed case, numbers and symbols.",
             "Password too short — vulnerable to brute force attacks."),
            ({"connected_to_public_wifi", "no_vpn_active"}, "unsafe_wifi", "medium",
             "Disconnect or use VPN. Avoid sensitive accounts on public WiFi.",
             "Unsafe WiFi: connected to public network without VPN protection."),
            ({"caller_claims_to_be_it_support", "asked_for_password"}, "social_engineering", "medium",
             "Hang up. Verify identity through official number. Never share passwords.",
             "Social engineering: caller requesting password while claiming IT support."),
        ]

        symptom_set = set(symptoms)
        for required, threat, severity, rec, exp in rules:
            if required.issubset(symptom_set):
                return {"threat": threat, "severity": severity,
                        "recommendation": rec, "explanation": exp}

        return {
            "threat": "no_threat_detected",
            "severity": "none",
            "recommendation": "No immediate threat found. Practice safe browsing.",
            "explanation": "No matching threat patterns found for the selected symptoms.",
        }


# ─── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = CyberSecApp()
    app.mainloop()
