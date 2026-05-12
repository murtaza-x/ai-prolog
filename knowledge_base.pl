
% ============================================================
%   CYBER SECURITY THREAT DETECTION EXPERT SYSTEM
%   Knowledge Base - Prolog (Facts + Rules)
%   Author: Expert System Project
% ============================================================

% ============================================================
% SECTION 1: FACTS (30 facts total)
% ============================================================

% --- Phishing Indicators (Facts 1-8) ---
suspicious_keyword(urgent).
suspicious_keyword(verify_account).
suspicious_keyword(click_immediately).
suspicious_keyword(winner).
suspicious_keyword(confirm_password).
suspicious_keyword(bank_suspended).
suspicious_keyword(free_gift).
suspicious_keyword(act_now).

% --- Known Unsafe File Extensions (Facts 9-13) ---
dangerous_extension('.exe').
dangerous_extension('.bat').
dangerous_extension('.vbs').
dangerous_extension('.scr').
dangerous_extension('.ps1').

% --- Malware Behavioral Symptoms (Facts 14-18) ---
malware_symptom(slow_performance).
malware_symptom(unexpected_popups).
malware_symptom(high_cpu_usage).
malware_symptom(disabled_antivirus).
malware_symptom(random_crashes).

% --- Unsafe Network Indicators (Facts 19-22) ---
unsafe_network_type(public_wifi).
unsafe_network_type(open_hotspot).
unsafe_network_type(unknown_network).
unsafe_network_type(no_password_wifi).

% --- Weak Password Patterns (Facts 23-27) ---
common_weak_password('123456').
common_weak_password('password').
common_weak_password('admin').
common_weak_password('qwerty').
common_weak_password('abc123').

% --- Safe Security Practices (Facts 28-30) ---
secure_protocol(https).
trusted_antivirus(windows_defender).
trusted_antivirus(kaspersky).

% ============================================================
% SECTION 2: RULES (20 rules total)
% ============================================================

% --- RULE 1: Phishing Detection - Email with suspicious keyword + unknown sender ---
threat(phishing) :-
    symptom(unknown_sender),
    symptom(suspicious_link),
    !.

% --- RULE 2: Phishing via urgent keyword + attachment ---
threat(phishing) :-
    symptom(urgency_in_email),
    symptom(unexpected_attachment),
    !.

% --- RULE 3: Phishing via fake login page ---
threat(phishing) :-
    symptom(redirects_to_login),
    symptom(url_mismatch),
    !.

% --- RULE 4: Phishing via prize/reward scam ---
threat(phishing) :-
    symptom(prize_offer),
    symptom(personal_info_requested),
    !.

% --- RULE 5: Malware - Behavioral symptoms (popups + slow PC) ---
threat(malware) :-
    symptom(unexpected_popups),
    symptom(slow_performance),
    !.

% --- RULE 6: Malware - Antivirus disabled + high CPU ---
threat(malware) :-
    symptom(disabled_antivirus),
    symptom(high_cpu_usage),
    !.

% --- RULE 7: Malware via dangerous file downloaded ---
threat(malware) :-
    symptom(downloaded_exe_from_email),
    symptom(random_crashes),
    !.

% --- RULE 8: Ransomware detection ---
threat(ransomware) :-
    symptom(files_encrypted),
    symptom(ransom_message_displayed),
    !.

% --- RULE 9: Ransomware - Files inaccessible + desktop changed ---
threat(ransomware) :-
    symptom(files_inaccessible),
    symptom(desktop_wallpaper_changed),
    !.

% --- RULE 10: Weak Password Detection ---
threat(weak_password) :-
    symptom(password_too_short),
    !.

% --- RULE 11: Weak password - no special characters ---
threat(weak_password) :-
    symptom(no_special_characters),
    symptom(no_uppercase),
    !.

% --- RULE 12: Weak password - using common password ---
threat(weak_password) :-
    symptom(common_password_used),
    !.

% --- RULE 13: Unsafe WiFi - public open network ---
threat(unsafe_wifi) :-
    symptom(connected_to_public_wifi),
    symptom(no_vpn_active),
    !.

% --- RULE 14: Unsafe WiFi - unknown network ---
threat(unsafe_wifi) :-
    symptom(unknown_network_name),
    symptom(auto_connected),
    !.

% --- RULE 15: Social Engineering Attack ---
threat(social_engineering) :-
    symptom(caller_claims_to_be_it_support),
    symptom(asked_for_password),
    !.

% --- RULE 16: Social Engineering via fake authority ---
threat(social_engineering) :-
    symptom(email_from_ceo_lookalike),
    symptom(urgent_wire_transfer_requested),
    !.

% --- RULE 17: Keylogger suspicion ---
threat(keylogger) :-
    symptom(typed_text_appears_elsewhere),
    symptom(unknown_process_running),
    !.

% --- RULE 18: Spyware detection ---
threat(spyware) :-
    symptom(webcam_light_on_unexpectedly),
    symptom(microphone_active_without_reason),
    !.

% --- RULE 19: Man-in-the-Middle Attack ---
threat(mitm_attack) :-
    symptom(ssl_certificate_warning),
    symptom(on_public_wifi),
    !.

% --- RULE 20: No threat detected ---
threat(no_threat_detected) :-
    \+ threat(phishing),
    \+ threat(malware),
    \+ threat(ransomware),
    \+ threat(weak_password),
    \+ threat(unsafe_wifi),
    \+ threat(social_engineering),
    \+ threat(keylogger),
    \+ threat(spyware),
    \+ threat(mitm_attack).

% ============================================================
% SECTION 3: SEVERITY RULES
% ============================================================

severity(ransomware, critical).
severity(malware, high).
severity(mitm_attack, high).
severity(keylogger, high).
severity(spyware, high).
severity(phishing, medium).
severity(social_engineering, medium).
severity(unsafe_wifi, medium).
severity(weak_password, low).
severity(no_threat_detected, none).

% ============================================================
% SECTION 4: RECOMMENDATION RULES
% ============================================================

recommendation(phishing, 'Do NOT click any links. Report the email. Verify sender identity through official channels. Enable email filtering.').
recommendation(malware, 'Run a full antivirus scan immediately. Disconnect from internet. Do not open any new files. Update your antivirus.').
recommendation(ransomware, 'DISCONNECT from network immediately. Do NOT pay ransom. Contact IT security team. Restore from clean backup.').
recommendation(weak_password, 'Change password immediately. Use 12+ characters with uppercase, lowercase, numbers and symbols. Use a password manager.').
recommendation(unsafe_wifi, 'Disconnect from this network. Use mobile data or trusted VPN. Avoid accessing sensitive accounts on public WiFi.').
recommendation(social_engineering, 'Hang up/ignore. Verify identity through official company number. Never share passwords over phone or email.').
recommendation(keylogger, 'Disconnect from internet. Run antimalware scan. Change all passwords from a clean device. Check startup programs.').
recommendation(spyware, 'Cover webcam. Run spyware removal tool. Check installed applications for unknowns. Factory reset if needed.').
recommendation(mitm_attack, 'Stop all sensitive transactions. Disconnect from WiFi. Use mobile data. Clear browser cache and change passwords.').
recommendation(no_threat_detected, 'No immediate threat detected. Continue practicing safe browsing habits and keep software updated.').

% ============================================================
% SECTION 5: EXPLANATION RULES
% ============================================================

explain(phishing) :- write('EXPLANATION: Phishing is a cyber attack where criminals impersonate trusted entities via email/SMS to steal credentials or install malware. Key indicators include unknown senders, suspicious links, and urgency.').
explain(malware) :- write('EXPLANATION: Malware is malicious software designed to damage or gain unauthorized access. Symptoms include slow performance, popups, and disabled security tools.').
explain(ransomware) :- write('EXPLANATION: Ransomware encrypts your files and demands payment for decryption. It is one of the most dangerous threats. Never pay the ransom as it does not guarantee file recovery.').
explain(weak_password) :- write('EXPLANATION: Weak passwords are easily cracked by brute force or dictionary attacks. A strong password uses 12+ characters with mixed case, numbers, and symbols.').
explain(unsafe_wifi) :- write('EXPLANATION: Public/open WiFi networks lack encryption, allowing attackers to intercept your data. Always use VPN on public networks.').
explain(social_engineering) :- write('EXPLANATION: Social engineering manipulates people psychologically to reveal confidential information. No legitimate IT staff will ever ask for your password.').
explain(keylogger) :- write('EXPLANATION: Keyloggers record every keystroke you make, capturing passwords and sensitive data. They often run silently as background processes.').
explain(spyware) :- write('EXPLANATION: Spyware secretly monitors your activities including webcam and microphone without consent.').
explain(mitm_attack) :- write('EXPLANATION: A Man-in-the-Middle attack intercepts communication between two parties on unsecured networks.').
explain(no_threat_detected) :- write('EXPLANATION: Based on the provided symptoms, no specific cyber threat was identified. Stay vigilant and keep systems updated.').
