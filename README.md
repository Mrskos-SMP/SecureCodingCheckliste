# Secure Coding Checkliste

## Inhaltsverzeichnis
1. [Allgemeine Sicherheitsgrundsätze](#allgemeine-sicherheitsgrundsätze)
2. [Eingaben validieren](#eingaben-validieren)
3. [Ausgaben und Encoding](#ausgaben-und-encoding)
4. [Authentifizierung und Autorisierung](#authentifizierung-und-autorisierung)
5. [Sitzungsverwaltung](#sitzungsverwaltung)
6. [Fehlerbehandlung und Logging](#fehlerbehandlung-und-logging)
7. [Datenverschlüsselung](#datenverschlüsselung)
8. [Sichere Kommunikation](#sichere-kommunikation)
9. [Datenzugriff](#datenzugriff)
10. [Code-Qualität und -Reviews](#code-qualität-und-reviews)
11. [Abhängigkeiten und Bibliotheken](#abhängigkeiten-und-bibliotheken)
12. [Umgang mit sensiblen Daten](#umgang-mit-sensiblen-daten)
13. [Konfigurationssicherheit](#konfigurationssicherheit)
14. [Sichere API-Entwicklung](#sichere-api-entwicklung)
15. [Sichere Dateiverarbeitung](#sichere-dateiverarbeitung)
16. [Mobile Sicherheit](#mobile-sicherheit)
17. [Sicherheitstests](#sicherheitstests)
18. [Sichere Speicherung](#sichere-speicherung)
19. [Container- und Cloud-Sicherheit](#container-und-cloud-sicherheit)
20. [Benutzeroberfläche und Usability](#benutzeroberfläche-und-usability)
21. [Sicherheitsbewusstes Deployment](#sicherheitsbewusstes-deployment)
22. [Sicherheits-Updates und Patching](#sicherheits-updates-und-patching)

## 1. Allgemeine Sicherheitsgrundsätze
- [ ] **Minimale Berechtigungen:** Anwendungen und Dienste sollten nur die minimal notwendigen Berechtigungen haben.
- [ ] **Fail Secure:** Bei Fehlern sollte das System in einem sicheren Zustand verbleiben.
- [ ] **Verwende Sicherheitsstandards:** Halte dich an bewährte Sicherheitspraktiken und -standards (z.B. OWASP Top 10).
- [ ] **Kritische Sicherheitsaspekte:** Identifiziere kritische Sicherheitsanforderungen in der Software-Architektur.

## 2. Eingaben validieren
- [ ] **Input-Validierung:** Validierung von allen Eingaben (z.B. Nutzer, Dateien, Datenbanken, APIs).
- [ ] **Whitelist-Prinzip:** Verwende Whitelists für erlaubte Eingaben, keine Blacklists.
- [ ] **SQL-Injection verhindern:** Parameterisierte SQL-Abfragen verwenden (Prepared Statements).
- [ ] **Command Injection verhindern:** Eingaben vor der Verwendung in Shell-Befehlen prüfen.
- [ ] **Cross-Site Scripting (XSS):** Validierung und Sanitization aller Benutzereingaben.

## 3. Ausgaben und Encoding
- [ ] **Ausgabe Encoding:** Alle Ausgaben korrekt encodieren (HTML, URL, JavaScript, etc.).
- [ ] **Escape gefährlicher Zeichen:** Besonders bei dynamisch generiertem HTML, SQL oder Shell-Befehlen.
- [ ] **Content Security Policy (CSP):** Für Webanwendungen eine CSP implementieren, um XSS-Angriffe zu erschweren.

## 4. Authentifizierung und Autorisierung
- [ ] **Passwort-Management:** Sichere Passwortspeicherung mittels starker Hash-Verfahren (z.B. bcrypt, Argon2).
- [ ] **Multi-Faktor-Authentifizierung (MFA):** Wo möglich, MFA einführen.
- [ ] **Sichere Sitzung:** Sitzungs-IDs zufällig und schwer vorhersagbar generieren.
- [ ] **Zugriffsrechte:** Vor jedem Zugriff prüfen, ob der Nutzer die notwendige Berechtigung besitzt.

## 5. Sitzungsverwaltung
- [ ] **Sitzungsspeicherung:** Sitzungstokens niemals in URLs oder lokalen Speicher ablegen.
- [ ] **Session Expiry:** Sitzungen nach einer bestimmten Zeit der Inaktivität automatisch beenden.
- [ ] **Sitzungshandling:** Sitzungen invalidieren, wenn der Nutzer sich abmeldet oder sein Passwort ändert.
- [ ] **Secure Cookies:** Sitzungscookies sollten das `Secure` und `HttpOnly` Flag verwenden.

## 6. Fehlerbehandlung und Logging
- [ ] **Keine Details in Fehlermeldungen:** Fehlernachrichten sollten keine sensiblen Daten oder Systemdetails enthalten.
- [ ] **Logging:** Wichtige Ereignisse (Fehlversuche bei der Anmeldung, unberechtigte Zugriffsversuche, etc.) protokollieren.
- [ ] **Sichere Log-Dateien:** Log-Dateien vor unbefugtem Zugriff schützen.
- [ ] **Log-Überwachung:** Protokollierte Ereignisse regelmäßig überwachen und auswerten.

## 7. Datenverschlüsselung
- [ ] **Vertrauliche Daten verschlüsseln:** Sensible Informationen (Passwörter, persönliche Daten, etc.) sollten verschlüsselt gespeichert werden.
- [ ] **Verschlüsselte Kommunikation:** TLS für alle Datenübertragungen verwenden.
- [ ] **Starke Algorithmen:** Nur bewährte und starke Verschlüsselungsalgorithmen einsetzen (z.B. AES-256).
- [ ] **Schlüsselmanagement:** Kryptographische Schlüssel sicher generieren, speichern und verwenden.

## 8. Sichere Kommunikation
- [ ] **TLS:** Verwende TLS (mindestens Version 1.2) für alle Netzwerkkommunikationen.
- [ ] **Zertifikatsprüfung:** Stelle sicher, dass Zertifikate auf Gültigkeit geprüft werden (inklusive Sperrliste).
- [ ] **Keine sensiblen Daten im Klartext:** Vermeide die Übertragung sensibler Daten im Klartext.

## 9. Datenzugriff
- [ ] **Minimaler Datenzugriff:** Nur notwendige Daten sollten abgerufen und verarbeitet werden.
- [ ] **Datenbankverbindungen:** Verbindungen zur Datenbank nur mit minimalen Rechten ausstatten.
- [ ] **ORMs verwenden:** Verwende Object-Relational Mapping (ORM) Frameworks, um direkte SQL-Abfragen zu minimieren.

## 10. Code-Qualität und -Reviews
- [ ] **Code-Reviews:** Alle Änderungen sollten von mindestens einem weiteren Entwickler überprüft werden.
- [ ] **Statische Codeanalyse:** Setze Tools zur statischen Codeanalyse ein, um Schwachstellen frühzeitig zu erkennen.
- [ ] **Unit Tests:** Schreibe Unit Tests, um die korrekte Funktionalität sicherzustellen.
- [ ] **Automatisierte Sicherheits-Tests:** Nutze Sicherheits-Scans (z.B. SAST, DAST) in CI/CD-Pipelines.

## 11. Abhängigkeiten und Bibliotheken
- [ ] **Aktuelle Bibliotheken:** Verwende stets die neuesten stabilen Versionen aller Bibliotheken und Frameworks.
- [ ] **Überprüfung auf Schwachstellen:** Analysiere alle Abhängigkeiten regelmäßig auf bekannte Sicherheitslücken (z.B. mittels Dependency-Scanner).
- [ ] **Externe Bibliotheken:** Minimale Nutzung von Drittanbieter-Bibliotheken und nur, wenn notwendig.
- [ ] **Integrity Checks:** Führe Integritätsprüfungen durch (z.B. Hashes oder Signaturen) für externe Bibliotheken.

## 12. Umgang mit sensiblen Daten
- [ ] **Datenklassifizierung:** Definiere und klassifiziere sensible Daten wie personenbezogene Daten (PII), Zahlungsinformationen (PCI), Gesundheitsdaten (PHI) etc.
- [ ] **Datenminimierung:** Erhebe und speichere nur die Daten, die unbedingt benötigt werden.
- [ ] **Maskierung:** Maskiere sensible Daten (z.B. Kreditkartennummern) bei der Speicherung und Anzeige.
- [ ] **Löschrichtlinien:** Implementiere eine klare Richtlinie für das Löschen sensibler Daten, wenn sie nicht mehr benötigt werden.

## 13. Konfigurationssicherheit
- [ ] **Sichere Standardkonfigurationen:** Entferne oder ändere unsichere Standardkonfigurationen (z.B. Standardpasswörter).
- [ ] **Konfigurationsdateien:** Speichere Konfigurationen getrennt vom Quellcode und nutze Zugangsbeschränkungen für sensible Konfigurationsdateien.
- [ ] **Umgebungsvariablen:** Verwende Umgebungsvariablen, um sensible Informationen wie API-Schlüssel und Passwörter sicher zu verwalten.
- [ ] **Debugging und Tracing:** Deaktiviere Debugging, Tracing und detaillierte Fehlermeldungen in der Produktionsumgebung.

## 14. Sichere API-Entwicklung
- [ ] **API-Authentifizierung:** Verwende starke Authentifizierungsmethoden (z.B. OAuth2, API-Schlüssel).
- [ ] **Rate Limiting:** Implementiere Rate Limiting, um API-Missbrauch zu verhindern.
- [ ] **CORS:** Setze Cross-Origin Resource Sharing (CORS) korrekt ein, um unerlaubten Zugriff von anderen Domänen zu verhindern.
- [ ] **Input- und Output-Validation:** Führe eine strenge Validierung und Sanitization aller API-Eingaben durch.
- [ ] **API-Versionsverwaltung:** Nutze eine Versionskontrolle für APIs, um die Rückwärtskompatibilität zu gewährleisten und Sicherheitsprobleme zu minimieren.

## 15. Sichere Dateiverarbeitung
- [ ] **Datei-Uploads:** Überprüfe alle hochgeladenen Dateien auf Typ, Größe und Inhalt.
- [ ] **Speicherort:** Speichere hochgeladene Dateien außerhalb des Webroot-Verzeichnisses.
- [ ] **Anti-Malware:** Setze Anti-Malware-Scans für hochgeladene Dateien ein.
- [ ] **Keine automatische Verarbeitung:** Vermeide die automatische Ausführung oder Verarbeitung von hochgeladenen Dateien, insbesondere Skripten.

## 16. Mobile Sicherheit
- [ ] **Sichere Speicherung:** Verschlüssele sensible Daten lokal auf dem Gerät.
- [ ] **Transportverschlüsselung:** Verwende TLS für alle Netzwerkverbindungen.
- [ ] **Keine sensiblen Daten im Quellcode:** Hardcode keine sensiblen Informationen wie API-Schlüssel oder Passwörter in der App.
- [ ] **Root/Jailbreak-Prüfung:** Implementiere eine Prüfung, um den Root- oder Jailbreak-Status des Geräts zu erkennen und entsprechend zu reagieren.
- [ ] **Sicheres Backup:** Schütze lokale Daten vor unbefugtem Zugriff bei Backups.

## 17. Sicherheitstests
- [ ] **Penetrationstests:** Führe regelmäßige Penetrationstests durch, um Schwachstellen zu identifizieren und zu beheben.
- [ ] **Threat Modeling:** Führe Threat Modeling durch, um potenzielle Angriffe zu erkennen und abzuwehren.
- [ ] **Fuzzing:** Nutze Fuzzing-Tools, um unerwartetes Verhalten und Schwachstellen durch zufällige Eingaben zu finden.
- [ ] **Kontinuierliche Überwachung:** Implementiere eine kontinuierliche Überwachung auf Sicherheitsvorfälle (Intrusion Detection Systems, SIEM).
- [ ] **Red Teaming:** Simuliere Angriffe durch Red-Teaming-Übungen, um die Reaktionsfähigkeit des Systems und des Teams zu testen.

## 18. Sichere Speicherung
- [ ] **Sensitive Daten:** Verwende für die Speicherung sensibler Daten verschlüsselte Datenbanken oder Dateisysteme.
- [ ] **Zwischenspeicherung:** Vermeide das Cachen sensibler Daten auf Client-Seite (z.B. in Browser-Caches oder lokalen Speicherbereichen).
- [ ] **Speicherverschlüsselung:** Implementiere eine Speicher-Verschlüsselung (z.B. für Datenbanken und Dateisysteme) sowohl auf der Festplatte (at rest) als auch im Speicher (in use).
- [ ] **Passwortverwaltung:** Speichere keine Passwörter in Klartext. Verwende stets Hashing-Methoden wie bcrypt, Argon2 oder PBKDF2 mit einem Salt.

## 19. Container- und Cloud-Sicherheit
- [ ] **Container-Isolation:** Stelle sicher, dass Container ordnungsgemäß isoliert sind und keine sensiblen Daten zwischen den Containern ausgetauscht werden können.
- [ ] **Minimalistisches Container-Image:** Verwende schlanke Container-Images, die nur die notwendigen Pakete und Abhängigkeiten enthalten.
- [ ] **Secrets-Management:** Speichere keine sensiblen Informationen (z.B. API-Schlüssel, Passwörter) im Container-Image. Nutze stattdessen Secrets-Management-Tools.
- [ ] **Netzwerksegmentierung:** Verwende Netzwerksegmentierung, um den Datenverkehr zwischen verschiedenen Containern zu kontrollieren.
- [ ] **Cloud-Konfiguration:** Nutze Cloud-spezifische Sicherheitsfunktionen (z.B. IAM-Rollen, Sicherheitsgruppen) und setze IAM-Richtlinien korrekt auf.
- [ ] **Identitäts- und Zugriffsmanagement:** In Cloud-Umgebungen nur die minimal notwendigen Zugriffsrechte vergeben (Prinzip der geringsten Privilegien).

## 20. Benutzeroberfläche und Usability
- [ ] **Sichere Passwörter erzwingen:** Führe Passwortregeln (Länge, Komplexität) ein, um schwache Passwörter zu vermeiden.
- [ ] **Sichere Passwort-Rücksetzprozesse:** Implementiere sichere Mechanismen für Passwortzurücksetzung (z.B. Multi-Faktor-Authentifizierung).
- [ ] **Sichere Formularverarbeitung:** Verwende CSRF-Tokens in Formularen, um Cross-Site Request Forgery zu verhindern.
- [ ] **Bestätigung bei sicherheitsrelevanten Aktionen:** Implementiere eine Benutzerbestätigung für sicherheitskritische Aktionen (z.B. Kontoänderungen).
- [ ] **Timeout für Sitzungen:** Verwende visuelle Hinweise und automatisches Timeout für inaktive Sitzungen.
- [ ] **Schutz vor Clickjacking:** Nutze HTTP-Header wie `X-Frame-Options` und `Content Security Policy (CSP)` zur Abwehr von Clickjacking-Angriffen.

## 21. Sicherheitsbewusstes Deployment
- [ ] **Sicherheitsüberprüfung vor dem Deployment:** Führe vor jedem Deployment einen umfassenden Sicherheitscheck durch (z.B. automatisierte Sicherheits-Scans).
- [ ] **Deployment Automatisierung:** Nutze CI/CD-Pipelines für automatisiertes, konsistentes und überprüftes Deployment.
- [ ] **Blue-Green-Deployments:** Nutze Blue-Green-Deployments oder Canary-Releases, um eine sichere und kontrollierte Bereitstellung neuer Versionen zu ermöglichen.
- [ ] **Rollback-Strategie:** Implementiere eine automatisierte Rollback-Strategie für den Fall eines fehlerhaften Deployments.
- [ ] **Zugangsbeschränkungen:** Setze strikte Zugangskontrollen für Deployment-Tools und -Systeme.

## 22. Sicherheits-Updates und Patching
- [ ] **Regelmäßige Updates:** Aktualisiere alle Softwarekomponenten regelmäßig, insbesondere sicherheitsrelevante Komponenten wie Webserver, Frameworks und Bibliotheken.
- [ ] **Patch-Management:** Implementiere einen Prozess für schnelles Patching bei Bekanntwerden kritischer Sicherheitslücken.
- [ ] **Notfallplan:** Entwickle einen Notfallplan für Sicherheitsvorfälle, einschließlich Eskalationsprozessen und Verantwortlichkeiten.
- [ ] **Risikoanalyse vor Updates:** Führe vor jedem Sicherheitsupdate eine Risikoanalyse durch, um potenzielle Auswirkungen auf das System zu verstehen.
- [ ] **Automatische Sicherheitsupdates:** Wenn möglich, aktiviere automatische Updates für Systemsoftware und Bibliotheken.
- [ ] **Monitoring:** Überwache alle Systeme auf Hinweise auf potenzielle Sicherheitsvorfälle und Anomalien nach Updates.



## Weitere Ressourcen
- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/publications/detail/sp/800-218/final)
- [CWE/SANS Top 25 Most Dangerous Software Errors](https://cwe.mitre.org/top25/)
