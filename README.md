# iOS App Security Assessment Checklist

A practitioner's working checklist for iOS app assessments, organized by OWASP MASVS v2 categories. Each check says what to verify, how to verify it, and how bad it is when it fails.

## How to use it

Work top to bottom during an assessment. Static checks come from code review and tooling (MobSF, manual review of the Xcode project). Dynamic checks come from running the app: a proxy (Burp), runtime inspection (Frida), and a jailbroken or checkra1n test device. Mark each check pass, fail, or not applicable, and note the evidence.

MASVS is the source standard; the checks below are the iOS-specific version of it. Severity assumes a typical consumer app handling accounts or personal data. Adjust up for finance, health, or government apps.

---

## MASVS-STORAGE — Data Storage

### STORAGE-1 — No sensitive data in plaintext preferences
**Verify:** Auth tokens, PII, and secrets are never written to UserDefaults or plist files.
**How:** Static: search for `UserDefaults` writes and review what is stored. Dynamic: pull an app backup and read `Library/Preferences`.
**If failed:** High. Readable from any backup and by any process on a jailbroken device.
**Android equivalent:** SharedPreferences in cleartext; use EncryptedSharedPreferences.

### STORAGE-2 — Keychain items use correct accessibility
**Verify:** Secrets use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (or a justified weaker level), never `Always`.
**How:** Static: review every `SecItemAdd` call and its `kSecAttrAccessible` value.
**If failed:** Medium to High. Weak levels expose secrets on a locked, stolen phone.

### STORAGE-3 — No sensitive data in logs
**Verify:** No tokens, PII, or API responses in `NSLog`, `print`, or `os_log`.
**How:** Static: search for logging calls. Dynamic: watch Console.app while exercising the app.
**If failed:** Medium. Logs persist on device and ship in sysdiagnose files users send to support.

### STORAGE-4 — Sensitive screens hidden in the app switcher
**Verify:** Banking, health, or message content is not visible in the iOS snapshot shown in the app switcher.
**How:** Dynamic: open a sensitive screen, background the app, open the switcher and look.
**If failed:** Medium. Shoulder-surfing and screenshots leak data the app never stored.

### STORAGE-5 — Local databases holding sensitive data are encrypted
**Verify:** Core Data / SQLite files with sensitive content use SQLCipher or equivalent, or hold no sensitive data.
**How:** Dynamic: extract the `.sqlite` file and try opening it in a SQLite browser.
**If failed:** High. Same exposure as plaintext preferences.

### STORAGE-6 — Sensitive input fields disable autocorrect and caching
**Verify:** Password, token, and PII fields use `isSecureTextEntry` or set `autocorrectionType = .no`.
**How:** Static: review text field configuration.
**If failed:** Low to Medium. Keyboard cache and suggestions leak what was typed.

### STORAGE-7 — Sensitive files excluded from backups
**Verify:** Files with secrets set `isExcludedFromBackup`, or the data protection class justifies backup inclusion.
**How:** Static: check file attributes at creation. Dynamic: inspect an unencrypted backup.
**If failed:** Medium. iTunes/Finder backups are a quiet exfiltration path.

---

## MASVS-CRYPTO — Cryptography

### CRYPTO-1 — No hardcoded keys or secrets in the binary
**Verify:** No API keys, encryption keys, or tokens compiled into the app.
**How:** Static: run `strings` on the binary, review with MobSF.
**If failed:** High. Extractable in seconds, not rotatable without an app update.

### CRYPTO-2 — Standard algorithms only
**Verify:** CryptoKit or CommonCrypto (AES-GCM, SHA-256, ECDH). No custom ciphers, no homegrown key derivation.
**How:** Static: code review of crypto helpers.
**If failed:** High. Custom crypto is broken crypto until proven otherwise.

### CRYPTO-3 — Random values come from a secure source
**Verify:** `SecRandomCopyBytes` (or CryptoKit's random generation) for tokens, IVs, and nonces. Not `arc4random` for security purposes, never `rand()`.
**How:** Static: search for random APIs in security-sensitive code.
**If failed:** Medium. Predictable randomness breaks tokens and encryption.

### CRYPTO-4 — TLS everywhere, no unjustified exceptions
**Verify:** No `NSAllowsArbitraryLoads` and no per-domain HTTP exceptions in Info.plist without a documented reason.
**How:** Static: read Info.plist. Dynamic: proxy the app and confirm everything is TLS.
**If failed:** High. Cleartext traffic is readable on any network in the path.

### CRYPTO-5 — Certificate validation is never disabled
**Verify:** No authentication-challenge handler that returns `.useCredential` unconditionally, no trust-all delegates left from debugging.
**How:** Static: search for `didReceive challenge` handlers and `serverTrust` usage.
**If failed:** Critical. The app will accept any certificate, including an attacker's.

---

## MASVS-AUTH — Authentication and Session Management

### AUTH-1 — Biometric auth is bound to the Keychain, not a flag
**Verify:** Sensitive data is protected by `SecAccessControl` with biometry flags. No boolean "biometryPassed" in UserDefaults guarding screens.
**How:** Static: review biometric flows. Dynamic: try flipping the flag or bypassing the check.
**If failed:** High. A flag is not access control.

### AUTH-2 — Sessions die server-side on logout
**Verify:** After logout, the old access and refresh tokens are rejected by the backend.
**How:** Dynamic: capture a token in Burp, log out in the app, replay the token.
**If failed:** Medium. A stolen token stays useful after the user "logged out".

### AUTH-3 — Sensitive actions require fresh authentication
**Verify:** Payments, password changes, and PII exports ask for biometry or password again.
**How:** Dynamic: walk through the sensitive flows.
**If failed:** Medium. An unlocked phone becomes a blank check.

### AUTH-4 — Deep links and URL schemes validate input
**Verify:** Custom URL scheme handlers validate parameters and do not trigger sensitive actions from untrusted links.
**How:** Static: review `scene(_:openURLContexts:)` and scheme handlers.
**If failed:** Medium. Any app or website can fire your URL scheme.

### AUTH-5 - Auth endpoints resist brute force
**Verify:** Login, OTP, and password-reset endpoints throttle or lock out after repeated failures.
**How:** Dynamic: send repeated bad logins through Burp and watch for throttling, CAPTCHA, or temporary lockout.
**If failed:** Medium. Unhindered guessing turns any weak password or short OTP into an entry point.

---

## MASVS-NETWORK — Network Communication

### NETWORK-1 — TLS 1.2 or better, strong cipher suites
**Verify:** The backend negotiates modern TLS; weak protocols and ciphers are off.
**How:** Dynamic: scan the endpoints (testssl.sh, nmap) or inspect the handshake in Burp.
**If failed:** Medium. Downgrade and decryption attacks get easier.

### NETWORK-2 — Certificate pinning on sensitive endpoints
**Verify:** Auth, payment, and PII endpoints pin their public keys; a proxy CA does not get traffic.
**How:** Static: look for a pinning delegate. Dynamic: install Burp's CA on the test device and confirm pinned endpoints refuse the connection.
**If failed:** Medium. Defense in depth: without pinning, any installed CA can intercept.

### NETWORK-3 — No sensitive data in URLs
**Verify:** Tokens, PII, and secrets travel in headers or bodies, never in query strings.
**How:** Dynamic: review Burp history for query parameters.
**If failed:** Medium. URLs end up in proxy logs, analytics, and referer headers.

### NETWORK-4 — Every API endpoint enforces authentication
**Verify:** No endpoint returns or mutates data without a valid token, including "internal" or versioned paths.
**How:** Dynamic: replay requests without the Authorization header; fuzz for hidden endpoints.
**If failed:** High. Client-side checks are not access control.

---

## MASVS-PLATFORM — Platform Interaction

### PLATFORM-1 — Pasteboard is not used for sensitive data
**Verify:** Tokens and PII are not copied to `UIPasteboard`, or the pasteboard is cleared immediately after use.
**How:** Static: search for `UIPasteboard` usage. Dynamic: monitor the pasteboard during sensitive flows.
**If failed:** Low to Medium. Any app can read the general pasteboard.

### PLATFORM-2 — WebViews do not expose native bridges to untrusted content
**Verify:** `WKScriptMessageHandler` bridges are only registered for trusted origins, and messages are validated.
**How:** Static: review every `add(_:name:)` call and what the handler does with the message.
**If failed:** High. A bridge to untrusted web content is remote code execution by another name.

### PLATFORM-3 — IPC and app extensions share the minimum data
**Verify:** App groups and shared Keychain access groups contain only what the extension needs.
**How:** Static: review entitlements and app group containers.
**If failed:** Medium. Over-sharing widens every other finding.

---

## MASVS-CODE — Code Quality

### CODE-1 — No debug code in release builds
**Verify:** No `NSLog`/`print` with internals, no `#if DEBUG` backdoors, debug flags off in the release scheme.
**How:** Static: search for debug symbols, check the release build configuration.
**If failed:** Low. Debug output is STORAGE-3 waiting to happen.

### CODE-2 — Standard exploit mitigations are on
**Verify:** PIE, ARC, and stack canaries are enabled (Xcode defaults; confirm nobody disabled them).
**How:** Static: check build settings and the binary.
**If failed:** Low. Raises the cost of memory-corruption exploits.

### CODE-3 — No sensitive strings in the binary
**Verify:** `strings` output shows endpoints and UI text, not secrets, internal URLs, or debug credentials.
**How:** Static: `strings` on the release binary plus MobSF string analysis.
**If failed:** Medium. See CRYPTO-1.

### CODE-4 — Third-party dependencies are inventoried and current
**Verify:** `Package.resolved` / `Podfile.lock` reviewed; no libraries with known critical CVEs.
**How:** Static: review the lockfiles against public advisories.
**If failed:** Medium. Your app inherits its dependencies' vulnerabilities.

---

## MASVS-RESILIENCE — Reverse Engineering Defenses

These apply based on the threat model, not to every app. A consumer social app and a banking app do not need the same answers. Document the decision either way.

### RESILIENCE-1 — Jailbreak detection, if the risk warrants it
**Verify:** The app detects common jailbreak artifacts and responds per policy (warn, limit, or refuse).
**How:** Dynamic: run on a jailbroken test device.
**Note:** Detection is bypassable by design. It raises the bar; it is not a wall.

### RESILIENCE-2 — Tamper detection on the binary, if warranted
**Verify:** Integrity checks detect repackaged or modified IPAs.
**How:** Dynamic: patch the binary, resign, and run.
**Note:** Same caveat as above. Useful for fraud-sensitive apps, theater for others.

### RESILIENCE-3 — Anti-debugging, if warranted
**Verify:** The app resists casual debugger attachment (e.g., `ptrace` deny).
**How:** Dynamic: attach lldb to the running app.
**Note:** Slows analysts down; does not stop them.

---

## Reference

- OWASP MASVS v2 (the source standard for these categories)
- OWASP MASTG (the testing guide: how to actually run these checks)
- OWASP Mobile Top 10 (the risk list behind the priorities)

Checklist version: 1.0. Built from real iOS assessment work. PRs welcome: if a check is wrong or missing, say so with evidence.
