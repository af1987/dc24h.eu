<!--
0015-argon2id-and-connection-abuse-protection.md

v0.0.11:
  - select Argon2id and automatic legacy password-hash upgrades
  - decide layered IP, account, reconnect and clone abuse controls

Author: gpt-5.6-sol
Date: 2026-08-22
-->

# ADR-0015: Argon2id and connection-abuse protection

## Status

Accepted

## Date

2026-08-22

## Author

`gpt-5.6-sol`

## Context

Version 0.0.10 created new password records with MD5 for compatibility. MD5 is
fast, unsalted and unsuitable for password storage. The hub also needs active
protection against repeated password failures, excessive sessions from one
address, immediate reconnect loops and multiple equal client fingerprints.
Account-to-IP authorization already exists in MariaDB and must remain an
admission decision.

OWASP recommends Argon2id with at least 19 MiB memory, two iterations and one
degree of parallelism. Its authentication guidance recommends throttling with
care to avoid attacker-controlled account lockout, and its denial-of-service
guidance recommends connection/resource limits and rate limiting.

## Decision

1. Every new password record uses the standard Argon2id PHC format with a
   random 16-byte salt, `m=19456 KiB`, `t=2`, `p=1` and a 32-byte output.
2. Tagged MD5 and PBKDF2-HMAC-SHA256 remain verification-only migration
   formats. After a successful legacy verification, the database performs a
   conditional update to a new Argon2id value. There is no MD5 generation API.
3. `anti_abuse.cpp` and `anti_abuse.hpp` are the paired owner of synchronized,
   monotonic-clock abuse state.
4. `LoginError()` maintains independent sliding windows for the supplied
   account and source IP. When either reaches `password_failure_limit`,
   `AddIPTempBan()` applies `pwd_tmpban` to the current source. A successful
   login clears both relevant windows. The control does not permanently lock
   an account.
5. `AdmitConnection()` checks an active temporary ban, then reconnect timing,
   then `max_users_from_ip`. Admission increments the source count;
   `RecordDisconnect()` releases it and records the disconnect timestamp.
6. A reconnect inside `reconnect_min_interval` receives a temporary ban with
   the generic reason `Reconnecting too fast`.
7. `mAuthIP()` admits an account with no binding or an exact address match and
   is called before NORMAL.
8. `CheckUserClone()` groups the client `AP` and `VE` fields per source IP.
   Detection is active when `clone_detect_count` is nonzero. The count is
   released at disconnect; `clone_det_tban_time` bounds retained observation
   state and `clone_ip_tban_time` bounds the resulting address ban.
9. All counts and durations are validated at startup. Network enforcement runs
   before expensive database/reverse-DNS admission work when the required data
   is already available.
10. ADC BASE VERIFY uses `Tiger(password || random challenge)`, which cannot be
    derived from an Argon2id-only database record. This release does not weaken
    storage by retaining plaintext or a reversible password solely to add
    GPA/PAS. Protected in-hub management therefore remains loopback-only until
    a separately designed authenticated channel is adopted.

## Consequences

- An offline database compromise faces a memory-hard password KDF for all new
  and successfully migrated accounts.
- Legacy hashes disappear opportunistically without a forced password reset.
- Address limits reduce straightforward abuse but may affect many legitimate
  users behind one NAT; operators can raise the bounded configuration values.
- AP/VE is a heuristic, not identity proof. Keeping it disabled with zero is
  supported for environments where similar clients are expected.
- In-memory bans and counters reset with the daemon, avoiding schema writes on
  every network event. Persistent moderation bans remain a separate MariaDB
  control.

## Alternatives considered

### Keep MD5 or PBKDF2 as the write default

Rejected. MD5 is unsuitable; Argon2id is memory-hard and preferred by OWASP.
PBKDF2 remains a legacy reader but is not the best available default here.

### Persist every temporary counter in MariaDB

Rejected for this release because it makes connection floods create database
write amplification. Persistent operator bans and audit rows remain in
MariaDB; short-lived rate state stays local and monotonic.

### Store a reversible ADC password for GPA/PAS

Rejected because compromise of the server key or database would reveal usable
passwords and undo the Argon2id storage guarantee.

## References

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [ADC 1.0.4 specification](https://dc-protocols.github.io/ADC.html)
