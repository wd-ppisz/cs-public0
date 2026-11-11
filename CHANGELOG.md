# Changelog

## Unreleased

Brak dodatkowych zmian po wydaniu 1.1.0.

## 1.1.0 — 2026-11-11

- Automatyczna kwalifikacja wybranych reguł ALERT → DROP: CISA KEV, FIRST EPSS,
  przypięty silnik i reguły, replay dodatni/legalny/egress oraz kontrolowany canary.
- Profil technologiczny ogranicza nowe promocje do jawnego stosu i widocznych
  protokołów; ogólny korpus testowy zachowuje przykłady innych technologii.
- Kolektor egress z trwałym kursorem, dowodami EVE i klasyfikacją rewizji 2.
  IPInsights jest wyłącznie kontekstem reputacji ingress, bez blokowania.
- Niezależne feedy IP/IOC i inwentarz SID/rev/CVE. IPsum3 oraz Spamhaus mogą
  blokować tylko początkowy TCP SYN ingress do chronionej sieci; egress pozostaje
  bez blokad reputacyjnych. Daty pobrania, ważność i rzeczywisty apply są rozdzielone.
- Pasywny DNS EVE v3 i dokładne dopasowanie domen ThreatFox, bez DNS RPZ.
- Poprawki wzrostu feedów, odnowienia TTL i zachowania cache, kursora oraz historii
  podczas migracji; niezmienione cykle nie udają nowego wdrożenia.
- Playbooki, metryki i dokumentacja integracji z centralnym monitoringiem.
- Ograniczenie NFQUEUE/fail-open pozostaje znane. G6 i kwalifikacja konkretnej
  instalacji nie wynikają z numeru wydania. [Szczegóły](docs/releases/v1.1.0.md).

## 1.0.0 — 2026-10-30

- Parameterized IPv4 bridge/NFQUEUE controller with scoped table ownership.
- Explicit Ansible activation and systemd lifecycle.
- Alert-only configuration, local telemetry, alerts and dashboard.
- Offline regression tests and disposable namespace dataplane smoke.
- Installation, rollback, compatibility and security documentation.
