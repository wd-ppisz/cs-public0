# Changelog

## Unreleased

- Kandydat sondy flow (etap E0, nieaktywny domyślnie): obiekt eBPF TCX tylko do
  odczytu na tapach gości i uplinku, rekordy SYN z ISN do korelacji SNAT,
  detektory zachowania w trybie observe. [Opis](docs/flow-probe.md).
- Sonda flow: stan okna detektorów D1–D3 ograniczony niezależnie od tempa
  rekordów (zalew SYN nie zwiększa pamięci ani czasu oceny).
- `flow_ship.py`: wysyłka spoolu sondy do ClickHouse po HTTPS z weryfikacją
  certyfikatu i deterministycznym tokenem deduplikacji partii.
- Updater IP v6: dopuszczalny wiek publikacji 96 h dla Spamhaus, IPsum i FireHOL
  oraz 72 h dla IPInsights, Feodo i OTX. Lista, której dostawca nie wydał przez
  ponad dwa dni, nadal blokuje. ThreatFox zostaje przy 24 h, granicy katalogu
  pasywnego DNS. Ważność zachowanych list wynika z zainstalowanej polityki.
  Playbook instaluje zgodnego następcę obok poprzednika bez przerwy w DROP.

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
