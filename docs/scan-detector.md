# Detektor skanów przychodzących (ADR-067), tryb OBSERVE

Stan: **wersja 1, wyłącznie OBSERVE**. Nieaktywny domyślnie. Kontrakt
konfiguracji odrzuca każdy tryb poza `observe` i `off`, więc ta wersja nie może
odrzucić żadnego pakietu. ENFORCE wymaga osobnej, zrecenzowanej wersji i osobnej
decyzji (ADR-067, etap E3).

## Co robi

Skan portów z jednego adresu trafia w dziesiątki celów i tysiące portów, a prawie
żadne połączenie się nie udaje. Legalny klient o dużym tempie łączy się wiele razy
z jedną usługą i kończy handshake. Detektor rozróżnia je więc po **liczbie różnych
nieudanych par (cel, port)** od jednego źródła w oknie czasu, nie po tempie.
Limit tempa per źródło trafiałby legalnych klientów (w kalibracji do 471
połączeń/min na 443 z pełnym handshake).

| Element | Wartość startowa |
|---|---|
| Wejście | EVE `flow` Suricaty, TCP do sieci `protected`, źródło spoza własnych sieci i zakresów specjalnych |
| Nieudany przepływ | klient wysłał SYN, a handshake się nie zakończył (brak odpowiedzi, RST albo SYN-ACK zakończony RST skanera) |
| Reguła | okno 600 s, ≥100 różnych nieudanych par (cel, port) i ≥30 różnych portów |
| Czas dowodu | `flow.start` z EVE; przepływ starszy niż okno jest pomijany (`late`) |
| TTL decyzji | 15 min, powtórka w ciągu 24 h — 60 min, kolejne — 6 h (maksimum) |
| Werdykty | `behavior_only` (zachowanie) i `behavior_reputation` (zachowanie **oraz** adres na liście IOC updatera IP) |

Reputacja jest warunkiem koniecznym, nigdy wystarczającym: IPInsights nadal nie
jest jedynym wejściem żadnej decyzji (ADR-061 po zmianie z 28.11.2026). Werdykt
`behavior_only` jest liczony tylko do porównania (wariant A z ADR-067).

## Tabela nft

Własna tabela `bridge cs_public0_scan` (właściciel w komentarzu
`cs-public0-scan-v1-observe`), łańcuch na haku `forward` z priorytetem **−245**:
po DROP IP intelligence (−250), przed NFQUEUE (−240).

```
set protected      { type ipv4_addr; flags interval; }
set scan_behavior  { type ipv4_addr; flags timeout; size 4096; }   # każda decyzja (wariant A)
set scan_block     { type ipv4_addr; flags timeout; size 4096; }   # zachowanie ∧ reputacja (wariant B)
meta ibrname "public0" meta obrname "public0" ip daddr @protected ip saddr @scan_behavior
    tcp flags & (fin | syn | rst | ack) == syn counter name observed_behavior
meta ibrname "public0" meta obrname "public0" ip daddr @protected ip saddr @scan_block
    tcp flags & (fin | syn | rst | ack) == syn counter name observed_block
```

Reguły nie mają werdyktu: liczniki pokazują, ile początkowych SYN odrzuciłby
ENFORCE (pomiar kontrfaktyczny). Polityka łańcucha to `accept`. Elementy wygasają
w jądrze, a zatrzymany detektor nie zostawia niczego dłużej niż TTL. Pakiet
odrzucony wcześniej przez IP intelligence nie dociera do tej tabeli.

## Bezpieczniki

- Whitelista w konfiguracji (IaC). Wpis to adres albo prefiks nie szerszy niż /24
  z polami `kind` (`reported` albo `own_probe`), `reporter`, `reason`, `added`
  i `expires`. Wpis `reported` musi mieć datę ważności. Po tej dacie wpis przestaje
  działać. Trafienie whitelisty jest liczone, decyzji nie ma.
- Limit decyzji na minutę (domyślnie 60). Po przekroczeniu nie ma nowych decyzji,
  rośnie licznik `rate_limited`.
- Pełny zestaw: brak nowych elementów (fail-open), decyzja jest zgłaszana ze
  statusem `set_full`.
- Ograniczony stan: maksymalnie 20 000 śledzonych źródeł i 400 000 par łącznie.
  Najdawniej aktualizowane źródła są usuwane jako pierwsze. Zalew podrobionych
  adresów usuwa stan, a pamięć nie rośnie.
- EVE jest czytane od końca pliku, bez odtwarzania historii. Obsłużone są obie
  rotacje: zmiana nazwy (stary deskryptor jest czytany do końca) i copytruncate.
  Luki są liczone, nigdy zgadywane.

## Zdarzenia i metryki

Jedna linia JSON na decyzję w `/var/lib/cs-public0-scan/events.jsonl` (schemat
`cs-public0-scan-decision-v1`, `action=observe`, `enforcement=none`), nigdy jedna
na przepływ. Pola wspólne (`observed_unix`, `remote_ip`, `direction`, `category`,
`evidence_kind=scan_decision`, `ioc.matched_sources`) mają kształt, który adapter
Wazuh sensora już normalizuje dla kanałów IP i DNS. Plik rotuje się sam przy 8 MiB
(zmiana nazwy na `.1`).

Metryki `cs_public0_scan_*` w pliku textfile node_exportera nie mają etykiet
z adresami IP: decyzje według werdyktu, klasy przepływów, luki EVE, trafienia
whitelisty, bezpieczniki, liczba elementów zestawów, liczniki `observed_syn_packets`
z jądra, świeżość reputacji i suma czasu do decyzji.

## Instalacja

`ansible/scan.yml` (jeden jawny host, przypięte SHA-256 `scan_detector.py`
i `egress_model.py`). Konfiguracja jest najpierw sprawdzana zainstalowanym kodem
(`scan_detector.py check`), dopiero potem zastępuje bieżącą.
`cs_public0_scan_enable=false` zatrzymuje jednostkę i usuwa własną tabelę
(`withdraw`). Bez restartu Suricaty i bez zmian w tabelach innych właścicieli.

## Weryfikacja

- `tests/test_scan_detector.py`: kontrakt konfiguracji, klasyfikacja EVE, okno,
  whitelista, bezpieczniki, drabina TTL, kontrakt nft, rotacje EVE i przebieg
  usługi z atrapą nft.
- `tests/integration/scan.py` (root, pusty netns): prawdziwa tabela na mostku
  `public0` i surowe ramki. Sprawdza:
  - przekazanie SYN mimo wpisu w zestawie i liczniki wariantów A/B;
  - że SYN-ACK, ACK, RST i cele niechronione nie są liczone;
  - wygaśnięcie elementu w jądrze, limit rozmiaru zestawu i atomową podmianę;
  - współistnienie z DROP IP intelligence;
  - przebieg usługi z prawdziwym jądrem, odtworzenie po restarcie, wycofanie
    i odmowę obcej tabeli.

  Na sensorze test uruchamia się jako
  `systemd-run --wait --pipe --property=PrivateNetwork=yes python3 -B tests/integration/scan.py`.
- `scan_detector.py replay --config … --ioc … --eve <pliki>` odtwarza decyzje na
  zachowanym EVE (także `.gz`) bez jądra i bez zapisu zdarzeń.
