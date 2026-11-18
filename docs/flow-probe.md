# Sonda flow: obserwacja pierwszych pakietów na tapach gości i uplinku

Stan: **kandydat (etap E0)**, nieaktywny domyślnie i niebędący częścią wydania 1.1.
Instalacja na hoście nie jest odbiorem; wymaga osobnych bramek LAB.

## Cel i granica

Sonda zbiera metadane pierwszych pakietów połączeń w dwóch miejscach:

| Program | Dołączenie | Co widzi |
|---|---|---|
| `flow_guest_out` | TCX ingress na tapie gościa (np. `vnetN`) | ruch wychodzący z VM, **przed** routerem i SNAT |
| `flow_guest_in` | TCX egress na tapie gościa | odpowiedzi do VM (SYN-ACK, RST) — liczniki nieudanych prób |
| `flow_uplink` | TCX egress na uplinku mostu (np. VLAN publiczny) | ten sam ruch **po** SNAT |

Rekord (IPv4 TCP SYN bez ACK) zawiera czas, interfejs, adresy, porty, numer
sekwencyjny (ISN), TTL i IP ID. SNAT w netfilterze nie zmienia ISN, więc
złączenie `(adres docelowy, port docelowy, ISN)` po obu stronach przypisuje
publiczny `IP:port` do konkretnego tapu — bez zgadywania i bez zmian w routerze
CloudStack. Korelacja i magazyn są poza tym komponentem.

Sonda **niczego nie blokuje**: każdy program zwraca `TCX_NEXT` (kontynuacja
łańcucha innych właścicieli), nie przekierowuje i nie modyfikuje pakietów.
Pełny kolejka rekordów oznacza zgubiony rekord (licznik), nigdy opóźnienie pakietu.

## Dlaczego TCX, a nie `clsact`

Limity pasma libvirt (np. oferty CloudStack) instalują na tapach qdisc
`htb` i `ingress`; `clsact` i `ingress` się wykluczają. TCX (jądro ≥ 6.6)
działa niezależnie od qdisców. Dołączenia są wykonywane `BPF_PROG_ATTACH`
bez linku, więc przetrwają restart demona; odpięcie wskazuje konkretny program
sondy i nie rusza cudzych programów TCX. Gdy interfejs znika, jądro usuwa
dołączenie samo.

## Komponenty

- `bpf/flow_probe.c` — obiekt eBPF (licencja `GPL-2.0-only OR BSD-2-Clause`),
  budowany w CI (`clang -target bpf`); hosty nie potrzebują kompilatora.
- `runtime/flow_probe.py` — demon w samej bibliotece standardowej Pythona:
  `load` (`bpftool prog loadall` + przypięcie w `/sys/fs/bpf/...`), `run`,
  `once`, `unload`. Mapy czyta wywołaniami `bpf(2)` przez `ctypes`.
- Mapowanie tap → VM z `/run/libvirt/qemu/*.xml` (UUID domeny, nazwa, MAC);
  systemowe VM CloudStack (`r-`, `s-`, `v-`) są pomijane.
- Wyjście: `records-*.jsonl` (spool z rotacją godzinową i limitem plików),
  `events.jsonl` (detektory w trybie observe), metryki textfile
  `cs_public0_flow_*` — **bez adresów IP i identyfikatorów VM w etykietach**.

## Detektory (observe, progi do kalibracji)

| ID | Sygnał | Źródło |
|---|---|---|
| D1 | tempo nowych połączeń TCP z VM | rekordy w oknie 60 s |
| D2 | liczba różnych adresów docelowych | rekordy w oknie 60 s |
| D3 | fan-out na porty usług (22, 23, 25, 445, 3389, 5900) | rekordy w oknie 60 s |
| D4 | odsetek nieudanych prób | liczniki `syn_out` vs `synack_in`/`rst_in` (następny etap) |
| D7 | DNS IOC per VM | pytania DNS gościa (UDP 53, pierwsze 128 B) porównane z kwalifikowanym katalogiem ThreatFox modułu DNS IOC (`dns_catalog_file`, ta sama klasa `DomainCatalog`); zapisywane wyłącznie trafienia, pozostałe nazwy odrzucane w pamięci; katalog nieaktualny = D7 wstrzymany (`dns_catalog_fresh=0`) |

Progi domyślne są wyłącznie punktem startu; zdarzenie nie jest werdyktem.

## Zegar i korelacja

Demon odczytuje stan zegara jądra (`adjtimex`, tylko odczyt) i publikuje
`cs_public0_flow_clock_synced` oraz `cs_public0_flow_clock_maxerror_seconds`.
Brak synchronizacji albo błąd większy niż `clock_max_error_ms` zeruje
`continuity_known`. Funkcja `correlate()` jest referencją dla centralnego
korelatora: klucz `(dst_ip, dst_port, isn)` + TTL −1 + okno czasowe, wybór rekordu
najbliższego w czasie (retransmisje SYN mają ten sam ISN), estymacja stałego
rozjazdu zegarów jako mediany opóźnień i flaga niejednoznaczności.

## Wysyłka do ClickHouse (`flow_ship.py`)

Osobny proces (tylko biblioteka standardowa) czyta pliki `records-*.jsonl` od
zapisanego przesunięcia i wysyła pełne linie partiami (`INSERT ... FORMAT
JSONEachRow`) do tabel `syn_vnet` (strona gościa) i `syn_public0` (uplink)
przez HTTPS. Przesunięcie rośnie dopiero po potwierdzeniu wstawienia.

- **Deduplikacja:** każda partia ma deterministyczny `insert_deduplication_token`
  z (sensor, plik, zakres bajtów, tabela). Zakres jest zapisywany w stanie *przed*
  wysłaniem, więc po awarii ponawiany jest dokładnie ten sam zakres, a serwer
  odrzuca duplikat. Wymaga po stronie serwera: `non_replicated_deduplication_window`
  na tabelach (także docelowych widoków zmaterializowanych), `async_insert = 0`
  i `deduplicate_blocks_in_dependent_materialized_views = 1` dla konta piszącego.
- **TLS:** weryfikacja certyfikatu zawsze, także przy łączeniu po adresie IP
  (nazwa z `server_name` jako SNI); lista `endpoints` próbowana po kolei,
  odmowa uwierzytelnionego serwera (HTTP ≠ 200) nie jest ponawiana na innym węźle.
- **Konto:** tylko `INSERT` na tabelach wejściowych; hasło w pliku dostępnym
  wyłącznie dla roota (`password_file`).
- **Straty:** plik usunięty przez retencję sondy przed wysłaniem całości zwiększa
  `cs_public0_flow_ship_unshipped_files_total`; metryki `cs_public0_flow_ship_*`
  w osobnym pliku textfile.

```sh
python3 runtime/flow_ship.py once --config /etc/cs-public0/flow-ship.json
```

## Testy

```sh
python3 -m unittest tests.test_flow_probe -v
# root, obiekt z CI, bpftool; jednorazowy veth + namespace:
sudo FLOW_OBJECT=flow-out/flow_probe.o python3 -B tests/integration/flow.py
```

Smoke sprawdza dołączenie TCX, rekordy z poprawną krotką i ISN, liczniki RST,
idempotentną rekonsyliację, brak adresów w metrykach i odpięcie wyłącznie
własnych programów. Kod wyjścia 77 oznacza brak warunków wstępnych, nie zaliczenie.

## Ograniczenia

IPv4 i TCP SYN w pierwszej wersji; UDP/ICMP tylko jako liczniki. Okna detektorów
są lokalne dla hosta (migracja VM zeruje okno). Brak zdarzenia przy
`continuity_known=0` nie dowodzi braku nadużycia.
