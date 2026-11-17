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

Progi domyślne są wyłącznie punktem startu; zdarzenie nie jest werdyktem.

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
