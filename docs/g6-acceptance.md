# Plan odbioru przed rozszerzeniem wdrożenia

Stan: **OPEN**. `production_ready=false`, `measurement_eligible=false` aż do
odbioru kompletnych dowodów. Monitor jest obserwatorem utraty inspekcji, nie
certyfikatem wydajności. Projekt 2.0 anti-DDoS pozostaje osobnym etapem po
ukończeniu bieżącego wydania.

## Kryteria i brakujące dowody

| Obszar | Kryterium | Wymagany dowód |
|---|---|---|
| CPU ochrony | co najmniej 20% rezerwy zmierzonego budżetu przy docelowym ruchu | budżet userspace i kernel/IRQ/softirq, ograniczające rdzenie/kolejki, koszt kolektora i rozkład w czasie |
| Wybrana usługa | wzrost p99 najwyżej 10% względem porównywalnego baseline | pełna kohorta prób, sukcesy/błędy/timeouty, dokładność timestampów i rozkłady par B/F |
| Operacje Ceph | wzrost p99 najwyżej 10% | jawna populacja właściwych daemonów i prób, retries/errors/cancel/unresolved, kompletność źródła oraz precision |
| Legalny ruch NFQ | brak niewyjaśnionych dropów | liczniki kernel/user/netlink, pełne okna i korelacja niezależnego klienta/backendu |
| Awaria IPS | forwarding recovery najwyżej 5 s | osobne kontrolowane okno awarii i niezależny pomiar dostarczenia; czas polecenia systemctl nie jest czasem recovery |

Ostrzejsze SLO mają pierwszeństwo. `alert-only` oznacza brak reguł blokujących;
nie gwarantuje zerowej perturbacji ani braku strat w kolejce. P99 klienta
storage, średnia i niepełna historia slow-ops nie zastępują dokładnego p99 Ceph.

## Kolejność wykonania

1. **Aktualizacja i lifecycle reguł.** Przygotuj kandydat zgodnie z
   [procedurą aktualizacji](rule-updates.md), odbierz test silnika, transakcję,
   przerwania/rollback i readback. Zachowaj hashe każdej wersji oraz poprzedni zbiór.
2. **Manifest pomiaru.** Zamroź wersje binarium, konfiguracji i reguł, host/boot,
   zakres interfejsów, kolejki, źródła klientów i usługi, czas, traffic mix/rates,
   limity generatora, budżet ochrony oraz CPU/NUMA/IRQ placement. Wartości
   nieznane pozostają NULL, bez promowania średniej idle do rezerwy IPS.
3. **Kwalifikacja źródeł.** Sprawdź pełny denominator usługi oraz Ceph,
   błędy/retries/rotacje/drop/reset, niezależny backend, dokładność i clock
   alignment. Dokładny zbiór OSD wynika z własnego workloadu/extentów/RBD i
   parent, a nie z listy daemonów na hoście sensora. Nowe instrumentowanie
   współdzielonych OSD wymaga osobnego uzgodnienia i ograniczenia kosztu producenta.
4. **Porównywalne B/F.** Dopiero po kwalifikacji źródeł i uzgodnieniu okna:
   naprzemienne pary baseline/forwarding-inspection, minimum pięć pełnych par
   120 s, warmup/drain, bez catch-up. Minimum liczności dotyczy rzeczywistych
   prób danej klasy; nie utożsamiaj 20 rps HTTP z liczbą operacji Ceph.
   Zachowaj wszystkie nieudane, spóźnione i pominięte próby oraz pary.
5. **Recovery i decyzja o rozszerzeniu.** W odrębnym autoryzowanym oknie
   zweryfikuj awarie jednostki/monitora/updatera, reboot i wycofanie. Odbierz
   pełny monitoring, alarmy i brak metryk. Po spełnieniu kryteriów przygotuj
   jeden kolejny host, własne okno i rollback; promuj kolejne hosty ręcznie.

Przy zakazie generowania ruchu testowego można wykonywać odczyty i przygotowanie
źródeł, lecz nie zaliczać brakujących eksperymentów z samej obserwacji. Ten plan
nie upoważnia do testów DROP, awarii, zmian innych hostów ani instrumentacji OSD.
