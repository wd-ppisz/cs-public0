# Przygotowanie aktualizacji reguł alert-only

`runtime/prepare_alert_rules.py` przygotowuje kandydat, bez pobierania feedu,
instalacji, wywoływania systemd, sygnałów i poleceń przeładowania. Wymaga jawnego
SHA256 pełnego lokalnego źródła. SHA identyfikuje bajty; zaufanie do dostawcy,
licencja i autentyczność feedu wymagają osobnego sprawdzenia.

```sh
python3 runtime/prepare_alert_rules.py /path/to/feed.rules \
  --source-sha256 <64-lowercase-hex> --output-dir /path/to/new-candidate
```

Bez `--output-dir` narzędzie wyłącznie odczytuje źródło i wypisuje podsumowanie.
Nowy katalog zawiera `candidate.rules`, deterministyczny `candidate.rules.gz`
oraz `manifest.json`, zapisany na końcu. Istniejący katalog jest odrzucany;
niepełny wynik po błędzie pozostaje do rozliczenia i nie jest aktualizowany.
Pliki mają tryb 0600, katalog 0700. To narzędzie dla Linux.

Zmienia się wyłącznie akcja na początku aktywnej reguły: `drop`, `reject`,
`rejectsrc`, `rejectdst`, `rejectboth` stają się `alert`. Komentarze i pozostałe
bajty są zachowane. `pass` i nieznane akcje są odrzucane. Wspólny walidator
runtime odrzuca opcje `bypass` i `replace`, kontynuacje, CRLF, nieobsługiwane
znaki sterujące i wcięte reguły. Obowiązują limity 64 MiB i 4096 B na linię.
To profil zachowawczy: odrzucenie wymaga sprawdzenia źródła, nie pominięcia
walidacji. Nie jest to pełny parser składni Suricaty. W szczególności wykrycie
błędów składni, SID/GID, zależności i semantyki silnika wymaga jego testu.

## Bramka przed aktywacją

**Warunek reloadu:** Suricata 8.0.7 odrzuca komendę reloadu, jeśli proces
uruchomiono z `-S` albo `-s`. Jednostka projektu używa teraz wyłącznie
przypiętej listy `rule-files: [local.rules]` i katalogu reguł w wygenerowanym
YAML; walidacja `-T --simulate-ips` korzysta z tego samego wyboru. Usunięcie
`-S` z już uruchomionej instalacji wymaga kontrolowanego restartu. Najpierw
trzeba sprawdzić YAML: stary profil sdc wskazuje inne, współdzielone pliki,
które były dotąd przesłonięte przez `-S`. Nie wolno po prostu usunąć flagi.
Zmiana źródła reguł w projekcie nie migruje automatycznie istniejącego sdc.

1. Zachowaj przypięte źródło, jego pochodzenie/licencję i manifest kandydata.
   Sprawdź różnice SID/revision i nieoczekiwane usunięcia względem aktywnego zbioru.
2. W oddzielnej ograniczonej jednostce wykonaj `Suricata -T` z tym samym binarium,
   konfiguracją, classification, reference i threshold co jednostka docelowa.
   Wyłącz socket poleceń i użyj własnego katalogu logów. Nie otwieraj kolejki NFQ.
   Sprawdź exit status oraz liczbę załadowanych, pominiętych i błędnych reguł.
   Dla profilu inline dodaj `--simulate-ips` oraz te same ustawienia CLI silnika
   (w tym `stream.inline=yes`) co w jednostce produkcyjnej, z pominięciem `-q`.
   Samo `-T` domyślnie może testować IDS. Potwierdź tryb IPS w rzeczywistym logu;
   symulacja trybu nie odbiera obsługi kolejki ani ruchu przez sensor.
3. Przygotuj transakcję obejmującą docelowy plik, gzip, manifest instalacyjny
   i piny IaC. Sam zapis `rules` bez aktualizacji weryfikacji startowej spowoduje
   odmowę następnego startu. Pełny playbook instalacyjny może restartować sensor;
   nie używaj go jako skrótu do przeładowania bez restartu.
4. Ustal limity pamięci i czasu oraz wycofanie do przypiętego poprzedniego zbioru.
   Stary i nowy silnik współistnieją podczas reloadu; `MemoryMax` nie rezerwuje RAM.
   Zmierz koszt testu oraz rzeczywistego reloadu; nie przypisuj kosztu `-T` do IPS.
5. Pod blokadą aktualizacji sprawdź tożsamość jednostki, PID/start_ticks/boot,
   peer socketu, kolejkę i selektor nft, aktualne hashe i brak drugiego updatera.
   Po atomowej podmianie wywołaj blokujące `ruleset-reload-rules` i odbierz
   `ruleset-stats`, `ruleset-reload-time`, błędy, niezmienioną tożsamość sensora,
   postęp kolejki, dropy, latch oraz monitoring. Samo `return: OK` nie wystarcza.
6. Timeout lub utrata odpowiedzi oznacza stan nieznany: reload może nadal trwać.
   Nie uruchamiaj wtedy równolegle rollbacku ani kolejnego reloadu. Najpierw
   rozlicz rzeczywisty stan. Awaria kontrolera po podmianie wymaga odzyskiwania
   z trwałego dziennika. Pełny kontroler z bramkami systemd, startu i monitoringu
   pozostaje do integracji. [Transport komend i połączenie z dziennikiem](suricata-commands.md)
   dostarczają osobny etap; preparer nie zastępuje tych mechanizmów.

Przygotowanie, poprawny `-T`, aktywny proces i brak dropów nie dowodzą pełnej
inspekcji ani G6. Nie włączaj automatycznej aktywacji z dziennego feedu.

Źródła: [przeładowanie reguł w Suricata 8.0.7](https://docs.suricata.io/en/suricata-8.0.7/rule-management/rule-reload.html),
[socket poleceń](https://docs.suricata.io/en/suricata-8.0.7/unix-socket.html).
Warunek `-S`/`-s` jest jawny w
[UnixManagerReloadRulesWrapper, tag 8.0.7](https://github.com/OISF/suricata/blob/suricata-8.0.7/src/unix-manager.c#L734).
