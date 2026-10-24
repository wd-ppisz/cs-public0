# Transport komend Suricaty i dziennik plików

`runtime/suricata_commands.py` wykonuje rzeczywiste operacje Linux: odczyt
tożsamości procesu z `/proc`, `pidfd_open`, połączenie z socketem Unix,
`SO_PEERCRED` i protokół JSON 0.2. Import i konstrukcja obiektu nie wykonują
I/O. Otwarcie sesji jest jawne, przez context manager. Moduł nie ma CLI,
autostartu, sygnałów, systemd, generatora ruchu ani komendy force.

## Tożsamość i protokół

Wywołujący dostarcza wcześniej zaakceptowany binding konkretnego PID:
start_ticks, boot_id, UID, inode pliku wykonywalnego i namespace sieci,
SHA256 cmdline/cgroup oraz obecność opcji `-S`/`-s`. Binding jest porównywany
z rzeczywistym procesem przed i po komendach. `pidfd` wykrywa śmierć procesu;
połączenie musi mieć zgodny peer PID/UID. Zmiana inode ścieżki socketu blokuje
dalsze polecenia. Moduł nie wyprowadza z PID nazwy jednostki systemd, nie
kwalifikuje binarium na podstawie samego inode i nie ustala budżetu zasobów.
To obowiązki pełnego kontrolera, a nie dowód zapewniany przez JSON bindingu.

Katalog socketu jest otwierany bez podążania za symlinkami, z kontrolą
właściciela i praw; łączenie używa przypiętego deskryptora katalogu. Obsługiwane
są fragmentowane odpowiedzi zakończone LF. Zduplikowane klucze, błędny UTF-8,
dodatkowe ramki, nieznany status, EOF i przekroczenie 65536 B powodują błąd.
Sesja ma maksymalnie 16 wymian i wspólny deadline do 120 s. Odczyty mają
dodatkowy limit 3 s. Są to ograniczenia klienta, nie twarda preempcja syscall
lub pomiar kosztu kontrolera. Po błędzie protokołu sesja nie jest używana ponownie.

`query()` dopuszcza wyłącznie sześć komend odczytowych. Osobne `reload_rules()`
wysyła blokujące `ruleset-reload-rules` najwyżej raz na sesję. Odrzuca wcześniej
proces z `-S`/`-s`. W Suricata 8.0.7 taki proces odmawia live reloadu;
jednostka projektu wskazuje reguły w YAML. Zmiana argv istniejącego procesu
wymaga odrębnego, kontrolowanego restartu i ponownego odbioru.

## Połączenie z dziennikiem

`reload_installed(journal, transaction, session, old_count, new_count)` przyjmuje
już zainstalowaną transakcję plikową. Najpierw sprawdza możliwość reloadu,
capture-mode NFQ, liczbę poprzednich reguł i czas ostatniego reloadu. Następnie
zapisuje trwałe `RELOAD_PENDING` **przed** komendą zmieniającą silnik.

Zatwierdzenie wymaga odpowiedzi `done`, późniejszego czasu reloadu, dokładnej
liczby nowych reguł przy failed/skipped=0, jednego nietenantowego silnika,
niezmienionego czasu w odczycie zamykającym oraz bindingu procesu. Dopiero
wtedy do dziennika trafia potwierdzenie z bindingiem i zdarzeniami transportu.
Każde zdarzenie zachowuje integer monotonic started/finished oraz hash odpowiedzi;
nieznany wynik ma finished=NULL i outcome UNKNOWN.

Timeout, utrata odpowiedzi, odmowa silnika, niewłaściwa liczba reguł lub
zmieniona tożsamość po zapisaniu zamiaru pozostawiają `RELOAD_PENDING`.
Nie następują ponowny reload, automatyczne odtworzenie plików lub zamknięcie
claimu. Nawet odpowiedź OK po deadline nie jest przyjmowana jako sukces.
Czas `last_reload` jest zegarem ściennym silnika; sprawdzana zmiana nie
kwalifikuje dokładności czasu ani synchronizacji między hostami.

## Odbiór i otwarte elementy

Testy jednostkowe używają rzeczywistych lokalnych socketów, procesów Linux,
pidfd i plikowego dziennika, ale odpowiedzi silnika są tam fixtures JSON.
Odrębny test `tests/integration/netns.py` uruchamia prawdziwą Suricatę/NFQUEUE:
sprawdza odmowę reloadu z `-S`, start z YAML, podmianę reguł przez dziennik,
blokujący reload w tym samym procesie i nowy skorelowany alert EVE. Całość
działa na maszynie CI i jej prywatnych namespace'ach, nie na sdc. Wynik CI
należy odebrać; istnienie testu w źródle nie jest wynikiem jego wykonania.

To transport i połączenie z dziennikiem, nie gotowy kontroler aktywacji.
Preflight zarządzanej usługi sprawdza przez `--dump-config` wybór dokonany
przez parser YAML silnika: katalog i jedyny `rule-files.0` muszą wskazywać
sprawdzony plik alert-only. Dodatkowe pliki, wildcard, duplikat lub inna
ścieżka zatrzymują aktywację. Walidacja samej zawartości `local.rules` nie
wystarczałaby po usunięciu `-S`, gdyby YAML ładował inny zestaw.
Pozostają: spójny weryfikator startu i piny IaC, kontrola jednostki/cgroup,
konkurencyjnych updaterów, pamięci/CPU oraz źródeł profilu, monitoring całej
transakcji i rozstrzyganie nieznanego reloadu. Trzy pliki produkcyjnego sdc
nie są migrowane przez tę bibliotekę. Liczba reguł i alert testowy nie dowodzą
tożsamości wszystkich załadowanych SID ani pełnej inspekcji lub pojemności.
`production_ready=false`, `measurement_eligible=false`, G6 OPEN.

Źródła: [komendy i protokół](https://docs.suricata.io/en/suricata-8.0.7/unix-socket.html),
[reload](https://docs.suricata.io/en/suricata-8.0.7/rule-management/rule-reload.html),
[odmowa dla -S/-s](https://github.com/OISF/suricata/blob/suricata-8.0.7/src/unix-manager.c#L734),
[schema liczników i last_reload](https://github.com/OISF/suricata/blob/suricata-8.0.7/src/output-json-stats.c#L77).
