# Trwały dziennik plików aktualizacji reguł

`runtime/rule_update_journal.py` jest biblioteką dla przyszłego kontrolera.
Wykonuje rzeczywiste operacje na plikach w Linux: kopie starego i nowego zestawu,
zapis zamiaru przed podmianą, indywidualne atomowe podmiany oraz odzyskiwanie po
przerwaniu procesu. Import i konstrukcja obiektu nie otwierają plików instalacji.
Nie ma CLI ani automatycznego uruchamiania.

Biblioteka nie pobiera feedu, nie parsuje reguł, nie wywołuje Suricaty/systemd,
nie otwiera NFQUEUE lub socketu sensora i nie wykonuje reloadu. Nie jest pełnym
kontrolerem aktywacji. Obecna instalacja sdc nie używa tej biblioteki.

## Granice i własność

Instalacja musi mieć jeden kanoniczny katalog dziennika. **Wszyscy** wykonawcy
zmieniający docelowe pliki muszą używać tej samej blokady. `flock` jest blokadą
doradczą; inny proces tego samego użytkownika albo root może ją zignorować.
Biblioteka nie zapewnia ochrony przed takim procesem ani jądrem/filesystemem,
który nie spełnia semantyki tych operacji.

Katalog dziennika ma tryb 0700, pliki 0600. Katalogi i pliki należą do bieżącego
UID; dla docelowego kontrolera będzie to root. Przejście przez katalogi odbywa
się deskryptorami, bez podążania za symlinkami. Zapisy odrzucają hardlinki,
obcych właścicieli i zapisywalne dla innych katalogi. Wyjątek dla przodka ze
sticky bit dotyczy wyłącznie katalogu należącego do root, np. `/tmp`; właściwe katalogi
instalacji i dziennika nadal muszą mieć bezpieczne prawa i własnego właściciela.
Przy wznowieniu sprawdzane są urządzenie i inode obu katalogów oraz identyfikator
transakcji. Nie wolno przenosić dziennika między instalacjami.

Transakcja obejmuje 1–4 istniejące zwykłe pliki w **jednym** katalogu docelowym.
Każdy ma jawny SHA256 starej i nowej zawartości; co najmniej jeden plik musi się
zmieniać. Nazwy są pojedynczymi segmentami,
bez ścieżek. Tryb i GID pliku są zachowane oraz sprawdzane przy odczycie.
Brak uprawnienia do odtworzenia GID zatrzymuje zapis przed podmianą tego pliku.
Przed claimem sprawdzany jest cały zestaw: proces nie-root musi mieć każdy GID
w grupie efektywnej lub dodatkowych; kontrola jest powtarzana przy wznowieniu.
Root musi mieć wymagane uprawnienia systemowe do `fchown`. Zmiana credentials,
capabilities lub uprawnień w trakcie operacji nie jest objęta tą kontrolą.
Limit wynosi 64 MiB na plik, 256 MiB na
każdą stronę zestawu, 32 KiB na metadane i 8192 B na potwierdzenie kontrolera.
To limity danych, nie pomiar lub gwarancja RAM/CPU/czasu operacji. Kod przyjmuje
nowe bajty w pamięci i przechowuje kopie starych podczas przygotowania.

Kopie i metadane są utrwalane przez `fsync`; podmiana jednego pliku używa rename
wewnątrz tego samego katalogu i kończy się synchronizacją katalogu. **Cały zestaw
nie jest jedną atomową operacją.** Pomiędzy podmianami czytelnik może zobaczyć
zestaw mieszany. Przyszły kontroler musi rozwiązać to dla weryfikatora startowego
i wszystkich konsumentów przed aktywacją. Biblioteka nie obejmuje pliku
wykonawczego w `/usr/local/libexec` w tej samej transakcji co `/etc`.
Zachowywane są UID, GID i tryb pliku, nie dodatkowe ACL/xattr/etykiety bezpieczeństwa;
ich wymagania trzeba rozliczyć przed integracją.

## Kolejność dla kontrolera

1. Poza biblioteką: kwalifikacja kandydata, test `-T` w IPS, dokładne artefakty
   IaC, budżet zasobów oraz tożsamość jednostki/PID/start_ticks/boot/socketu,
   kolejki i selektora. Kryteria i ograniczenia opisuje
   [procedura aktualizacji](rule-updates.md).
2. `prepare(id, updates, expected_old, expected_new)` zapisuje trwały claim
   `active.json` przed tworzeniem katalogu transakcji i kopii. Target pozostaje
   stary. Identyfikator to jawne 64 małe znaki hex; format nie dowodzi losowości.
   Zajęty store albo wcześniej użyty identyfikator są odrzucane.
3. `install(id)` sprawdza cały zestaw plików i kopii przed pierwszą podmianą,
   zapisuje `INSTALLING`, podmienia pliki i wymaga odczytu zgodnego z nowymi
   hashami przed `INSTALLED`. Przerwany `INSTALLING` można jawnie wznowić lub
   odtworzyć stary zestaw przez `restore(id)`, dopóki reload nie został zgłoszony.
4. `mark_reload_pending(id)` zapisuje `RELOAD_PENDING` **przed** wywołaniem
   reloadu przez przyszły kontroler. Od tej chwili `install`, `restore` i drugi
   zamiar reloadu są zabronione. Timeout, brak odpowiedzi lub śmierć kontrolera
   pozostawiają trwałą blokadę. Biblioteka nie ma opcji force ani automatycznego
   rollbacku tego stanu.
5. Poza biblioteką: rzeczywisty blokujący reload i pełny odczyt sensora,
   ruleset-stats/reload-time, tożsamości, błędów i monitoringu. Kontroler musi
   ustalić rzeczywisty wynik; sama odpowiedź OK nie wystarcza.
6. `record_reload_receipt(id, bytes)` zapisuje decyzję kontrolera, odczytuje
   aktualne pliki i zamyka transakcję plikową jako `COMMITTED`. Potwierdzenie
   jest ograniczonym, niepustym ciągiem bajtów. Biblioteka zapisuje jego hash,
   **nie weryfikuje jego prawdziwości ani dowodu reloadu**. Ten interfejs nie
   może być udostępniony jako operatorskie obejście nieznanego reloadu.

`status(id)` odczytuje stan i klasyfikuje docelowe pliki jako stare albo nowe.
Nieznana zawartość lub zmienione prawa powodują błąd; nie są nadpisywane.
Niepełne przygotowanie bez `state.json` można zakończyć przez
`abandon_preparation(id)` wyłącznie przy wszystkich starych plikach.
Istniejący, nawet uszkodzony stan nie jest traktowany jak brak stanu.
Pierwszy stan i potwierdzenie są publikowane przez plik tymczasowy, `fsync`
i rename. Przerwanie przed rename pozostawia tymczasowe bajty, a nie częściowy
plik pod nazwą `state.json` lub `receipt`; operację można ponowić zgodnie z fazą.
`retire_terminal(id)` domyka przerwane usunięcie claimu tylko dla stanów
końcowych i poprawnego zestawu plików; dla `COMMITTED` wymaga także dokładnego
zachowanego potwierdzenia.

Obrazy, stany końcowe i nieudane pliki tymczasowe pozostają do rozliczenia.
Nie ma automatycznego usuwania ani limitu retencji wielu zakończonych transakcji;
potrzebna jest polityka pojemności i sprzątania właściciela. Nowy claim jest
zabroniony, dopóki poprzedni nie zostanie poprawnie zakończony.

## Co jest sprawdzane, a co pozostaje otwarte

Testy używają rzeczywistych prywatnych plików Linux, rename, fsync, flock i
procesów potomnych. Obejmują SIGKILL po pierwszej podmianie, przerwania
przygotowania/odtwarzania/commit, mieszany zestaw, utratę odpowiedzi kontrolera,
SIGKILL wewnątrz zapisu pierwszego stanu i potwierdzenia, zachowanie GID,
obce bajty, korupcję kopii, symlinki/hardlinki, prawa, zmieniony inode i wyścig
o blokadę. Nie jest to test utraty zasilania lub uszkodzenia urządzenia.

Do implementacji i odbioru pozostają transport systemd/socket, źródłowe piny
weryfikatora startowego poza katalogiem reguł, zasoby i nadzór kontrolera,
rozstrzyganie nieznanego reloadu, integracja IaC, kontrolowany reload sdc i G6.
Testy tej biblioteki nie kwalifikują ruchu, pojemności, pełnej inspekcji ani
rezerwy CPU. `production_ready=false`, `measurement_eligible=false`, G6 OPEN.

Źródła API: [Python os.replace/fsync](https://docs.python.org/3.12/library/os.html),
[Python fcntl.flock](https://docs.python.org/3.12/library/fcntl.html).
