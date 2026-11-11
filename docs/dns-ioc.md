# Wykrywanie DNS IOC bez blokowania

Stan: opcjonalny moduł wydania [1.1](releases/v1.1.0.md), z implementacją i testami
LAB. Instalacja pakietu nie jest odbiorem konkretnego środowiska. Aktywacja,
pomiary kosztu, log transport i odbiór centralny wymagają osobnego potwierdzenia.

## Źródło i znaczenie danych

Osobny proces Suricaty działa pasywnie przez AF_PACKET, z filtrem BPF
`ip and (udp port 53 or tcp port 53)` i `--disable-detection`. Nie używa NFQUEUE,
kopiowania do innego interfejsu ani reguł DROP. Producent zapisuje DNS EVE v3
i statystyki. Jego `sensor-name` jest równy systemd `INVOCATION_ID`, dzięki czemu
każdy oryginał zawiera identyfikator uruchomienia producenta.

Osobny kolektor czyta te logi, porównuje dokładną nazwę zapytania z domenami
ThreatFox i publikuje wyłącznie dopasowania oraz ograniczony zestaw metryk.
Korzysta ze stanu już odebranego aktualizatora IP: parser ThreatFox dopuszcza
confidence >=75 i wskaźniki nie starsze niż siedem dni w chwili pobrania.
Kolektor sprawdza pin tego parsera i daty pobrania/publikacji/wygaśnięcia feedu.
Brak, błąd albo wygaśnięcie katalogu zatrzymuje konsumpcję do jego naprawy.
IPInsights nie jest źródłem domen dla tego mechanizmu. OTX czeka na osobną
konfigurację klucza i kwalifikacji źródła.

`dns_ioc_query` oznacza rzeczywiście zaobserwowane zapytanie do domeny z bieżącego
feedu. Nie dowodzi połączenia z serwerem C2, wykonania malware ani kompromitacji
VM. Aktualny feed nie poświadcza historycznej reputacji domeny w chwili zapytania;
zdarzenie zawiera oddzielnie czas obserwacji, dopasowania i źródła IOC.

## Kierunek i przypisanie

Rozpatrywane są tylko zwykłe zapytania DNS v3 (`type=request`, `opcode=0`),
z pełną nazwą i listą pytań. DNS v2, obcięte nazwy oraz niejednoznaczne rekordy
są odrzucane. Odpowiedź resolvera nie jest nowym wyjściem klienta.

Adres klienta pochodzi z rzeczywistego `src_ip` zapytania. Egress oznacza klienta
w jawnie skonfigurowanej sieci operatora i resolver poza nią. Przypadki ingress
i unknown mają własny kierunek. IP resolvera jest osobnym polem i nie jest IOC
domenowym. Publiczny adres po SNAT może reprezentować kilka VM; kolektor nie
tworzy przypisania do pojedynczej VM.

Dopasowanie jest dokładne, bez reguł sufiksowych: `bad.example` nie dopasowuje
`sub.bad.example` ani `bad.example.attacker.invalid`. Wielkość liter i końcowa
kropka DNS są normalizowane. Adresy IP, URL-e, wildcardy, puste etykiety,
niekanoniczne lub ucieczkowane nazwy nie stają się wskaźnikami domenowymi.

DNS przez HTTPS/TLS oraz inne szyfrowane tunele pozostają niewidoczne. DGA,
fast-flux, NXDOMAIN i RPZ nie są realizowane przez samo dokładne dopasowanie IOC.
Ten profil nie zmienia odpowiedzi DNS ani ruchu wychodzącego VM.

## Dowody i ograniczenia

Każde dopasowanie zachowuje SHA256, offset i długość oryginalnego rekordu EVE,
tożsamość pliku i producenta, DNS/flow ID oraz pochodzenie IOC. Stabilny event ID
umożliwia usunięcie powtórek transportu. Kolektor używa transakcyjnego kursora,
trwałego outboxu i ograniczonej bazy SQLite; restart nie zeruje liczników.
Przepisanie zawartości pod tym samym inode wykrywa odcisk poprzedniego fragmentu.
Rozwiązując starszy dowód po rotacji, należy sprawdzić również zachowane archiwa
i SHA256; sam bieżący inode nie wystarcza.

Producent ma niezależne limity 50% jednego CPU, 256MiB RAM i 64MiB na plik.
Logrotate zmienia nazwę pliku i sygnalizuje tylko producentowi DNS ponowne
otwarcie, zachowując cztery archiwa. Nie stosuje copytruncate. Kolektor ma
oddzielne limity 1CPU/384MiB, maksymalnie 1000 rekordów i 2MiB wejścia na cykl.
To limity techniczne, nie zmierzona przepustowość. Backlog, braki oryginałów,
nieznana telemetria lub straty capture oznaczają niepełne pokrycie.

`capture_drops_seen_total` zachowuje historię również między uruchomieniami
producenta. Zero strat capture nie dowodzi pełnego pokrycia całej sieci.
Pełne logi DNS są w prywatnej retencji operatora; nazwy, IP i flow ID nie są
etykietami metryk Prometheusa i nie trafiają do publicznych dowodów testów.

## Instalacja i odbiór

`ansible/dns-ioc.yml` wymaga jednego jawnego targetu, pinów źródeł, silnika
i konfiguracji. Domyślnie instaluje wyłączone usługi. Odmawia zastąpienia
działającego profilu lub zmienionych artefaktów; taka aktualizacja wymaga
kontrolowanej migracji. Nie zmienia konfiguracji, procesu ani reguł sensora inline.

Przed aktywacją sprawdź źródła feedu, klasy hostów, pamięć i CPU oraz niezależny
log transport. Najpierw odbierz jeden host: proces producenta, jego InvocationID
w oryginałach EVE, UDP/TCP, daty feedu, metryki w Prometheusie, rekordy w centrum,
opóźnienie i brak wpływu na sensor inline. Kolejne hosty wdrażaj pojedynczo.
Wycofanie zatrzymuje wyłącznie `cs-public0-dns.service` i jego timer kolektora;
zachowuje oryginały, historię i bazę. Odbiór DNS nie zamyka G6.

## Testy

- Testy modelu i rzeczywistego czytnika: `python3 -B -m unittest discover -s tests -p test_dns_ioc.py -v`.
- Pasywny capture, prywatny klient/resolver i bridge w trzech namespace'ach:
  `sudo python3 -B tests/integration/dns.py --engine /absolute/suricata --engine-sha256 <pin>`.
  Kod77 oznacza brak warunków, a nie zaliczenie.
- Przypadki dodatnie są syntetyczne i pozostają w LAB; nie wstrzykuj ich do
  produkcyjnego strumienia zgłoszeń abuse jako rzeczywistych nadużyć klientów.

## Źródła schematu

- [Zmiany DNS EVE v3 w Suricacie 8.0.7](https://docs.suricata.io/en/suricata-8.0.7/upgrade/8.0-dns-logging-changes.html).
- [DNS EVE i rozdzielenie request/response](https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-output.html#dns).
- [Opcje AF_PACKET i disable-detection](https://docs.suricata.io/en/suricata-8.0.7/command-line-options.html).
