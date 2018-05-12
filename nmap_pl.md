## nmap manual pl

### Uwagi do tłumaczenia
Przemysław Galczewski <sako(at)avet.com.pl> (http://www.avet.com.pl)

Dokument ten zawiera nieoficjalne polskie tłumaczenie oryginalnej dokumentacji Nmapa w wersji 2991. Dołożyłem wszelkich starań, aby było ono jak najbardziej zbliżone do oryginału, a przy tym fachowe i zrozumiałe. Nie jest przy tym gwarantowane, że jest ono tak samo dokładne i aktualne jak oficjalna wersja angielska. Dokument ten może być modyfikowany i rozpowszechniany na zasadach Creative Commons Attribution License. Polska wersja tego dokumentu jest dostępna w formatach HTML, NROFF i XML. Wszelkie uwagi dotyczące tłumaczenia proszę kierować bezpośrednio do mnie.


### Specyfikacja celu

Wszystko co nie jest opcją Nmapa w parametrach wywołania (lub jej argumentem) jest traktowane jako specyfikacja celu skanowania. Najprostszym przypadkiem jest sam adres do przeskanowania.

Czasami chcesz przeskanować całą sieć, dlatego Nmap obsługuje format CDIR. Możesz dołączyć do adresu /<ilośćbitów> i nmap przeskanuje każdy adres, który zawiera się w podanym zakresie. Na przykład, 192.168.10.0/24 przeskanuje 256 adresów pomiędzy 192.168.10.0 (binarnie: 11000000 10101000 00001010 00000000) i 192.168.10.255 (binarnie: 11000000 10101000 00001010 11111111) włącznie. Podanie 192.168.10.40/24 spowoduje dokładnie takie samo zachowanie. Załóżmy, że host scanme.nmap.org ma adres 205.217.153.62, podanie scanme.nmap.org/16 spowoduje przeskanowanie 65,536 adresów IP pomiędzy 205.217.0.0 i 205.217.255.255. Najmniejszą dopuszczalna wartość to /1, co stanowi połowę Internetu. Największa wartość to 32, która oznacza skanowanie pojedynczego adresu IP.

Notacja CIDR jest krótka i zwięzła, jednak nie zawsze wystarczająco elastyczna. Na przykład, chcesz przeskanować 192.168.0.0/16 z pominięciem wszystkich adresów kończących się .0 i .255, ponieważ są one najczęściej adresami typu broadcast. Nmap obsługuje to poprzez podawanie zakresów adresów za pomocą oktetów. Zamiast podawać normalny adres IP, możesz podać listę adresów lub zakresów oddzieloną przecinkami. Na przykład 192.168.0-255.1-254 pominie wszystkie adresy kończące się .0 lub .255. Zakresy nie są limitowane do końcowych oktetów: podanie 0-255.0-255.13.37 pozwoli na przeskanowanie wszystkich adresów kończących się 13.37. Tego typu skanowania mogą być przydatne podczas przeprowadzania badań Internetu.

Adresy IPv6 mogą być podawane jedynie w pełnej formie IPv6 lub nazwy hosta. Zapis z wykorzystaniem CIDR i zakresów nie jest obsługiwany przy IPV6, jednak rzadko byłoby to przydatne.

Nmap akceptuje podawanie wielu hostów w linii poleceń i nie muszą one być tego samego typu. Komenda nmap scanme.nmap.org 192.168.0.0/8 10.0.0,1,3-7.0-255 zrobi to co powinna.

Zwykle adresy są podawane w linii poleceń, jednak poniższe opcje pozwalają na alternatywną specyfikację celu:

-iL <plik_wejściowy> (Odczytanie z pliku)
odczytuje specyfikację celu z pliku <plik-wejściowy>. Podawanie długiej listy adresów z linii poleceń jest dosyć niewygodne. Na przykład Twój serwer DHCP może posiadać listę 10,000 aktualnie dzierżawionych adresów, które chcesz przeskanować. Możliwe również, że chcesz przeskanować wszystkie adresy IP z wykluczeniem aktualnie dzierżawionych aby uzyskać listę nielegalnie przypisanych adresów statycznych. Po prostu wygeneruj listę adresów i podaj ją Nmapowi jako argument do parametru -iL. Poszczególne definicje mogą być zgodne z dowolnym formatem akceptowanym przez Nmapa w linii poleceń (adres IP, nazwa, CIDR, IPv6 lub zakres). Każdy wpis musi być oddzielony od następnego za pomocą jednej (lub wiecej) spacji, znaków tabulacji lub znaków nowej linii. Możesz również podać znak (-) zamiast nazwy pliku jeśli chesz aby Nmap pobrał adresy ze standardowego wejścia zamiast z pliku.

-iR <ilość hostów> (Wybierz losowe cele)
Do przeprowadzania badań Internetu, możesz używać wyboru losowych adresów. Argument <ilość hostów> informuje Nmapa ile losowych adresów ma wygenerować. Adresy prywatne, typu multicast lub niewykorzystywane są automatycznie pomijane przy generowaniu. Argument 0 pozwala na przeprowadzanie skanowania bez końca. Pamiętaj, że niektórzy administratorzy nie lubią skanowania ich sieci i może się im to nie spodobać. Używaj tej opcji na własne ryzyko! Jeśli poczujesz się naprawdę znudzony w deszczowe popołudnie, wyprubuj komendę nmap -sS -PS80 -iR 0 -p 80 do wykrycia losowych serwerów WWW do przeglądania udostępnianych przez nie stron.

--exclude <host1[,host2][,host3],...> (Wyłączenie hostów/sieci)
Podana lista celów do wyłączenia z zakresu skanowania, jeśli wchodzą w zakres aktualnego skanowania. Lista musi być podana zgodnie ze standardowym formatem akceptowanycm przez Nmapa, więc może zawierać nazwy, adresy w formacie CDIR, zakresy, itp. Opcja ta jest przydatna, jeśli sieć którą chcesz przeskanować zawiera systemy nietykalne lub krytyczne, o których wiadomo, że nie tolerują dobrze skanowania lub też sieci administrowane przez innych ludzi.

--excludefile <plik_wyłączeń> (Lista wyłączeń z pliku)
Opcja ta oferuje taką samą funkcjonalność jak --exclude z tą rożnicą, że wykluczone cele (oddzielone spacjami, znakami tabulacji lub nowej linii) są pobierane z pliku <plik_wyłączeń>, a nie z linii poleceń.


### Wykrywanie hostów

Jednym z pierwszych kroków rekonesansu sieciowego jest redukcja (czasami ogromnych) zakresów adresów IP do listy aktywnych lub interesujących hostów. Skanowanie każdego portu na każdym adresie IP jest wolne i przeważnie niepotrzebne. Oczywiście to co czyni host interesującym głównie zależy od celu skanowania. Administratorzy sieci mogą być zainteresowani hostami udostępniającymi określoną usługę podczas gdy audytorzy bezpieczeństwa mogą chcieć przyjrzeć się każdemu urządzeniu posiadającemu adres IP. Administratorowi może wystarczać wykorzystanie pinga ICMP do zlokalizowania hostów w jego wewnętrznej sieci, podczas gdy audytor przeprowadzający zewnętrzne testy penetracyjne może wykorzystywać dziesiątki różnych testów do ominięcia reguł filtrowania systemu zaporowego.

Ponieważ niezbędne są różne metody wykrywania hostów, Nmap oferuje szeroki wachlarz opcji pozwalających na wybieranie wykorzystywanych technik. Wykrywanie hostów często jest zwane skanowaniem Ping, jednak wykracza daleko poza proste wysyłanie zapytania ICMP echo request znanego z programu ping. Użytkownik może pominąć etap wykrywania poprzez wykorzystanie opcji skanowania listy (-sL), poprzez wyłączenie pingowania (-P0) lub wykorzystania różnych kombinacji wieloportowego badania za pomocą testów TCP SYN/ACK, UDP, i ICMP. Celem tych testów jest uzyskanie informacji o adresach IP, które są aktualnie dostępne (są wykorzystywane przez urządzenie sieciowe lub komputer). W przypadku wielu sieci tylko mały procent wykorzystywanych adresów IP jest równocześnie aktywnych. Jest to szczególnie powszechne w sieciach prywatnych zgodnych z adresacją RFC1918, takich jak 10.0.0.0/8. Ta sieć zawiera 16 milionów adresów IP, ale widziałem nie raz firmy wykorzystujące niecały tysiąc z nich. Opcja wykrywania hostów pozwala na szybkie wykrycie rzeczywiście wykorzystywanych adresów IP z całej dostępnej puli.

Jeśli nie podano opcji wybierającej metodę wykrywania hostów, Nmap wysyła pakiety TCP ACK na port 80 i zapytanie ICMP Echo Request query do każdego badanego adresu. Wyjątkiem od tej reguły jest skanowanie ARP przeprowadzane dla aktualnego segmentu sieci ethernet. W przypadku uruchamiania przez nie uprzywilejowanych użytkowników systemów UNIX, wysyłany jest pakiet SYN zamiast ACK z wykorzystaniem wywołania systemowego connect(). Ustawienia domyślne są tożsame z opcjami -PA -PE. Takie wykrywanie hostów jest najczęściej wystarczające podczas skanowania sieci lokalnej, jednak podczas audytów bezpieczeństwa zalecane jest wykorzystywanie bardziej zaawansowanych opcji.

Opcje -P* (które wybierają sposób pingowania) mogą być łączone. Możesz poprawic dokładność wykrywania hostów za systemem zaporowym poprzez stosowanie wielu różnych portów/flag TCP i typów ICMP. Zwracam uwagę, że wykrywanie hostów ARP (-PR) jest z założenia włączane podczas testów sieci lokalnej w ramach tego samego segmentu, nawet jeśli podasz inne opcje -P*, ponieważ praktycznie zawsze tak jest szybciej i efektywniej.

#### Opcje kontroli wykrywania hostów.

-sL (Lista skanowania)
Lista skanowania jest okrojoną funkcją wykrywania hostów, która po prostu wyświetla wszystkie adresy z podanych zakresów skanowania i nie wysyła żadnych pakietów do nich. Domyślnie Nmap wykonuje odwrotne zapytania DNS o badane adresy aby poznać ich nazwy. Często niespodzianką jest jak dużo informacji mogą udzielić już same nazwy hostów. Na przykład fw.chi.playboy.com jest systemem zaporowym w biurze Playboy Enterprises w Chicago. Na końcu Nmap podaje także całkowitą liczbę adresów IP. Lista skanowania jest dobrym sposobem na sprawdzenie i uzyskanie pewności, że prawidłowo podano zakres skanowania. Jeśli nie rozpoznajesz nazw domen na uzyskanej liście, warto sprawdzić podany zakres, co pozwala unikąć niepotrzebnego skanowania sieci nieznanej firmy.

Ideą tej opcji jest wyświetlanie prostej listy adresów, z tego powodu bardziej zaawansowana funkcjonalność taka jak skanowanie portów, wykrywanie systemu operacyjnego czy pingowanie nie może być łączone z tą metodą. Jeśli chcesz wyłączyć pingowanie podczas skanowania, poczytaj na ten temat w opisie opcji -P0.

-sP (Skanowanie Ping)
Ta opcja nakazuje Nmapowi przeprowadzać tylko skanowanie typu Ping (wykrywanie hostów), a wynikiem jej działania jest lista aktywnych hostów. Dodatkowe testy (takie jak skanowanie portów lub wykrywanie systemu operacyjnego) nie są przeprowadzane. Metoda ta idzie krok dalej niż lista skanowania i może być wykorzystywana w podobnym celu. Pozwala na przeprowadzenie delikatnego rekonesansu bez zwracania zbytniej uwagi. Posiadanie wiedzy na temat ilości aktywnych hostów jest bardziej wartościowe dla atakujących niż sama lista adresów zawierająca adres IP i nazwę hosta.

Również administratorzy systemów często korzystają z tej opcji. Pozwala ona na łatwe i szybkie określenie liczby hostów w sieci lub monitorowanie dostępności serwerów. Opcja ta często jest nazywna Ping Sweep i daje bardziej wiarygodne wyniki niż pingowanie adresu broadcast, ponieważ niektóre adresy mogą na niego nie odpowiedzieć.

Domyślnie opcja -sP wysyła pakiety ICMP echo request i pakiety TCP na port 80. W przypadku wykonywania z konta nie uprzywilejowanego użytkownika wysyłane są pakiety SYN (z wykorzystaniem funkcji systemowej connect()) na port 80 badanego hosta. Jeśli uprzywilejowany użytkownik próbuje przeskanować adresy w lokalnej sieci ethernet, wykorzystywane są zapytania ARP (-PR), chyba że dodano opcję --send-ip. Dla większej wygody opcja -sP może być łączona w dowolny sposób z innymi metodami wykrywania hostów (opcje -P*, nie dotyczy -P0). Jeśli wybrano któryś z typów testów i numer portu, nie są wykorzystywne domyślne ustawienia (ACK i echo request). Wykorzystywanie tych opcji jest szczególnie zalecane, jeśli pomiędzy badanym systemem, a hostem na którym jest uruchomiony Nmap jest system zaporowy, inaczej niektóre (lub wszystkie) hosty nie zostaną wykryte.

-P0 (Bez pinga)
Ta opcja wyłącza całkowicie wykrywanie hostów. Normalnie Nmap próbuje wykryć aktywne adresy przed rozpoczęciem właściwego skanowania. Domyślnie Nmap przeprowadza tylko testy takie jak skanowanie portów, wykrywanie wersji i systemu operacyjnego tylko dla hostów, które zostały wcześniej wykryte jako aktywne. Wyłączenie wykrywania hostów za pomocą opcji -P0 powoduje, że Nmap próbuje wykonać wszystkie żadane typy skanowania na każdym podanym adresie IP. Jeśli więc jako cel w linii pleceń podano klasę B (/16), wszystkie 65,536 adresów zostanie przeskanowane. Drugi znak w opcji -P0 jest zerem, a nie literą O. Wykrywanie hostów jest pomijane jak przy wyświetlaniu listy skanowania, jednak zamiast zatrzymać się i wyświetlić listę, Nmap kontynuuje i przeprowadza założone testy na każym adresie IP, tak jak by był wykryty jako aktywny.

-PS [listaportów] (TCP SYN Ping)
Opcja ta powoduje wysyłanie pustych pakietów TCP z ustawioną flagą SYN. Domyślnie port docelowy to 80 (konfigurowalne przed kompilacją za pomocą stałej DEFAULT_TCP_PROBE_PORT w pliku nmap.h), ale inny port może być podany jako parametr. Możliwe jest również podanie listy portów, odzielonych przecinkami (np. -PS22,23,25,80,113,1050,35000), co spowoduje przeprowadzenie testów na wszystkich podanych portach równolegle.

Ustawiona flaga SYN sugeruje badanemu systemowi, że próbujesz nawiązać z nim połączenie. Normalnie zdalny port będzie zamknięty i zostanie wysłany z powrotem pakiet z flagą RST (reset). Jeśli port będzie otwarty, host będzie próbował wykonać drugi krok z trójstopniowego procesu nawiązywania połączenia odpowiadając za pomocą pakietu TCP SYN/ACK. Nmap zamiast wysłać pakiet ACK, który by pomyślnie zakończył nawiązywanie połączenia, w tym momencie przerwie połączenie wysyłając pakiet RST. Pakiet RST jest wysyłany przez kernel systemu na którym pracuje Nmap automatycznie, w odpowiedzi na niespodziwany pakiet SYN/ACK, a nie przez samego Nmapa.

Nmap nie zwraca uwagi czy port jest otwarty czy zamknięty. W zależności od uzyskanej omówionej wcześniej odpowiedzi (RST lub SYN/ACK) host jest uznawany za dostępny.

W systemach UNIX, tylko użytkownik uprzywilejowany - root - może wysyłać niskopoziomowe pakiety raw TCP. W przypadku użytkowników nie posiadających odpowiednich uprawnień wykorzystywane jest obejście w postaci wykorzystania funkcji systemowej connect() do wykonania połączeń ze wskazanymi portami. Jeśli connect() zwróci poprawność wykonania operacji lub błąd odmowy połączenia ECONNREFUSED, stos TCP musiał otrzymać pakiet z flagami SYN/ACK lub RST i host jest uznawany za dostępny. Jeśli próba nawiązania połączenia została przerwana po przekroczeniu maksymalnego czasu oczekiwania, host jest oznaczany jako niedostępny. To obejście jest również wykorzystywane dla protokołu IPv6, ponieważ wysyłanie niskopoziomowych pakietów raw TCP nie jest jeszcze dostępne w Nmapie.

-PA [lista portów] (TCP ACK Ping)
Metoda TCP ACK ping jest dosyć podobna do powyżej opisanego SYN ping. Różnica, jak łatwo zgadnąć, polega na wykorzystaniu flagi ACK zamiast SYN. Flaga ACK jest wykorzystywana do potwierdzania otrzymania danych za pomocą utworzonego wcześniej połączenia TCP, jednak w tym wypadku połączenie takie nie istnieje. Z tego powodu badany system powinien zawsze odpowiedzieć pakietem z flagą RST, świadczącą o nie isnieniu takiego połączenia.

Opcja -PA, tak jak SYN, używa portu numer 80 i również może przyjmować listę portów jako argument (w takim samym formacie). Jeśli program został uruchomiony przez nie uprzywilejowanego użytkownika lub badany jest adres IPv6, wykorzystywane jest opisane wcześniej obejście za pomocą connect(). Obejście to nie jest idealne, ponieważ funkcja connect() wysyła pakiet SYN zamiast oczekiwanego ACK.

Powodem udostępniania zarówno metody SYN jak i ACK jest zwiększenie szansy na ominięcie systemu zaporowego. Wielu administratorów konfiguruje routery i proste systemy zaporowe tak, żeby blokowały przychodzące pakiety SYN, poza przychodzącymi do publicznych serwerów takich jak WWW czy pocztowych. Zabezpiecza to przed przychodzeniem innych połączeń przy jednoczesnym nie zakłucaniu pozostałej transmisji wychodzącej do Internetu. Takie bezstanowe (non-stateful) rozwiązanie zajmuje mało zasobów systemu zaporowego/routera i jest szeroko wspierane przez filtry sprzętowe i programowe. Linuxowy firewall Netfilter/iptables dla wygody posiada opcję --syn, która implementuje takie właśnie bezstanowe filtrowanie. W przypadku takiego systemu zaporowego testy wykorzystujące metodę SYN ping (-PS) zostaną prawdopodobnie zablokowane w przypadku zamkniętych portów. W tym przypadku metoda ACK pozwoli na obejście tych zabezpieczeń.

Innym popularnym typem jest firewall wykorzystujący stany (stateful) do blokowania niechcianych pakietów. Taka funkcjonalność jest najczęściej spotykana w wysokiej klasy systemach zaporowych, które stają się z roku na rok coraz popularniejsze. Linuxowy Netfilter/iptables posiada opcję --state, która kategoryzuje pakiety na podstawie stanu połączenia. Metoda SYN prawdopodobnie będzie działała poprawnie dla tego typu systemów, ale już pakiet z ACK zostanie rozpoznany jako nieprawidłowy i zostanie zablokowany. Rozwiązaniem tego problemu jest wykorzystywanie jednocześnie obu metod SYN i ACK poprzez podanie parametrów -PS i -PA.

-PU [listaportów] (UDP Ping)
Kolejną metodą wykrywania hostów jest UDP ping, który wysyła puste (o ile nie wykorzystano opcji --data-length) pakiety UDP na wskazane porty. Lista portów jest podawana w takim samym formacie jak dla wcześniej opisanych opcji -PS i -PA. Jeśli nie podano numerów portów, domyślnie używany jest port 32338. Port ten może być zmieniony przed kompilacją poprzez zmianę stałej DEFAULT_UDP_PROBE_PORT w pliku nmap.h. Wybór tak mało popularnego portu został podyktowany chęcią uniknięcia wysyłania pakietów do otwartych portów, co w przypadku tego testu nie przyniosło by oczekiwanego efektu.

W przypakdu kiedy port jest zamknięty na badaniej maszynie, w odpowiedzi na pakiet UDP powinien zostać odesłany pakiet ICMP port unreachable oznaczający brak możliwości komunikacji z wybranym portem. Po otrzymaniu takiej odpowiedzi Nmap oznacza host jako dostępny. Inne typy odpowiedzi ICMP, takie jak host/sieć niedostępna czy przekroczony czas życia TTL oznaczają, że badany host nie jest dostępny, podobnie interpretowany jest brak odpowiedzi. Jeśli badany port jest otwarty, większość typowych usług zignoruje pusty pakiet i nie zostanie wysłana żadna informacja zwrotna. Właśnie dla tego domyślnie testowanym portem jest 31338, który jest bardzo rzadko wykorzystywany. Wiele usług, takich jak chargen, odpowie na pusty pakiet co spowoduje, że Nmap uzna host za dostępny.

Główną zaletą tego typu skanowania jest fakt, że omija systemy zaporowe i filtry skupiające sie tylko na TCP. Przykładowo, miałem kiedyś szerokopasmowy router bezprzewodowy Linksys BEFW11S4. Zewnętrzny interfejs tego urządzenia filtrował domyślnie wszystkie porty TCP, za to testy UDP zwracały odpowiedzi ICMP port unreachable, co ujawnia istnienie urządzenia.

-PE; -PP; -PM (Typy ICMP Ping)
Dodatkowo poza opisanymi wcześniej metodami wykrywania hostów TCP i UDP, Nmap może wysyłać standardowe pakiety ICMP znane z typowego programu ping. Nmap wysyła pakiety ICMP typu 8 (echo request) do badanego hosta i oczekuje typu 0 (echo reply) w odpowiedzi. Niestety wiele hostów i systemów zaporowych blokuje tego typu pakiety, zamiast odpowiadać prawidłowo i zgodnie z RFC 1122. Z tego powodu skanowania nieznanych hostów w internecie za pomocą tej metody przeważnie nie są wiarygodne. Jednakże administratorzy systemów monitorujący wewnętrzne sieci mogą z powodzeniem efektywnie wykorzystywać tą metodę. Takie wykorzystanie zapytań ICMP echo request jest możliwe za pomocą opcji -PE.

Zapytanie echo request jest standardowym zapytaniem ICMP ping, jednak Nmap nie poprzestaje na tym. Standard ICMP (RFC 792) opisuje także zapytania timestamp request, information request, i address mask request o kodach odpowiednio 13, 15 i 17. Podczas kiedy założonym efektem działania tych zapytań jest uzyskanie informacji typu maska sieci czy aktualny czas, mogą być one wykorzystane do wykrywania aktywności hostów. System który odpowiada, jest uznawany za aktywny. Nmap nie obsługuje zapytań information request, jako że nie są one często spotykane. RFC 1122 zaleca, że „host NIE POWINIEN obsługiwać tych zapytań”. Zapytania timestamp i address mask mogą być wysyłane z wykorzystaniem opcji odpowiednio -PP i -PM. Odpowiedzi timestamp reply (ICMP kod 14) lub address mask reply (kod 18) ujawniają aktywność hosta. Te dwa zapytania mogą być pomocne, kiedy administrator specyficznie blokuje zapytania echo request zapominając przy tym blokować inne typy ICMP, które mogą być wykorzystane w tym samym celu.

-PR (ARP Ping)
Jednym z najczęściej spotykanych scenariuszy wykorzystania Nmapa jest skanowanie sieci lokalnej ethernet. W większości sieci LAN, w szczególności wykorzystujących adresację prywatną zalecaną przez RFC1918, większość adresów IP nie jest wykorzystywana. Kiedy Nmap próbuje wysłać pakiet raw IP taki jak ICMP echo request, by poprawnie zaadresować ramkę ethernet system operacyjny musi określić (ARP) docelowy adres sprzętowy korespondujący z docelowym adresem IP. Takie zachowanie jest często powolne i problematyczne, ponieważ systemy operacyjne nie zostały napisane z uwzględnieniem potrzeby wysyłania milionów zapytań ARP o niedostępne hosty w krótkim czasie.

Skanowanie ARP wykorzystuje zoptymalizowany algorytm Nmapa do wysyłania zapytań ARP. Po otrzymaniu odpowiedzi Nmap nie musi się nawet martwić o oparte na IP pakiety ping, ponieważ już wie, że host jest aktywny. Takie zachowanie pozwala na dużo szybsze i bardziej wiarygodne skanowanie. Z tego powodu zachowanie takie jest domyślne podczas skanowania sieci, którą Nmap wykryje jako sieć lokalną należącą do tego samego segmentu. Nawet jeśli zostaną podane inne typy skanowania ping (takie jak -PE lub -PS), Nmap używa ARP zamiast nich do wykrywaia hostów w lokalnej sieci ethernet. Jeśli nie chcesz używać ARP do skanowania, dodaj opcję --send-ip.

-n (Wyłącz zapytania DNS)
Nakazuje Nmapowi nigdy nie używać zapytań odrotnych do serwerów DNS o nazwy przypisane do adresów IP. Jako że zapytania DNS są najczęściej długo trwają, opcja ta przyspiesza pracę.

-R (Wymuś zapytania DNS)
Nakazuje Nmapowi zawsze wykonywać odwrotne zapytania do serwera DNS o nazwy dla skanowanych adresów IP. Domyślnie zapytania są wykonywane tylko dla aktywnych hostów.

--system-dns (Używaj systemowego DNS)
Domyślnie Nmap określa nazwy dla adresów IP poprzez wysyłanie zapytań bezpośrednio do serwerów DNS skonfigurowanych w systemie, o ile są dostępne. Wiele zapytań (często dziesiątki) jest wykonywanych równolegle dla uzyskania wiekszej szybkości. Dodanie tej opcji wymusza wykorzystywanie rozwiązywania nazw za pośrednictwem systemu operacyjnego (każdorazowo o pojedyncze IP za pomocą funkcji getnameinfo()). Ta opcja jest wolniejsza i jest użyteczna tylko w sporadycznych przypadkach, chyba że w Nmapie jest błąd w kodzie DNS - prosze się z nami skontaktować w tym przypadku. W przypadku skanowania sieci IPv6, rozwiązywanie nazw jest zawsze wykonywane z wykorzystaniem systemu operacyjnego.

--dns-servers <server1[,server2],...> (Serwery do wykonywania zapytań DNS)
Domyślnie Nmap próbuje odczytać serwery DNS wpisane do pliku resolv.conf (UNIX) lub rejestru (Win32). Alternatywnie, możesz użyć tej opcji do podania własnych serwerów. Opcja ta nie jest uwzględniana, jeśli użyto również opcji --system-dns lub skanowane są adresy IPv6. Używanie wielu serwerów DNS jest często dużo szybsze, niż tylko jednego.



### Podstawy skanowania portów
Przez lata funkcjonalność Nmapa była sukcesywnie powiększana, z początku był tylko efektywnym skanerem portów i to nadal pozostaje jego główną funkcją. Prosta komenda nmap <target> skanuje ponad 1660 portów TCP na wybranym <celu skanowania>. Podczas kiedy większość skanerów tradycyjnie zalicza wszystkie porty do kategorii otwarty lub zamknięty, Nmap jest dużo dokładniejszy. Rozróżnia sześć możliwych stanów każdego portu: otwarty, zamknięty, filtrowany, niefiltrowany, otwarty|filtrowany, or zamknięty|filtrowany.

Te stany nie są rzeczywistymi stanami portów, opisują jak Nmap je widzi. Na przykład, skanowanie Nmapa z wnętrza sieci pokazuje port 135/TCP jako otwarty, podczas kiedy skanowanie przez Internet może określić stan portu jako filtrowany.

#### Sześć stanów portów Nmapa

otwarty
Aplikacja aktywnie akceptuje na tym porcie połączenia TCP lub pakiety UDP. Znalezienie takich portów jest głównym celem skanowania. Osoby obeznane z bezpieczeństwem wiedzą, że każdy otwarty port to potencjalny cel ataku. Atakujący i wykonujący testy penetracyjne chcą wykorzystać luki w oprogramowaniu poprzez otwarte porty, podczas gdy administratorzy starają się zamykać lub chronić je za pomocą systemów zaporowych przed niepożądanymi użytkownikami. Otwarte porty są także interesujące przy skanowaniach nie związanych z oceną bezpieczeństwa, ponieważ pokazują usługi dostępne w sieci.

zamknięty
Zamknięty port jest dostępny (odbiera i odpowiada na pakiety Nmapa), ale nie ma żadnej aplikacji, która by obsłużyła połaczenie. Porty te mogą być pomocne przy sprawdzaniu czy host jest aktywny (wykrywanie hostów lub skanowanie Ping) oraz przy wykrywaniu systemu operacyjnego. Ponieważ są dostępne zamknięte porty, warto skanować dalej w poszukiwaniu otwartych. Administratorzy mogą chcieć blokować takie porty za pomocą systemów zaporowych, wtedy ich stan zostanie określony jako filtrowany, opisany dalej.

filtrowany
Nmap nie może określić czy port jest otwarty z powodu filtrowania komunikacji. Filtrowanie może być przeprowadzane na dedykowanym urządzeniu, za pomocą reguł routera lub programowego firewalla na hoście. Takie porty są frustrujące dla atakujących, ponieważ dostarczają znikomych ilości informacji. Porty czasami odpowiadają komunikatami ICMP takim jak typ 3 kod 13 (destination unreachable: communication administratively prohibited), ale filtry blokują wysyłanie takiego komunikatu bez wysyłania typowej odpowiedzi. Takie zachowanie zmusza Nmapa do kilkukrotnego powtarzania pakietów na wypadek ich zaginięcia na przykład na skutek przeciążenia sieci, co spowalnia skanowanie w sposób drastyczny.

niefiltrowany
Stan niefiltrowane oznacza że port jest dostępny, ale Nmap nie jest w stanie ustalić czy port jest otwarty czy zamknięty. Tylko skanowanie ACK, które jest używane do mapowania reguł firewalla, może przypisać portom taki stan. Skanowanie niefiltrowanych portów za pomocą innych typów skanowania takich jak Window, SYN czy FIN może pomóc określić czy port jest otwarty czy zamknięty.

otwarty|filtrowany
Nmap podaje taki stan w przypadku portów, dla których nie jest w stanie określić czy port jest otwarty, czy filtrowany. Taki zachowanie występuje podczas typów skanowania, przy których porty nie dają odpowiedzi. Brak odpowiedzi może również oznaczać, że filtr pakietów zablokował połączenie lub wysyłaną odpowiedź. Z tego powodu Nmap nie ma pewności czy port jest otwarty, czy filtrowany. W ten sposób klasyfikują porty skanowania UDP, FIN, Null, Xmas i skanowanie protokołów.

zamknięty|filtrowany
Ten stan jest używany przez Nmapa do oznaczania portów, dla których nie jest możliwe ustalenie czy port jest zamknięty czy filtrowany. Taki stan może się pojawiać tylko podczas skanowania IPID Idle.


### Techniki skanowania portów
Jako początkujący mechanik samochodowy, mogłem godzinami męczyć się z wykonaniem naprawy posiadanymi narzędziami (młotek, taśma izolacyjna, klucz francuski itp.). Kiedy popadłem w depresję i w końcu zaprowadziłem mojego gruchota do prawdziwego mechanika, pogrzebał w przepastnej skrzyni z narzędziami i wyciągnął specjalne narzędzie, którym wykonał naprawę błyskawicznie i bez kłopotów. Sztuka skanowania polega dokładnie na tym samym. Eksperci znają dziesiątki typów skanowania i wybierają jedną adekwatną (lub kombinację kilku) do danego zadania. Z drugiej strony niedoświadczeni użytkownicy i script kiddies próbują rozwiązać każdy problem za pomocą domyślnego skanowania SYN. Nmap jest darmowy i dostępny dla wszyskich, w związku z tym jedyną barierą jest odpowiednia wiedza. To oczywiście bije na głowę świat motoryzacyjny, gdzie trzeba posiadać duże umiejętności, żeby domyślić się, że potrzebne jest bardzo specyficzne narzędzie, ale wtedy potrzeba jeszcze dużo pieniędzy na jego zakup.

Większość typów skanowania jest dostępna tylko dla uprzywilejowanych użytkowników, ponieważ tylko oni mogą wysyłać pakiety raw. Takim użytkownikiem w przypadku systemów UNIX jest root. Używanie konta administratora w systemach Windows jest zalecane, jednak Nmap przeważnie działa poprawnie z konta zwykłego użytkownika przy zainstalowanej w systemie bibliotece WinPcap. Wymóg posiadania uprawnień użytkownika root był poważnym ograniczeniem kiedy pojawił się Nmap w 1997 roku, jako że użytkownicy posiadali dostęp głównie tylko do współdzielonych kont. Świat się zmienił. Komputery są tańsze, coraz więcej ludzi ma bezpośredni dostęp do Internetu i coraz powszechniejsze stają się komputery z systemami UNIX (włączając Linuxa i MAC OS X). Dostępna jest również Windowsowa wersja Nmapa, co powiększa możliwości jego wykorzystywania. Z tych powodów coraz rzadziej zachodzi potrzeba uruchamiania Nmapa z ograniczonych współdzielonych kont. Na szczęście większe przywileje użytkowników przekładają się na większą elastyczność i możliwości Nmapa.

Nmap stara się podawać jak najbardziej dokładne wyniki, jednak trzeba mieć na uwadze fakt, że wyniki są oparte na pakietach zwracanych przez badane systemy (lub firewalle je ochraniające). Dlatego też zwracane informacje nie muszą być wiarygodne i mogą wprowadzać Nmapa w błąd. Bardzo powszechne są hosty nie zachowujące się zgodnie z RFC w odpowiedzi na zapytania Nmapa. Rozwiązaniem są skanowania FIN, Null czy Xmas. Tego typu problemy zostały opisane oddzielnie w częściach poświęconych poszczególnym typom skanowania.

Ta sekcja opisuje dziesiątki typów skanowania dostępnych w Nmapie. Jednocześnie może być wykorzystywana tylko jedna metoda, za wyjątkiem skanowania UDP (-sU), które może być łączone z dowolnymi typami skanowania TCP. Dla łatwiejszego zapamiętania, opcje skanowania portów posiadają nazwy w formie -s<C>, gdzie <C> jest przeważnie pierwszą dużą literą angielskiej nazwy typu skanowania. Wyjątkiem jest przestarzała opcja skanowania FTP bouce (-b). Domyślnie Nmap wykonuje skanowanie SYN, które jest zastępowane connect(), jeśli użytkownik nie ma odpowiednich uprawnień do wysyłania pakietów raw (co wymaga konta root w systemach UNIX) lub w przypadku skanowania sieci IPv6. Z pośród przedstawionych poniżej typów skanowania użytkownicy nie uprzywilejowani mogą jedynie używać typów connect() i FTP bounce.

-sS (Skanowanie TCP SYN)
Skanowanie SYN jest domyślną i najpopularniejszą metodą skanowania. Jest to spowodowane tym, że może być przeprowadzone szybko, możliwe jest skanowanie tysięcy portów na sekundę w szybkich sieciach nie chronionych systemami zaporowymi. Skanowanie SYN jest relatywnie dyskretne i niewidoczne, ponieważ nigdy nie otwiera połączeń do końca. Działa to dobrze w stosunku do wszystkich stosów zgodnych z TCP, w przeciwieństwie do udziwnionych, dla których Nmap ma tryby FIN/Null/Xmas, Maimon i Idle. SYN pozwala na przejrzyste i wiarygodne rozróżnienie stanów portu pomiędzy otwartym, zamkniętym i filtrowanym.

Technika ta jest często określana jako skanowanie z połowicznym otwieraniem połączeń (ang. half-open), ponieważ nie otwiera pełnego połączenia TCP. Wysyłany jest pakiet SYN, tak jak by miało być otwarte prawdziwe połączenie i czeka na odpowiedź. SYN/ACK oaznacza, że port oczekuje na połączenia (jest otwarty), a RST (reset) identyfikuje port jako zamknięty. Jeśli odpowiedź nie zostanie otrzymana pomimo kilku prób, port jest oznaczany jako filtrowany. Port jest również oznaczany jako filtrowany w przypadku otrzymania komunikatu błędu ICMP unreachable error (typ 3, kody 1, 2, 3, 9, 10 lub 13).

-sT (Skanowanie TCP connect())
Skanowanie TCP Connect() jest wybierane domyślne, jeśli SYN nie jest dostęne. Ma to miejsce kiedy użytkownik nie posiada uprawnień do wysyłania pakietów raw lub podczas skanowania sieci IPv6. Zamiast wysyłać pakiety raw, jak to ma miejsce przy innych typach skanowania, Nmap prosi system operacyjny o zestawienie połączenia z badanym hostem za pomocą wywołania funkcji systemowej connect(). Jest to taki sam wysoki poziom wywołań systemowych, z jakich korzystają przeglądarki internetowe, oprogramowanie Peer2Peer czy inne programy korzystające z połączeń sieciowych. Jest to część interfejsu programistycznego znanego jako Berkeley Sockets API. Zamiast odczytywać odpowiedzi za pomocą odwołań niskopoziomowych prosto z sieci, Nmap wykorzystuje ten sam wysokopoziomowy interfejs do otrzymania informacji o stanie operacji dla każdej próby połączenia oddzielnie.

Kiedy skanowanie SYN jest dostępne, przeważnie jest lepszym wyborem. Nmap ma dużo mniejszą kontrolę nad wywołaniem wysokopoziomowym connect() niż nad pakietami raw, co jest dużo mniej efektywne. Wywołanie systemowe otwiera pełne połączenie w przeciwieństwie do metody SYN korzystającej z połowicznego połączenia. Nie tylko wymaga to więcej czasu i wymaga więcej pakietów do uzyskania takich samych informacji, ale również prawdopodobnie spowoduje zapisanie w logach badanego systemu próby połączenia. Nowoczesne systemy detekcji intruzów IDS potrafia wykrywać takie połączenia, ale większość systemów nie posiada odpowiednich systemów alarmowych. Wiele usług w typowym systemie UNIX zapisze uwagę do logu systemowego i czasami zagadkowy komunikat błędu, kiedy Nmap połączy się i natychmiast zamknie połączenie bez wysyłania jakichkolwiek danych. Naprawdę żałosne usługi przestaną działać po otrzymaniu takiego pakietu, ale nie jest to często spotykane. Administrator widzący w logach informacje o wielu próbach nawiązania połączenia z jednego adresu powinien wiedzieć, że jego system był skanowany za pomocą metody connect().

-sU (Skanowanie UDP)
Większość popularnych usług w sieci Internet wykorzystuje protokół TCP, ale również usługi UDP są często spotykane. Najpopularniesze z nich to DNS, SNMP i DHCP (porty 53, 161/162 i 67/68). Ponieważ skanowanie UDP jest ogólnie wolniejsze i trudniejsze niż TCP, wielu audytorów bezpieczeństwa ignoruje te porty. Jest to pomyłka, jako że wiele usług UDP jest podatnych na zdalne ataki i atakujący nie ignorują tego protokołu. Na szczęście Nmap umożliwia inwentaryzację portów UDP.

Skanowanie UDP jest aktywowane za pomocą opcji -sU. Może być łączone z innymi typami skanowania TCP, takimi jak SYN (-sS), dla sprawdzenia obu protokołów w jednym przebiegu.

Skanowanie UDP polega na wysyłaniu pustych (bez danych) nagłówków protokołu UDP do każdego portu docelowego. Jeśli w odpowiedzi zostanie zwrócony komunikat ICMP port uchreachable (typ 3, kod 3), port jest uznawany za zamknięty. Inne typy komunikatów ICMP unreachable (typ 3, kody 1, 2, 9, 10 lub 13) oznaczają, że port jest filtrowany. Czasami w odpowiedzi zwrócony zostanie pakiet UDP, co oznacza, że porty jest otwarty. Jeśli pomimo powtarzania transmisji nie zostanie uzyskana żadna odpowiedź, port zostaje zaklasyfikowany jako otwarty|filtrowany. Oznacza to, że port może być otwarty lub filtr pakietów blokuje do niego dostęp. Wykorzystanie skanowania wersji usług (-sV) może pomóc w odróżnieniu portów na prawdę otwartych od filtrowanych.

Największym wyzwaniem przy skanowaniu UDP jest przeprowadzenie go odpowiednio szybko. Otwarte i filtrowane porty rzadko wysyłają jakąkolwiek odpowiedź, zmuszając Nmapa do oczekiwania na odpowiedź i ponawiania transmisji na wypadek zagubienia pakietów. Zamknięte porty są często jeszcze większym problemem. Zwykle wysyłają pakiet ICMP port unreachable, jednak w odróżnieniu od pakietów z flagą RST znanych ze skanowania SYN czy connect, wiele hostów domyślnie limituje szybkość wysyłania pakietów ICMP port unreachable. Przykładami mogą być systemy Linux i Solaris. Kernel Linuxa w wersji 2.4.20 limituje ilość pakietów o niedostępności portów do jednego na sekundę (w net/ipv4/icmp.c).

Nmap potrafi wykrywać limitowanie odpowiedzi i zwalnia odpowiednio proces skanowania dla uniknięcia zaśmiecania sieci niepotrzebnymi pakietami, które i tak nie zostaną wykorzystane. Niestety, skanowanie wszystkich 65,536 portów UDP przy limicie Linuxowym jeden pakiet na sekundę powoduje, że skanowanie trwa ponad 18 godzin. Sposobami na przyspieszenie są skanowanie wielu hostów równolegle, wykonywanie na początek szybkiego skanowania popularnych portów, skanowanie z poza systemu zaporowego i używanie opcji --host-timeout do pomijania zbyt wolnych hostów.

-sN; -sF; -sX (Skanowania TCP Null, FIN i Xmas)
Te typy skanowania (większe możliwości posiada opcja --scanflags opisana w dalszej części) wykorzystują nieopisane w TCP RFC kombinacje flag do rozróżnienia pomiędzy stanami portów otwarty oraz zamknięty. Strona 65 opisuje, że „jeśli [docelowy] port jest ZAMKNIĘTY ... w odpowiedzi na pakiet nie zawierający RST należy wysłać odpowiedź RST.” Następna strona opisuje pakiety wysyłane na porty bez flag SYN, RST lub ACK w następujący sposób: „coś takiego nie powinno mieć miejsca, jednak jeśli się zdarzy, pomiń taki pakiet”.

Podczas skanowania systemów zgodnych z zapisami w RFC, dowolny pakiet nie zawierający flag SYN, RST lub ACK powinien wywoływać odpowiedź RST w przypadku portu zamkniętego i całkowity brak odpowiedzi w przypadku portu otwartego. Tak długo jak żadna z wymienionych flag nie została użyta, wszystkie inne kombinacje flag (FIN, PSH i URG) są prawidłowe. Nmap wykorzystuje to do przeprowadzania trzech typów skanowania:

Skanowanie Null (-sN)
Nie ustawia żadnych flag (pole flag w nagłówku tcp zawiera 0).

Skanowanie FIN (-sF)
Ustawiona flaga FIN.

Skanowanie Xmas (-sX)
Ustawione flagi FIN, PSH i URG, pakiet podświetlony jak choinka.

Te trzy tryby skanowania są takie same poza ustawionymi flagami w pakietach. Jeśli w odpowiedzi zostanie otrzymany pakiet RST, port jest uznawany za zamknięty, podczas gdy brak odpowiedzi oznacza otwarty|filtrowany. Port uznajemy za filtrowany, jeśli otrzymany zostanie komunikat ICMP unreachable (typ 3, kod 1, 2, 3, 9, 10 lub 13).

Główną zaleta tych typów skanowania jest to, że potrafią się one przemykać przez bezstanowe systemy zaporowe i filtrowanie na routerach. Inną zaletą jest tylko minimalnie większa wykrywalność niż skanowania SYN. Nie można jednak na to liczyć - większość nowych systemów IDS może zostać skonfigurowana do ich wykrywania. Ujemną stroną jest to, że nie wszystkie systemy są zgodne z RFC793. Wiele systemów wysyła odpowiedzi RST niezależnie od tego czy port jest otwarty czy nie. Powoduje to, że wszystkie porty pojawiają się jako zamknięty. Najczęściej spotykane systemy, które się tak zachowują to Microsoft Windows, wiele urządzeń Cisco, BSDI, i IBM OS/400. Skanowania działają jednak dobrze w przypadku większości systemów UNIXowych. Kolejnym minusem tych metod jest to, że nie potrafią rozróżnić portów oznaczonych jako otwarty od filtrowany, ujawniając jedynie stan otwarty|filtrowany.

-sA (Skanowanie TCP ACK)
Ten typ skanowanie jest inny niż omawiane powyżej, bo nigdy nie wykrywa stanów portów otwarty (lub nawet otwarty|filtrowany). Jest wykorzystywany do mapowania reguł filtrowania, do sprawdzania czy fitrowanie jest oparte o stany (stateful) lub nie i które porty są filtrowane.

Pakiety skanowania ACK posiadają tylko flagę ACK (o ile nie została użyta opcja --scanflags). Podczas skanowania systemów nie posiadających filtrowania, porty o stanach otwarty i zamknięty zwrócą pakiet RST. W obu przypadkach Nmap oznaczy je jako niefiltrowane, co oznacza, że były osiągalne dla pakietu ACK, ale nie zostało określone, czy posiadają stan otwarty czy zamknięty. Porty, które nie odpowiedzą lub odpowiedzą za pomocą komunikatu o błędzie ICMP (typ 3, kody 1, 2, 3, 9, 10 lub 13), zostaną oznaczone jako filtrowany.

-sW (Skanowanie TCP Window)
Skanowanie Window jest takie samo jak ACK, różnica polega na tym, że potrafi odróżnić porty otwarte od zamkniętych, zamiast zawsze podawać stan niefiltrowany, kiedy otrzymano flagę RST. Jest to realizowane poprzez analizę pola Window pakietu zwrotnego RST. Na niektórych systemach, otwarte porty zwracają dodatnią wartość rozmiaru okna (także w pakietach RST), a przy zamkniętych o rozmiarze zero. Tak więc zamiast zawsze przedstawiać port jako niefiltrowany kiedy w odpowiedzi przyjdzie RST, skanowanie Window oznacza port jako otwarty lub zamknięty, w zależności czy odpowiednio otrzymano w odpowiedzi rozmiar okna o wartości dodatniej lub zero.

Ten typ skanowania polega na szczególnej implementacji stosu TCP, występującej w rzadko spotykanych systemach w internecie, a więc nie można zawsze na niej polegać. Zwykle systemy, które nie obsługują tej metody będą zwracały porty oznaczone jako zamknięty. Oczywiście jest również możliwe, że host na prawdę nie ma otwartych portów. Jeśli większość przeskanowanych portów ma stan zamknięty, jednak niektóre (takie jak 22, 25 czy 53) mają stan filtrowany, system jest podejrzany. Czasami systemy potrafią się zachowywać zupełnie przeciwnie. Jeśli skanowanie wykaże 1000 otwartych portów i tylko 3 zamknięte lub filtrowane, wtedy te trzy prawdopodobnie są rzeczywiście otwarte.

-sM (Skanowanie TCP Maimon)
Skanowanie Maimon zostało nazwane na cześć jego odkrywcy, Uriela Maimona. Opisał tę technikę w Phrack Magazine w wydaniu #49 (Listopad 1996). Nmap, który potrafił wykorzystać tę technikę został wypuszczony dwa wydania później. Skanowanie to należy do rodziny Null, FIN i Xmass z tą różnicą, że używa flag FIN/ACK. Zgodnie z RFC 793 (TCP), dla takiej kombinacji flag, pakiet RST powinien być wygenerowany niezależnie czy port jest otwarty czy zamknięty. Jednakże Uriel zauważył, że wiele systemów opartych na BSD po prostu pomija odpowiedzi, jeśli port jest otwarty.

--scanflags (Skanowanie TCP z definiowanymi flagami)
Prawdziwie zaawansowani użytkownicy Nmapa nie mogą być ograniczani ilością oferowanych wbudowanych typów skanowania. Opcja --scanflags pozwala na projektowanie własnych typów skanowania z wykorzystaniem wybranych flag TCP. Cieszcie się podczas wykorzystywania tej techniki do oszukiwania systemów IDS, których twórcy pobieżnie przeglądali dokumentację Nmapa dodając specyficzne reguły!

Argument opcji --scanflags może być numerycznym zapisem flag, np 9 (PSH i FIN), lub dla ułatwienia można wykorzystywać symbliczne nazwy. Można podać dowolną kombinację flag URG, ACK, PSH, RST, SYN i FIN. Na przykład --scanflags URGACKPSHRSTSYNFIN ustawia wszystkie flagi, choć nie jest to zbyt użyteczna metoda skanowania. Kolejność podawania flag nie jest istotna.

Dodatkowo przy podawaniu wybranych flag możliwe jest podanie typu skanowania (takiego jak -sA lub -sF). Dodany typ skanowania informuje Nmapa jak ma interpretować otrzymane odpowiedzi. Na przykład skanowanie SYN zakłada, że brak odpowiedzi oznacza stan portu filtrowany, podczas gdy skanowanie FIN potraktuje ten go jako otwarty|filtrowany. Nmap będzie się zachowywał w taki sam sposób jak przy wybranym trybie skanowania, jednak wykorzystane zostaną podane flagi. Jeśli bazowy typ skanowania nie zostanie określony, zostanie wykorzystany domyślny typ SYN.

-sI <zombie host[:probeport]> (Skanowanie Idle)
Ta zaawansowana technika skanowania pozwala na prawdziwie ślepe skanowanie TCP (co oznacza, że żaden pakiet nie zostanie wysłany do badanego systemu z prawdziwego adresu IP Nmapa). Zamiast tego wykorzystany zostanie host zombie, o przwidywalnym działaniu stosu TCP polegającym na sekwencyjnym powiększaniu numerów ID pakietów, do uzyskania informacji o otwartych portach w badanym systemie. Systemy detekcji intruzów pokażą jako adres atakującego zdefiniowany host zombie (musi spełniać określone warunki). Ten fascynujący typ skanowania jest zbyt skomplikowany żeby go dokładnie opisać w tej dokumentacji, dlatego napisałem oddzielny nieformalny dokument na ten temat ze szczegółowymi informacjami i jest on dostępny pod adresem https://nmap.org/book/idlescan.html.

Poza tym, że metoda ta jest niespotykanie poufna (z powodu jej ślepej natury), ten typ skanowania pozwala na mapowanie reguł zaufania pomiędzy maszynami bazujących na adresach IP. Wyniki zawierają otwarte porty, z punktu widzenia hosta zombie . Tak więc można próbować skanowania z wykorzystaniem różnych hostów zombie, które można traktować jako zaufane (poprzez router/reguły filtrowania pakietów).

Można po dwukropku dodać numer portu, jeśli chcemy go wykorzystać na hoście zombie do badania zmian IPID. W innym przypadku Nmap wykorzysta domyślnie port używany przez tcp ping (80).

-sO (Skanowanie protokołów IP)
Skanowanie to pozwala na wykrycie listy protokołów IP (TCP, ICMP, IGMP itp), które są dostępne na danym hoście. Technicznie nie jest to skanowanie portów, ponieważ sprawdza kolejne numery protokołów, a nie kolejne porty TCP czy UDP. Opcja ta nadal używa parametru -p do wybrania numerów protokołów do sprawdzenia, w formacie analogicznym do listy portów. Z tego powodu metoda ta została zaklasyfikowana jako skanowanie portów i dlatego znajduje się tutaj.

Poza swoją własną funkcjonalnością, skanowanie protokołów demonstruje potęgę oprogramowania open source. Podczas gdy podstawowa idea jest całkiem prosta, nie pomyślałem o jej dodaniu, jak również nie otrzymałem żadnej prośby o dodanie takiej funkcjonalności. Latem roku 2000, Gerhard Rieger opracował koncepcję, stworzył odpowiednią poprawkę i wysłał ją na listę dyskusyjną nmap-hackers. Włączyłem ją do drzewa Nmapa i wypuściłem nową wersję następnego dnia. Niewiele komercyjnych programów posiada użytkowników na tyle entuzjastycznych, żeby zaprojektować i stworzyć ich własne poprawki!

Skanowanie protokołów działa w sposób podobny do skanowania UDP, jednak zamiast iteracji po kolejnych numerach portu, w nagłówkach pakietów zmienia się 8-mio bitowy numer protokołu. Nagłówki są przeważnie puste, nie zawierają żadnych danych ani nawet poprawnego dla danego protokołu nagłówka. Trzema wyjątkami są TCP, UDP i ICMP. Poprawne nagłówki dla tych protokołów są konieczne, ponieważ niektóre systemy nie będą ich potrafiły wysłać oraz dlatego, że Nmap posiada już odpowiednie funkcje do ich tworzenia. Zamiast obserwować komunikaty ICMP unreachable, skanowanie protokołów nie polega na komunikatach ICMP protocol unreachable. Jeśli Nmap otrzyma jakąkolwiek odpowiedź w jakimkolwiek protokole, ustala stan protokołu jako otwarty. Otrzymanie komunikatu ICMP protocol unreachable (typ 3, kod 2) powoduje oznaczenie protokołu jako zamknięty. Inne komuniakty ICMP protocol unreachable (typ 3, kody 1, 3, 9, 10 lub 13) powodują oznaczenie protokołu jako filtrowany (oraz równocześnie potwierdzają, że protokół ICMP jest również otwarty). Jeśli nie uzyskano odpowiedzi, protokół jest oznaczany jako otwarty|filtrowany.

-b <pośredniczący host ftp> (Skanowanie FTP bounce)
Interesującą funkcją protokołu FTP (RFC 959) jest wspieranie tak zwanych połączeń proxy. Pozwala to użytkownikowi na połączenie z jednym serwerem FTP i poproszenie o wysłanie plików do innego. Ta funkcjonalność była przyczyną nadużyć na wielu poziomach, dlatego wiele serwerów porzuciło dla niej wsparcie. Jednym z możliwych nadużyć jest sposobność do zmuszenia serwera do skanowania portów na zewnętrznym hoście. Wystarczy po prostu poprosić serwer o wysłanie pliku kolejno na każdy interesujący port badanego systemu. Uzyskany komunikat o błędzie zwróci informację, czy porty był otwarty czy zamknięty. Jest to dobra metoda do omijania systemów zaporowych, ponieważ korporacyjne serwery FTP często są umieszczane w takim miejscu, że mają możliwość komunikacji zarówno z hostami w internecie jak i w sieci lokalnej. Nmap obsługuje skanowanie FTP bounce z wykorzystaniem opcji -b. Opcja przyjmuje argument w postaci <nazwa_użytkownika>:<hasło>@<serwer>:<port>. <Serwer> jest nazwą lub adresem IP podatnego serwera FTP. Tak jak przy zwykłym adresie URL, można pominąć pola <nazwa_użytkownika>:<hasło>, w tym przypadku zostanie wykorzystana domyślna kombinacja dla użytkowników anonimowych (użytkownik anonymous hasło:-wwwuser@). Numer portu (i poprzedzający go dwukropek) również może zostać pominięty, w tym przypadku przy połączeniu z wybranym adresem <serwer>, zostanie wykorzystany domyślny port serwera FTP (21).

Podatność ta była szeroko spotykana w roku 1997, kiedy to Nmap został wypuszczony, jednak z biegiem czasu jej znaczenie bardzo się zmniejszyło. Dziurawe serwery FTP nadal się zdarzają, więc warto wyprubować i tę metodę, jeśli inne zawiodą. Jeśli potrzebne jest obejście systemu zaporowego, można przeskanować sieć w poszukiwaniu otwartych portów 21 (lub poprzez wyszukanie ftp na innych portach z wykorzystaniem opcji do wykrywania wersji) i wypróbować na wykrytych portach metodę bounce. Nmap poinformuje, czy usługa jest podatna czy nie. Jeśli chcesz ukrywać swoje działania, nie trzeba (i nie powinno) ograniczać się do hostów z badanej sieci. Przed rozpoczęciem skanowania losowych adresów w sieci Internet w poszukiwaniu podatnych wersji serwerów FTP trzeba mieć na uwadze, że wielu administratorów nie bedzie zachwyconych wykorzystywaniem ich serwerów w ten sposób.


### Specyfikacja portów i kolejności skanowania
Poza wszystkimi metodami skanowania opisanymi wcześniej, Nmap oferuje opcję pozwalającą na podanie numerów portów do skanowania i określenie, czy skanowanie ma przebiegać w kolejności sekwencyjnej czy losowej. Domyślnie Nmap skanuje wszystkie porty do 1024 włącznie oraz wyższe porty wyszczególnione w pliku nmap-services.

-p <zakres portów> (Skanuj tylko wybrane porty)
Opcja pozwala na zdefiniowanie listy portów do skanowania, zamiast domyślnej. Możliwe jest podanie pojedynczych portów jak i zakresów oddzielonych myślnikiem (np. 1-1023). Zakres można również pominąć, co spowoduje użycie całego zakresu (1-65535). Można więc po prostu podać opcję -p- do przeskanowania wszystkich portów od 1 do 65535 włącznie. Można również podać port zero, ale trzeba to zrobic jawnie. W przypadku połączenia tej opcji ze skanowaniem protokołów (-sO), określa ona numery protokołów do sprawdzenia (0-255).

Przy jednoczesnym skanowaniu portów TCP i UDP możliwe jest oddzielne zdefiniowanie portów dla obu protokołów poprzez poprzedzenie numerów znakami odpowiednio T: i U:. Jako argument opcji przyjmowany jest ciąg znaków aż do następnej opcji. Na przykład, podanie -p U:53,111,137,T:21-25,80,139,8080 spowoduje przeskanowanie portów UDP o numerach 53,111 i 137 oraz podanych portów TCP. Przy skanowaniu zarówno portów TCP jak i UDP, nie można zapomnieć podać odpowiednich typów skanowania: -sU oraz przynajmniej jednego TCP (np. -sS, -sF czy -sT). Jeśli nie podano protokołu skanowania, na czas skanowania numery portów zostaną dodane do domyślnej listy portów.

-F (Skanowanie Fast (ograniczona ilość portów))
Pozwala na określenie, że mają być skanowane tylko porty zawarte w pliku nmap-services z pakietu Nmapa (lub z pliku protokołów dla opcji -sO). Opcja ta pozwala na szybsze skanowanie, niż w przypadku wszystkich 65535 portów. Ponieważ lista ta zawiera tylko nieco ponad 1200 portów, różnica w szybkości w porównaniu do typowego skanowania TCP (około 1650 portów) nie jest duża. Różnica może być większa, jeśli zostanie podany własny, mały plik nmap-services za pomocą opcji --datadir.

-r (Nie używaj losowej kolejności)
Domyślnie Nmap skanuje porty w kolejności losowej (poza niektórymi najczęściej wykorzystywanymi portami, które są skanowane na początku ze względów wydajnościowych). Takie zachowanie jest normalnie pożądane, jednak można je wyłączyć za pomocą opcji -r, wymuszającej sekwencyjną kolejność skanowania.


### Detekcja usług i wersji
Przy skanowaniu zdalnego systemu, Nmap może wykryć otwarte porty takie jak 25/tcp, 80/tcp czy 53/udp. Wykorzystując bazę danych zawierającą około 2,200 popularnych usług, znajdującą się w pliku nmap-services, Nmap odczyta przypuszczalne nazwy usług dla wykrytych portów - odpowiednio serwer pocztowy (SMTP), serwer WWW (HTTP) i serwer nazw (DNS). Takie działanie jest zwykle poprawne, większość aplikacji słuchających na porcie 25, to rzeczywiście serwery pocztowe. Jednakże, niech Twoja ocena bezpieczeństwa niepolega na tych podpowiedziach! Ludzie mogą i często umieszczają usługi na dziwnych portach.

Nawet jeśli Nmap sie nie myli i hipotetyczny serwer z przykładu powyżej udostępnia usługi SMTP, HTTP i DNS, nie jest to duża ilość informacji na temat tych usług. Przeprowadzając testy bezpieczeństwa (lub zwykłą inwentaryzację zasobów) swojej firmy lub klienta, potrzeba uzyskać dokładniejsze informacje na temat usług: jaka aplikacja i w jakiej wersji jest zainstalowana na serwerze SMTP czy DNS. Posiadanie tych informacji w znaczący sposób wpływa na możliwość ustalenia podatności danej aplikacji. Detekcja wersji pozwala na uzyskanie takiej informacji.

Po tym jak zostaną wykryte za pomocą innych technik skanowania dostępne usługi TCP i UDP, detekcja wersji odpytuje porty w celu określenia dalszych szczegółów na temat aplikacji. Baza danych nmap-service-probes zawiera opisy wielu usług i próbuje dopasować je do uzyskanych informacji. Nmap stara się najpierw określić protokół wykorzystywany przez usługę (np. ftp, ssh, telnet, http), następnie nazwę aplikacji (np. ISC Bind, Apache httpd, Solaris telnetd), wersję usługi, nazwę hosta, typ urządzenia (np. drukarka, router), rodzinę systemów operacyjnych (np. Windows, Linux) i czasami uzyskuje dodatkowe informacje (takie jak czy X serwer przyjmuje połączenia, obsługiwane wersje protokołu SSH czy nazwę użytkownika KaZaA). Oczywiście większość usług nie dostarczy wszystkich tych informacji. Jeśli Nmap został skompilowany z OpenSSL, będzie potrafił łączyć się z serwerami SSL i uzyskiwać informacje od usług ukrytych za szyfrowaną warstwą. Kiedy zostaną wykryte usługi RPC, odpowiedni skaner (-sR) zostanie automatycznie uruchomiony do ustalenia oprogramowania i wersji RPC. Z powodu specyfiki UDP, po zakończeniu skanowania niektóre porty pozostają w stanie otwarty|filtrowany, jako że ten typ skanowania nie potrafi określić, czy port jest otwarty czy filtrowany. Skanowanie wersji spróbuje uzyskać odpowiedź od takiego portu (tak jak to robi przy otwartych portach) i jeśli to się uda, zmieni stan na otwarty. Porty TCP w stanie otwarty|filtrowany są traktowane w ten sam sposób. Należy zwrócić uwagę, że opcja -A poza innymi rzeczami włącza wykrywanie wersji. Dodatkowa dokumentacja na temat działania detekcji wersji jest dostępna pod adresem http://www.insecure.org/nmap/vscan/.

Jeśli Nmap otrzyma odpowiedź, ale nie jest w stanie dopasować jej do żadnej znanej usługi, wyświetli specjalny odcisk palca (fingerprint) usługi wraz z adresem URL, pod którym można go następnie wysłać wraz ze stosownym opisem, jeśli jesteśmy pewni jakiej usłudze odpowiada. Proszę poświęcić te kilka minut na wysłanie informacji o nieznanych usługach, a będą mogli z tego skorzystać również inni użytkownicy Nmapa. Dzięki temu sposobowi wysyłania Nmap rozpoznaje około 3,000 odcisków dla ponad 350 protokołów usług, takich jak smtp, ftp, http itp.

Detekcja wersji jest włączana i kontrolowana następującymi opcjami:

-sV (Detekcja wersji usług)
Włącza detekcję wersji usług, opisaną powyżej. Alternatywnie można użyć opcji -A do jednoczesnego włączenia detekcji wersji usług i systemu operacyjnego.

--allports (Nie pomijaj żadnych portów przy detekcji wersji)
Domyslnie, skanowanie wersji Nmapa pomija port TCP 9100, ponieważ niektóre drukarki po prostu drukują wszystko, co zostanie przysłane na ten port, powodując wydruk setek stron z zapytaniami HTTP, binarnymi zapytaniami SSL itp. Takie zachowanie może zostać wyłączone poprzez modyfikację lub usunięcie dyrektywy Exclude w pliku nmap-service-probes, lub poprzez dodanie opcji --allports, wymuszającej skanowanie wszystkich portów niezależnie od dyrektywy Exclude.

--version-intensity <poziom> (Ustaw poziom skanowania wersji)
Podczas przeprowadzania skanowania wersji (-sV), Nmap przeprowadza serię testów, przy czym każdy z nich ma przypisany swój poziom pomiędzy 1 a 9. Niskie poziomy działają poprawnie w stosunku do najpopularniejszych usług, wysokie numery obejmują mało popularne. Poziom skanowania określa które testy zostaną wykonane. Czym wyższy poziom, tym większa szansa na prawidłowe rozpoznanie mało popularnych usług. Domyśly poziom to 7. Jeśli test zostanie powiązany z wykrytą usługą z pliku nmap-service-probes, określoną dyrektywą ports, zostanie on wykonany niezależnie od ustalonego poziomu wykrywania wersji. Zachowanie takie ma na celu zawsze poprawne wykrywanie domyślnych usług na otwartych portach, wykrywanie serwera DNS na porcie 53, SSL na porcie 443 itp.

--version-light (Włącz tryb delikatny)
Jest wygodniejszym odpowiednikiem ustalającym wartość --version-intensity 2. Opcja ta pozwala na znaczne przyspieszenie wykrywania wersji, kosztem dokładności.

--version-all (Użyj wszystkich testów)
Odpowiednik opcji --version-intensity 9, powodujący wykonanie wszystkich możliwych testów na każdym porcie.

--version-trace (Śledzenie aktywności skanowania wersji)
Opcja włącza opcje śledzenia błędów podczas wykrywania wersji, powodując wyświetlanie dodatkowych informacji na temat prowadzonych działań. Opcja ta jest częścią większej --packet-trace.

-sR (Skanowanie RPC)
Metoda ta działa w połączeniu z różnymi metodami skanowania portów Nmapa. Na wszystkie wykryte wcześniej porty są wysyłane komendy NULL SunRPC i za ich pomocą sprawdzane jest, czy dany port należy do usług RPC. Jeśli tak, identyfikowana jest aplikacja i jej wersja. Opcja pobiera takie same informacje jak komenda rpcinfo -p, nawet jeśli host jest chroniony za pomocą systemu zaporowego (lub TCP wrapperów). Hosty pośrednie zombie nie są obsługiwane przy tym trybie skanowania. Opcja jest automatycznie aktywowana jako część wykrywania wersji usług (-sV). Jako że detekcja wersji jest daleko bardziej uniwersalna, opcja -sR jest wykorzystywana sporadycznie.


### Wykrywanie systemu operacyjnego
Jedna z najbardziej znanych możliwości Nmapa jest zdalna detekcja systemu operacyjnego za pomocą odcisków palca (fingerprint) stosu TCP/IP. Nmap wysyła serię pakietów TCP i UDP do zdalnego systemu i analizuje praktycznie każdy bit z uzyskanych odpowiedzi. Po wykonaniu dziesiątek testów takich jak próbkowanie ISN TCP, analiza opcji protokołu TCP i kolejności, próbkowanie IPID i kontrola początkowych rozmiarów okna, Nmap porównuje uzyskane wyniki z bazą z pliku nmap-os-fingerprints zawierającą ponad 1500 znanych odcisków systemów operacyjnych i wyświetla wynik, jeśli udało sie go odnaleźć. Każdy odcisk zawiera tekstowy opis systemu operacyjnego, nazwę jego producenta (np. Sun), nazwę systemu (np. Solaris), generację (np. 10) i typ urządzenia (przeznaczenie ogólne, router, switch, konsola do gier itp).

Jeśli Nmap nie może ustalić systemu i warunki do jego wykrycia są wystarczające (np. wykryto przynajmniej jeden otwarty i jeden zamknięty port), Nmap poda adres URL, dzięki któremu, jeśli jesteśmy pewni, możliwe jest wysłanie opisu nieznanego systemu, wraz z jego odciskiem. Wykonanie tej operacji przyczynia się do rozbudowy bazy i poprawy wykrywania, na czym korzystają wszyscy użytkownicy.

Detekcja systemu operacyjnego pozwala na uzyskanie innych informacji, które są zbierane podczas tego procesu. Jedną z nich jest czas od uruchomienia hosta, co jest uzyskiwane poprzez wykorzystanie opcji TCP timestamp (RFC 1323) do ustalenia kiedy host był restartowany. Informacja ta jest podawana tylko wtedy, jeśli host jej dostarcza. Inną informacją jest klasyfikacja przewidywalności numerów sekwencyjnych TCP. Badane jest prawdopodobieństwo możliwości wstrzyknięcia pakietów w przechwycone połączenie. Informacja ta jest przydatna w przypadku testowania połączeń opartych na zaufaniu do adresu IP nadawcy (rlogin, filtry firewalla itp) lub podczas ukrywania źródła ataku. Ten typ ataków jest obecnie rzadko wykorzystywany, jednak niektóre systemy są nadal na niego podatne. Podawany poziom trudności jest oparty na statystycznych próbkach i może się zmieniać. Ogólnie lepiej jest używać angielskich określeń dla poszczególnych klas, takich jak „worthy challenge” (stanowiący wyzwanie) lub „trivial joke” (trywialny dowcip). Taki sposób raportowania jest dostępny tylko przy domyślnym formacie raportu przy włączonej opcji zwiększającej szczegółowość podawanych informacji (-v). Jeśli użyto opcji -v w połączeniu z -O, podane zostaną informacje o generowaniu numerów sekwencyjnych IPID. Większość adresów należy do klasy „incremental” (rosnące) co oznacza, że wartość pola ID w nagłówkach pakietów IP jest zmieniana rosnąco w kolejnych pakietach. Taki sposób powiększania numerów powoduje podatność na szereg ataków.

Dokument opisujący działanie i używanie detekcji wersji jest dostępny w wielu językach pod adresem http://www.insecure.org/nmap/osdetect/.

Wykrywanie systemu operacyjnego jest włączane i kontrolowane przez poniższe opcje:

-O (Włączenie wykrywania systemu operacyjnego)
Włącza wykrywanie systemu operacyjnego opisanego powyżej. Alternatywnie można używać opcji -A, która włącza jednocześnie wykrywanie systemu operacyjnego i wersji usług.

--osscan-limit (Limitowanie wykrywania do obiecujących celów)
Wykrywanie systemu operacyjnego jest dużo bardziej efektywne, jeśli wykryto przynajmniej po jednym otwartym i zamkniętym porcie TCP. Użycie tej opcji spowoduje, że Nmap nie będzie próbował określać systemu operacyjnego, jeśli nie zostały spełnione powyższe kryteria. Wykorzystanie tego ograniczenia pozwala na znaczne skrócenie czasu, zwłaszcza w połączeniu z opcją -P0 przy skanowaniu wielu adresów. Opcja ma znaczenie tylko w połączeniu z -O lub -A.

--osscan-guess; --fuzzy (Zgadywanie wersji systemu operacyjnego)
Jeśli Nmap nie może jednoznacznie dopasować systemu operacyjnego, czasami może sugerować kilka różnych, zbliżonych do siebie. Podobieństwo musi być bardzo duże, żeby Nmap zachował się w ten sposób przy domyślnej konfiguracji. Wykorzystanie tej opcji pozwala na większą swobodność przy próbach ustalenia wersji systemu.


### Zależności czasowe i wydajność
Zawsze najważniejszym priorytetem przy tworzeniu Nmapa była wysoka wydajność. Domyślne skanowanie (nmap <nazwahosta>) hosta w sieci lokalnej zajmuje tylko jedną piątą sekundy. Jest to zadowalający czas, jednak przy skanowaniu setek tysięcy adresów sumaryczny czas staje się bardzo duży. Dodatkowo niektóre typy skanowania, takie jak skanowanie UDP i detekcja wersji także wpływają negatywnie na czas wykonania, podobnie jak konfiguracja systemów zaporowych, na przykład limitująca ilość pakietów. Nmap posiada możliwości równoległego skanowania i odpowiednie zaawansowane algorytmy przyspieszające skanowanie, a użytkownik posiada ogromne możliwości wpływania na to jak są one wykorzystywane. Zaawansowani użytkownicy uważnie przeglądający komendy Nmapa, nakazują mu dostarczanie tylko istotnych informacji zgodnie z przyjętymi wymaganiami i założeniami czasowymi.

Techniki przyspieszające skanowanie dotyczą ograniczenia wykonywania mało istotnych testów i częstej zmiany wersji Nmapa na najnowszą (zmiany dotyczące przyszpieszenia pracy są wprowadzane dosyć często). Optymalizacja parametrów dotyczących szybkości skanowania również ma duży wpływ i została opisana poniżej.

--min-hostgroup <ilość_hostów>; --max-hostgroup <numhosts> (Zmiana ilości hostów w grupie)
Nmap posiada możliwość skanowania portów i wersji na wielu hostach równocześnie. Jest to realizowane poprzez dzielenie listy adresów docelowych na grupy, które są następnie kolejno skanowane. Ogólnie skanowanie większych grup jest bardziej efektywne. Wadą tego rozwiązania jest opóźnienie w podawaniu wyników testów do czasu przeskanowania całej grupy. Przykładowo, jeśli Nmap rozpoczął skanowanie w grupach po 50 adresów, żadne wyniki nie zostaną wyświetlone (poza informacjami podawanymi przez -v) do czasu zakończenia skanowania pierwszych 50 adresów.

Domyślnie Nmap stosuje rozwiązanie kompromisowe. Rozpoczyna z grupą o rozmiarze 5, co pozwala szybko wyświetlić pierwsze wyniki, a następnie stopniowo powiększa rozmiar grupy aż do maksymalnie 1024. Dokładne wykorzystywane rozmiary grup są uzależnione od podania dodatkowych opcji. Dla uzyskania większej efektywności Nmap używa większych grup dla skanowań UDP oraz przy skanowaniach TCP dotyczących zaledwie kilku portów.

Jeśli maksymalny rozmiar grupy został określony za pomocą opcji --max-hostgroup, Nmap nigdy nie przekroczy tego limitu. Analogicznie podanie minimalnego rozmiaru za pomocą --min-hostgroup wymusi stosowanie grup o przynajmniej takim rozmiarze. Nmap może użyć mniejszej grupy tylko w przypadku, kiedy ilość adresów do przeskanowania jest mniejsza niż założone minimum. Obie wymienione opcje pozwalają na utrzymywanie rozmiaru grupy w podanym przedziale, jednak jest to rzadko potrzebne.

Podstawowym zastosowaniem tych opcji jest podawanie dużego minimalnego rozmiaru grupy tak, żeby pełne skanowanie odbywało się szybciej. Często stosowaną wartością jest 256, co pozwala na skanowanie w kawałkach o rozmiarze klasy C. Przy skanowaniu wielu portów, stosowanie większych wartości minimalnych przeważnie nie poprawi wydajności. W przypadku skanowania małych ilości portów pomocne może być stosowanie grup o rozmiarze 2048 lub nawet większym.

--min-parallelism <ilość_prób>; --max-parallelism <ilość_prób> (Kontrola współbierzności testów)
Opcja ta kontroluje ilość jednoczesnych dla danej grupy adresów testów i jest wykorzystywana podczas wykrywania hostów i skanowania portów. Domyślnie Nmap dobiera idealną ilość testów w zależności od parametrów sieci. Jeśli jakiś pakiet zostanie zagubiony, zwalnia i zaczyna wykonywać mniejszą ilość testów równolegle. Nmap próbuje powoli przyspieszać, jeśli nie są gubione pakiety. Podane opcje pozwalają na określenie minimalnego i maksymalnego limitu ilości jednocześnie wykonywanych testów. Normalnie ilość ta może spaść do 1 przy złych warunkach sieciowych lub wzrosnąć do kilkuset w idealnych warunkach.

Najczęściej wykorzystywana jest opcja --min-parallelism do ustawiania wyższej niż 1 wartości przy skanowaniu sieci przy złych warunkach. Zmiana tej opcji może być ryzykowna, ponieważ ustawienie zbyt wysokiej wartości może sie odbić na poprawności testów. Wykorzystanie jej także pociąga za sobą zmniejszenie możliwości Nmapa w zakresie dynamicznego dostosowywania się do warunków panujących w sieci. Ustalenie minimalnej ilości na 10 może być sensowne, jednak powinno być stosowane w ostateczności.

Opcja --max-parallelism jest czasami wykorzystywana do zmuszenia Nmapa do nie przeprowadzania więcej niż jednego testu równolegle, co może być użyteczne w połączeniu z opcją--scan-delay (opisaną dalej).

--min-rtt-timeout <czas>, --max-rtt-timeout <czas>, --initial-rtt-timeout <czas> (Kontrola czasu oczekiwania na wykonanie testu)
Nmap posiada mechanizm kontrolujący czas oczekiwania na wynik testu, zanim nie zostanie on ponowiony. Czas oczekiwania jest zależny od czasu wykonania poprzednich testów. Jeśli opóźnienia w sieci okażą sie duże i zmienne, czas oczekiwania może zwiększyć sie do kilku sekund. Początkowa wartość jest dosyć konserwatywna (wysoka) i może taka pozostać w przypadku skanowania nie odpowiadających hostów.

Opcje przyjmują wartości w milisekundach, ale można dodać litery s, m lub h odnoszące się odpowiednio do sekund, minut i godzin. Podanie niższych wartości --max-rtt-timeout i --initial-rtt-timeout niż domyślne, może znacząco skrócić czas skanowania. Jest to głównie widoczne w przypadku skanowania bez wykorzystywania pinga (-P0) oraz przy skanowaniu dobrze filtrowanych sieci. Nie można również przesadzać w drugą stronę, ustawienie zbyt małego czasu może przekładać sie na dłuższy czas skanowania przez niepotrzebne retransmisje spowodowane upływem czasu oczekiwania na odpowiedź.

Jeśli wszystkie skanowane hosty są w sieci lokalnej, sensownym agresywnym ustawieniem opcje --max-rtt-timeout jest 100 milisekund. Jeśli skanowany ma być inny segment, warto sprawdzić czasy odpowiedzi dla protokołu ICMP - za pomocą narzędzia ping lub innego pozwalającego na definiowanie pakietów mogących omijać system zaporowy, takiego jak hping2. Interesującą nas wielkością jest maksymalny czas odpowiedzi dla 10 lub więcej pakietów. Uzyskany czas może zostać po podwojeniu wykorzystany jako wartość dla --initial-rtt-timeout, a po pomnożeniu przez trzy lub cztery dla --max-rtt-timeout. Nie jest zalecane ustawianie maksymalnego rtt poniżej 100ms, niezależnie od czasów pingowania, podobnie większego niż 1000ms.

--min-rtt-timeout jest rzadko wykorzystywaną funkcją, która może być przydatna jeśli komunikacja sieciowa jest tak niepewna, że nawet domyślne ustawienia Nmapa są zbyt agresywne. Jako że Nmap redukuje czas oczekiwania tylko do momentu w którym sieć zacznie działać poprawnie, potrzeba dodatkowego wydłużania czasu oczekiwania nie jest normalna i powinna zostać zaraportowana jako błąd na liście dyskusyjnej nmap-dev.

--max-retries <ilość> (Maksymalna ilość prób ponawiania skanowania portów)
Kiedy Nmap nie otrzyma odpowiedzi na skanowanie portu, może to oznaczać, że port ten jest filtrowany. Możliwe jest jednak także, że pakiet testu lub odpowiedzi po prostu zaginął w sieci, albo że host limituje ilość możliwych odpowiedzi w jednostce czasu i właśnie tymczasowo je zablokował. Większą pewność uzyskuje się dzieki powtarzaniu testu w przedstawionych przypadkach. Jeśli Nmap wykryje problemy z komunikacją sieciową, może ponawiać próbę badania portu wiele razy, zanim sie podda. Z jednej strony zwiększa to dokładność testów, z drugiej wydłuża czas ich wykonania. Jeśli wydajność jest krytycznym aspektem, skanowania mogą zostać przyspieszone poprzez limitowanie dozwolonej ilości retransmisji. Ustawienie opcji --max-retries 0 , całkowicie wyłączającej powtarzanie testów jest wykorzystywane sporadycznie.

Domyślnie (bez stosowania opcji -T) dozwolone jest maksymalnie 10 powtórzeń. Jeśli sieć działa prawidłowo i skanowane hosty nie limitują ilości pakietów, Nmap zwykle wykorzystuje jedną retransmisję. Dlatego też większość skanowań nie zostanie dotkniętych zmianą wartości --max-retries na trzy. Stosowanie tak niskich wartości pozwala na znaczne przyspieszenie skanowania hostów limitujących ilość odpowiedzi. Jeśli Nmap będzie zbyt szybko poddawał się przy skanowaniu portów, część informacji nie zostanie zebrana, dlatego być może warto skorzystać z opcji przerywającej test --host-timeout, która dotyczy całego hosta, a nie tylko pojedynczych testów.

--host-timeout <czas> (Pomijaj powolne hosty)
Skanowanie niektórych hostów trwa bardzo długo. Może to być spowodowane niezbyt wydajnym sprzętem sieciowym lub oprogramowaniem, limitowaniem ilości pakietów czy restrykcjami systemu zaporowego. Niewielki procent hostów może zabrać większość czasu przeznaczonego na skanowanie. Czasami najlepszym rozwiązaniem jest ich pominięcie z wykorzystaniem opcji --host-timeout z parametrem oznaczającym ilość milisekund, jakie jesteśmy w stanie poświęcić na czekanie per host. Parametr można również podawać w sekundach, minutach lub godzinach dodając odpowiednio litery s, m lub h. Często dodaję 30m żeby mieć pewność, że Nmap nie będzie skanował jednego hosta dłużej niż pół godziny. Trzeba pamiętać, że Nmap może równolegle w tym czasie skanować inne hosty, więc nie bedzie to czas kompletnie stracony. Host który przekroczy czas jest pomijany i nie są dla niego wyświetlane wyniki takie jak lista portów, system operacyjny czy wersje usług.

--scan-delay <czas>; --max-scan-delay <czas> (Ustaw opóźnienie pomiędzy testami)
Opcja pozwala na narzucenie czasu w milisekundach jaki musi minąć pomiędzy kolejnymi testami dla badanego hosta. Podobnie jak przy innych opcjach pozwalających na określanie czasu, można dodać s, m lub h do parametru do określenia go odpowiednio w sekundach, minutach lub godzinach. Opcja ta jest szczególnie użyteczna w przypadku systemów limitujących ilość pakietów. Solaris zwykle odpowiada na skanowanie UDP poprzez wysyłanie tylko jednego pakietu ICMP na sekundę, więc wysyłanie zapytań szybciej jest zupełnie nie potrzebne. Wykorzystanie opcji --scan-delay 1s pozwala na wymuszenie odpowiedniej prędkości skanowania. Normalnie Nmap stara się wykryć jaka powinna być optymalna prędkość skanowania dla każdego hosta, jednak ręczne dodanie takiej opcji nie zaszkodzi, o ile znana jest optymalna prędkość.

Kiedy Nmap zwiększa czas opóźnienia, dostosowując go do limitu ilości otrzymywanych odpowiedzi, czas skanowania dramatycznie rośnie. Opcja --max-scan-delay pozwala na ustawienie maksymalnego limitu do którego może być automatycznie zwiększane opóźnienie. Ustawienie tej wartości zbyt nisko może spowodować niepotrzebne retransmisje i pominięcie niektórych portów w przypadku hostów ściśle limitujących ilość pakietów.

Inną możliwością wykorzystanie opcji --scan-delay jest omijanie systemów detekcji intruzów (IDS/IPS).

-T <Paranoid|Sneaky|Polite|Normal|Aggressive|Insane> (Ustawnienie szablonu zależności czasowych skanowania)
Opisane wcześniej opcje do zmiany zależności czasowych pozwalają na efektywne i precyzyjne sterowanie skanowaniem, jednak wiele osób uzna je za niepotrzebnie skomplikowane. Dodatkowo w wielu przypadkach dobranie odpowiedniej kombinacji parametrów może zająć więcej czasu, niż samo skanowanie. Z tego powodu Nmap oferuje prostrze rozwiązanie w postaci sześciu szablonów. Ich wybór jest możliwy poprzez wykorzystanie opcji -T z parametrem oznaczającym numer lub nazwę szablonu. Dostępne szablony to paranoid (0, paranoidalny), sneaky (1, podstępny), polite (2, grzeczny), normal (3, normalny), aggressive (4, agresywny) i insane (5, szalony). Pierwsze dwa wykorzystywane są do omijania systemów IDS. Szablon polite spowalnia skanowanie powodując mniejsze obciążenie łącza i zmniejszające wykorzystanie zasobów w badanym systemie. Domyślnie używany jest normal, więc podawanie -T3 nic nie zmieni. Szablon agresywny przyspiesza skanowanie przy założeniu że korzystamy z szybkiej i nie przeciążonej sieci. Insane zakłada wykorzystanie ponad przeciętnie szybkiej sieci lub jeśli chcemy uzyskać dużą szybkość kosztem możliwej utraty dokładności.

Szablony pozwalają poinformować Nmapa jak dużej agresywności od niego oczekujemy przy jednoczesnym pozwoleniu mu na automatyczne dobieranie pozostałych parametrów czasowych. Wprowadzane też są inne drobne modyfikacje, do których nie istnieją odzielne opcje. Na przykład, -T4 zabrania wzrostu dynamicznego opóźnienia skanowania powyżej 10ms dla portów TCP, a w przypadku -T5 powyżej 5ms. Szablony mogą być używane w połączeniu z innymi opcjami do ustawiania zależności czasowych o ile zostaną umieszczone przed pozostałymi opcjami w linii poleceń (inaczej domyślne ustawienia z szablonu zastąpią ustawione innymi opcjami). Większość dzisiejszych sieci może być z powodzeniem skanowana z wykorzystaniem opcji -T4.

Jeśli używasz łącza szerokopasmowego lub sieci ethernet, rekomendowane jest stałe używanie szablonu -T4. Wiele osób lubi -T5, lecz jest ono jak dla mnie trochę za agresywne. Ludzie czasami używają -T2 ponieważ myślą, że zminiejszają szanse na zawieszenie serwera lub uważają się za bardziej kulturalnych z założenia, często nie zdając sobie sprawy z tego, jak wolne jest -T Polite - ich skanowania może trwać dziesięć razy dłużej. Zawieszanie hostów i problemy z pasmem są rzadko spotykane przy domyślym -T3, i ta opcja jest polecana dla ostrożnych skanujących. Nie włączanie detekcji wersji jest daleko bardziej efektywnym sposobem na unikanie problemów.

Podczas gdy opcje -T0 i -T1 mogą być użyteczne przy unikaniu wykrycia przez systemy IDS, są niesamowicie powolne przy skanowaniu setek adresów lub portów. Przy tak długich skanowaniach możesz raczej chcieć ustawić ręcznie poszczególne zależności czasowe, niż polegać na predefiniowanych wartościach z -T0 i -T1.

Głównym efektem działania T0 jest ograniczenie ilości równolegle przeprowadzanych testów do jednego i wprowadzenie odstępu pomiędzy kolejnymi testami o długości 5 minut. Opcje T1 i T2 są podobne, ale czakają już tylko odpowiednio 15 i 0.4 sekundy pomiędzy testami. T3 jest domyślnym ustawieniem Nmapa włączając w to zrównoleglanie testów. T4 jest odpowiednikiem podania opcji --max-rtt-timeout 1250 --initial-rtt-timeout 500 --max-retries 6 i ustawienia maksymalnego opóźnienia przy skanowaniu TCP na 10 milisekund. Opcja T5 jest alternatywą dla --max-rtt-timeout 300 --min-rtt-timeout 50 --initial-rtt-timeout 250 --max-retries 2 --host-timeout 900000 oraz ustawienia maksymalnego czasu opóźnienia dla skanowania TCP na 5ms.


### Firewall/IDS i podszywanie się
Wielu pionierów ineternetu wykorzystywało globalną otwartą sieć opartą o uniwersalną przestrzeń adresową pozwalającą na tworzenie wirtualnych połączeń pomiędzy dwoma dowolnymi węzłami. Pozwalało to hostom na równoprawną komunikację przy której każdy mógł serwować i pobierać dane od drugiego. Ludzie mogli uzyskać dostęp do wszystkich swoich systemów z dowolnego miejsca w sieci. Wizja nieograniczonej łączności została ograniczona przez wyczerpujące się zapasy wolnych adresów IP i względy bezpieczeństwa. We wczesnych latach 90-tych organizacje zaczęły masowo wprowadzać systemy zaporowe dla ograniczenia możliwości komunikacji. Duże sieci zostały otoczone kordonem zabezpieczeń w postaci proxy aplikacyjnych, translacji adresów i filtrowania pakietów. Niczym nie ograniczany przepływ informacji ustąpił ścisłym regulacjom dotyczącym dozwolonych dróg komunikacji i treści nimi przesyłanych.

Zabezpieczenia sieciowe takie jak systemy zaporowe mogą bardzo utrudnić uzyskiwanie informacji o sieci i jej architekturze. Nmap posiada wiele funkcji pozwalających zrozumieć działanie złożonych sieci i na weryfikacje działania filtrów pakietów i ich zgodności z założeniami. Pozwala nawet na omijanie źle zaimplementowanych zabezpieczeń. Jednym z najlepszych sposobów na poznanie bezpieczeństwa swojej sieci jest próba jego przełamania. Zacznij myśleć jak atakujący, który stosuje techniki z tej części dokumentacji przeciwko Twojej sieci. Uruchom skanowania FTP bounce, Idle, dodaj fragmentację pakietów lub spróbuj uruchomić tunel omijający lokalne proxy.

W połączeniu z ograniczeniami aktywności sieciowej, firmy coraz częściej rozpoczynają monitorowanie ruchu sieciowego za pomocą systemów detekcji intruzów (IDS). Wszystkie popularne systemy IDS mają dołączone reguły wykrywające skanowania Nmapa, ponieważ skanowania takie czasami poprzedzają ataki. Wiele z tych systemów ostatnio przeistoczyło się w systemy prewencji (IPS), które aktywnie przeciwstawiają się niepożądanemu ruchowi. Niestety, dla administratorów sieci i producentów systemów IDS, wiarygodne wykrywanie złych intencji poprzez analizę pakietów jest ciężkim orzechem do zgryzienia. Cierpliwi atakujący, posiadający odpowiednie umiejętności podparte możliwościami Nmapa zwykle mogą ominąć systemy detekcji intruzów i ich działania nie zostaną wykryte. W tym samym czasie administratorzy muszą się zmagać z ogromną ilością fałszywych alarmów dotyczących niepoprawnie zaklasyfikowanej zupełnie niewinnej komunikacji.

Co jakiś czas ktoś sugeruje, że Nmap nie powinien oferować możliwości omijania systemów zaporowych czy systemów IDS. Argumentują to możliwością wykorzystania tych funkcji także przez atakujących, a nie tylko przez administratorów podnoszących bezpieczeństwo swoich sieci. Problemem jest sama logika, ponieważ atakujący i tak będą wykorzystywali tego typu metody używając innych narzędzi lub samemu wprowadzając odpowiednią funkcjonalność do kodu Nmapa. Równocześnie administratorzy będą mieli utrudniony dostęp do odpowiednich narzędzi i ich praca będzie trudniejsza. Uruchomienie nowoczesnego, bezpiecznego serwera FTP jest dużo skuteczniejszą metodą ochrony niż ograniczanie dostępności do narzędzi pozwalających na przeprowadzanie ataków FTP bounce.

Nie ma magicznej kuli (lub opcji Nmapa) do przełamywania i obchodzenia systemów zaporowych i IDS. Wymaga to umiejętności i doświadczenia. Dokładne instrukcje wykraczają poza zakres tej dokumentacji, która jest jedynie listą dostępnych opcji wraz z opisami jak one działają.

-f (fragmentacja pakietów); --mtu (Używanie wybranego MTU)
Opcja -f powoduje wykorzystywanie przy skanowaniu (włączając w to skanowanie ping) małych pofragmentowanych pakietów. Idea polega na podzieleniu nagłówka TCP na wiele pakietów, co powoduje utrudnienia w ich przetwarzaniu przez filtry pakietów, systemy detekcji intruzów oraz irytujące komplikacje przy ustalaniu co się dzieje. Ale uwaga! Wiele programów ma problemy przy obsłudze tego typu pakietów. Przestarzały sniffer Sniffit wykonuje nieprawidłową operacje i zostaje zamknięty zaraz po odebraniu już pierwszego z takich pakietów. Dodanie tej opcji spowoduje automatyczne dzielenie wszystkich pakietów wysyłanych przez Nmapa na mniejsze o rozmiarze maksymalnie 8 bajtów. Przykładowo 20 bajtowy nagłówek TCP zostanie podzielony na 3 pakiety: najpierw dwa po 8 bajtów i ostatni 4 bajty. Oczywiście każdy fragment dostaje własny nagłówek IP. Dodanie drugiej opcji -f powiększa wykorzystywany rozmiar fragmentów z 8 do 16 (redukując ilość fragmentów). Możliwe jest również podanie własnego rozmiaru za pomocą opcji --mtu. Nie używaj parametru -f, jeśli używasz --mtu. Podawany rozmiar musi być wielokrotnością 8. W niektórych systemach filtry pakietów nie otrzymują bezpośrednio pakietów, tylko są one wstępnie kolejkowane, tak jak w Linuxie przy ustawieniu opcji CONFIG_IP_ALWAYS_DEFRAG w kernelu, jednak w wielu przypadkach takie opcje nie są włączane ze względów wydajnościowych. Opcja taka nie jest również włączana jeśli zachodzi możliwość routowania poszczególnych pakietów różnymi ścieżkami. Niektóre systemy operacyjne potrafią defragmentować pakiety wysyłane przez kernel, Linux z iptables i modułem śledzenia połączeń jest jednym z przykładów. Uruchamiając skanowanie można podsłuchać za pomocą sniffera takiego jak Ethereal, czy wychodzące pakiety są rzeczywiście pofragmentowane. Jeśli system powoduje tego typu problemy, można wypróbować opcje --send-eth, która pomija stos TCP/IP i wysyła bezpośrenio ramki ethernetowe.

-D <decoy1 [,decoy2][,ME],...> (Ukrywaj skanowanie za pomocą innych hostów)
Powoduje skanowanie, wykrywane jako przychodzące z kilku miejsc równocześnie. System IDS może wykryć 5-10 różnych skanowań z różnych adresów, jednak nie będzie w stanie ocenić który z nich jest prawdziwym źródłem pochodzenia, a które tylko niewinnymi zasłonami. Chociaż metoda ta może zostać rozpoznana poprzez śledzenie ścieżki pakietów na routerach i innych aktywnych mechanizmów, ogólnie jest efektywną techniką na ukrywanie swojego adresu IP.

Podwając listę poszczególnych hostów-zasłon, trzeba je oddzielić przecinkami, można również na tej liście umieścic ME oznaczające pozycję własnego adresu IP na liście. W przypadku wykorzystania przynajmniej 6-tej pozycji na liście dla własnego IP, wiele popularnych systemów wykrywających skanowania (na przykład scanlogd firmy Solar Designer) nawet nie pokaże prawdziwego źródła pochodzenia pakietów na liście ataków. Jeśli ME nie zostanie dodane, Nmap umieści je losowo na liście.

Należy zwrócić uwagę, ze hosty-przykrywki powinny być dostępne, inaczej będzie można łatwo wykryć host skanujący i że można niechcący dokonać ataku SYN flood na hosty skanowane. Bezpieczniej jest używać adresów IP zamiast nazw systemów-przykrywek, bo nie zostawi to informacji w logach ich serwera nazw.

Przykrywki są używane zarówno przy początkowym skanowaniu ping (z wykorzystaniem ICMP, SYN ACK itp), podczas skanowania portów jak i przy wykrywaniu systemu operacyjnego. Technika ta nie działa podczas wykrywania wersji i skanowania metodą connect().

Używanie zbyt wielu adresów hostów-przykrywek znacznie spowalnia skanowanie i może nawet spowodować zmniejszenie dokładności. Dodatkowo niektórzy dostawcy usług odfiltrowują pakiety podszywające się pod adresy z innych sieci, jednak wielu nie robi tego wcale.

-S <adres_ip> (Ustawienie adresu nadawcy)
W niektórych przypadkach Nmap nie potrafi ustalić właściwego adresu nadawcy (i wyświetli stosowny komunikat). W takim przypadku należy za pomocą opcji -S podać adres lokalnego interfejsu przez który mają być wysyłane pakiety.

Inną możliwością tej opcji jest podmiana adresu nadawcy tak, by cel skanowania uważał, że skanuje go ktoś inny. Wyobraź sobie, ze firmę nagle zacznie skanować konkurencja! W przypadku takiego użycia, zwykle będzie wymagana opcja -e, a zalecana również -P0.

-e <interfejs> (Użyj wybranego interfejsu)
Informuje Nmapa przez który interfejs ma wysyłać i odbierać pakiety. Nmap powinien wykryć go automatycznie, ale jeśli mu się nie uda, można to zrobić ręcznie.

--source-port <numerportu>; -g <numerportu> (Używaj podanego portu źródłowego)
Jednym z najczęściej spotykanych problemów konfiguracyjnych jest ufanie danym przychodzącym z określonego portu źródłowego. Łatwo jest zrozumieć, czemu tak się dzieje. Administrator instaluje nowiusieńki system zaporowy, którego jedyną wadą są zgłoszenia od niepocieszonych użytkowników, którym nagle przestały działać aplikacje. Przykładem może być DNS, ponieważ odpowiedzi na zapytania z zewnętrznych serwerów przestały dochodzić do sieci. Innym przykładem jest FTP, przy stosowaniu aktywnych połączeń zewnętrzne serwery próbują utworzyć połączenia powrotne do klienta żądającego przesłania pliku.

Bezpieczne rozwiązanie dla tych problemów istnieje, często w formie aplikacyjnych serwerów proxy lub analizy protokołu przez systemy zaporowe. Niestety istnieją również inne łatwiejsze, ale i mniej bezpieczne rozwiązania. Wielu administratorów wpada w pułapkę zakładając, że dane przychodzące z portu 53 są zawsze odpowiedziami serwera DNS, a z 20 aktywnymi połączeniami FTP i zezwalając na przechodzenie takiego ruchu przez system zaporowy. Często zakładają, że żaden atakujący nie spróbuje wykorzystać takiej luki. Zdaża się również, że problem taki zostaje wprowadzony do konfiguracji jako tymczasowe rozwiązanie, jednak zapominają o jego zmianie na bardziej bezpieczne.

Przepracowani administratorzy nie są jedynymi, którzy wpadają w taką pułapkę. Wiele komercyjnych produktów jest dostarczanych z podobnymi problemami. Zdarzyło się to nawet firmie Microsoft, której filtry IPsec dostarczone z Windows 2000 i XP zawierają regułę wpuszczającą cały ruch TCP i UDP pochodzący z portu 88 (Kerberos). Innym dobrze znanym przykładem jest Zone Alarm personal firewall, który do wersji 2.1.25 włącznie nie filtrował pakietów UDP z portów 53 (DNS) i 67 (DHCP).

Nmap oferuje dwie ekwiwalentne opcje -g i --source-port pozwalające na wykorzystanie opisanej wyżej funkcjonalności poprzez podanie numeru portu z którego wysyła dane, o ile jest to tylko możliwe. Nmap musi używać różnych numerów portów dla poprawnego działania niektórych testów wykrywających system operacyjny, zapytania DNS również ignorują opcję --source-port, ponieważ Nmap wykorzystuje do tego biblioteki systemowe. Większość typów skanowania TCP, włączając skanowanie SYN obsługuje tę opcję we wszystkich przypadkach, podobnie jak i UDP.

--data-length <rozmiar> (Dodawaj losowe dane do wysyłanych pakietów)
Domyślnie Nmap wysyła pakiety o minimalnej wielkości zawierające jedynie sam nagłówek. Pakiety TCP mają 40 bajtów, a ICMP tylko 28. Ta opcja pozwala dołączać do większości pakietów losowe dane o podanym rozmiarze. Pakiety używane do detekcji systemu operacyjnego (-O) pozostają nie zmienione, ale przy większości pakietów ping i skanowania portów opcja ta jest wykorzystywana. Powiększanie pakietów spowalnia proces skanowania, jednocześnie czyniąc go mniej podejrzanym.

--ttl <wartość> (Ustaw czas życia pakietu IP)
Ustawia czas życia (TTL) pakietów na podaną wartość.

--randomize-hosts (Losowanie kolejności skanowania hostów)
Opcja powoduje włączenie losowania kolejności hostów w każdej grupie do 8096 hostów przed ich skanowaniem. Zachowanie takie czyni skanowanie mniej oczywistym dla wielu systemów monitorujących sieci, zwłaszcza w połączeniu z opcją spowalniającą skanowanie. Możliwe jest losowanie z jeszcze większych grup, poprzez zmianę stałej PING_GROUP_SZ w pliku nmap.h i rekompilacji. Innym rozwiązaniem jest wygenerowanie listy adresów IP za pomocą opcji lista skanowania (-sL -n -oN <nazwapliku>) i losowemu pomieszaniu adresów na niej za pomocą skryptu Perla, oraz podaniu jej Nmapowi za pomocą opcji -iL.

--spoof-mac <adres mac, prefiks, lub nazwa producenta > (Podmieniaj adres MAC)
Podaje Nmapowi adres MAC z użyciem którego będą wysyłane wszystkie pakiety ethernet. Opcja włącza również automatycznie --send-eth dla uzyskania pewności wysyłania pakietów na poziomie ethernetu. Podany adres MAC może przyjmować wiele postaci. Jeśli zostanie podany znak „0”, Nmap wybierze kompletnie losowy adres MAC na czas trwania danej sesji. Podanie parzystej ilości cyfr heksadecymalnych (mogą być oddzielone dwukropkami), spowoduje wykorzystanie jej jako adresu MAC, przy czym jeśli podano mniej niż 12 cyfr szestnastkowych, Nmap wypełni pozostałość 6 bajtów losowymi wartościami. Jeśli podany ciąg nie jest 0 lub liczbą heksadecymalną, Nmap poszuka w pliku nmap-mac-prefixes nazwy producenta zawierającego podany ciąg (duże i małe litery nie są rozróżniane) i jeśli znajdzie, użyje identyfikatora producenta OUI (3 bajty) wypełniając pozostałe 3 bajty losowo. Przykłady poprawnych argumentów to Apple, 0, 01:02:03:04:05:06, deadbeefcafe, 0020F2, Cisco itp.

--badsum (Wysyłanie pakietów z nieprawidłową sumą kontrolną TCP/UDP)
Powoduje wstawianie do nagłówków wysyłanych pakietów nieprawidłowych sum kontrolnych. Jako że prawie każdy stos IP odrzuci tego typu pakiety, otrzymana odpowiedź najprawdopodobniej pochodzi od systemu zaporowego lub IDS, które nie przejmują się sumami kontrolnymi. Dokładniejszy opis tej techniki znajduje się pod adresem https://nmap.org/p60-12.txt


### Wyjście
Każde narzędzie jest tylko tak dobre, jak wyniki które się za jego pomocą uzyskuje. Złożone testy i algorytmy nie są nic warte, jeśli ich wyniki nie są zaprezentowane w odpowiedniej formie. Z związku z tym, że użytkownicy Nmapa używają go w różny sposób, także w połączeniu z innymi narzędziami, nie ma jednego formatu, który by wszystkich zadowolił. Dlatego też Nmap oferuje kilka formatów, włączając w to tryb interaktywny i tryb XML do lepszej integracji z innymi programami.

Dodatkowo poza różnymi formatami wyjściowymi, Nmap posiada opcje pozwalające na kontrolowanie poziomu szczegółowości dostarczanych informacji oraz komunikatów do śledzenia błędów. Wyniki mogą być przekazywane do standardowego wyjścia jak i do plików (w trybie zastępowania lub dołączania). Wygenerowane pliki mogą również być wykorzystywane do wznowienia przerwanych skanowań.

Nmap pozwala na uzyskanie pięciu różnych formatów raportów. Domyślny to format interaktywny i jest wykorzystywany w połączeniu ze standardowym wyjściem. Jest także format format normalny, podobny do interaktywnego, jednak wyświetla mniej rutynowych informacji i ostrzeżeń, ponieważ jest raczej przewidziany do poźniejszej	analizy, niż do interaktywnego oglądania w trakcie skanowania.

Tryb XML jest jednym z najważniejszych, jako że może zostać przekonwertowany na HTML lub bezporoblemowo przetworzony przez inne programy, takie jak graficzne interfejsy użytkownika lub zaimportowany do bazy danych.

Pozostałe dwa najmniej skomplikowane to format pozwalający na łatwe przetwarzanie za pomocą wyrażeń regularnych (grep), który zawiera większość informacji o hoście w jednej linii, oraz format sCRiPt KiDDi3 0utPUt.

Podczas gdy format interaktywny jest domyślny i nie posiada dodatkowych opcji, pozostałe cztery formaty używają tej samej składni w postaci jednego argumentu, będącego nazwą pliku do którego mają zostać zapisane wyniki. Możliwe jest podawanie wielu formatów jednocześnie, jednak każdy z nich może być podany tylko raz. Na przykład, jeśli chcesz zapisać format normalny do późniejszego przegladania i równocześnie XML do przetwarzania przez inne programy, używamy składni -oX myscan.xml -oN myscan.nmap. W przykładach z tej dokumentacji dla ułatwienia używamy prostych nazw, takich jak myscan.xml, jednak w codzinnym użyciu zalecane jest stosowanie nazw bardziej opisowych. Nazwy te mogą być dowolnie wybierane, zgodnie z własnymi preferencjami, osobiście preferuję długie nazwy zawierające datę skanowania i słowo lub dwa opisujące skanowanie, umieszczone w katalogu zawierającym nazwę firmy skanowaniej.

Podczas zapisywania wyników do pliku Nmap nadal wyświetla interaktywną formę raportu na standardowe wyjście. Przykładowo, komenda nmap -oX myscan.xml cel zapisuje wyniki w formacie XML do pliku myscan.xml równocześnie wyświetlając je w trybie interaktywnym tak, jakby opcja -oX nie była podana. Możliwa jest zmiana tego zachowania poprzez podanie znaku myślnika (-) zamiast nazwy pliku przy wybranym formacie, co spowoduje wyświetlanie go zamiast formy interaktywnej. Tak więc komenda nmap -oX - cel spowoduje wyświetlenie tylko formatu XML na standardowym wyjściu stdout. Komunikaty o poważnych błędach sa nadal wyświetlane za pomocą standardowego wyjścia błędów stderr.

Inaczej niż przy innych opcjach, spacja pomiędzy opcją (taką jak -oX), a nazwą pliku lub myślnika nie jest wymagana. Jeśli spacja zostanie pominięta przy opcjach takich jak -oG- lub -oXscan.xml, z powodów kompatybilności wstecznej Nmap zapisze wyniki w formacie normalnym w plikach odpowiednio G- i Xscan.xml.

Nmap posiada również opcje pozwalające na ustalenie poziomu szczegółowości podawanych informacji jak również pozwalające na dołączanie wyników do już istniejących plików. Opcje te zostały opisane poniżej.

Formaty wyjściowe Nmapa

-oN <nazwapliku> (Format normalny)
Powoduje zapis w formacie normalnym do wskazanego pliku. Jak napisano wyżej, format ten różni się nieco od formatu interaktywnego.

-oX <nazwapliku> (Format XML)
Powoduje zapis w formacie XML do wskazanego pliku. Nmap dołącza definicje formatu dokumentu (DTD), który pozwala innym programom na weryfikację zawartości tego pliku. Funkcja ta jest głównie przeznaczona do wykorzystania przez oprogramowanie dodatkowe, jednak może pomóc w ręcznej analizie zawartych danych. DTD opisuje jakie elementy XML mogą być legalnie uzywane w pliku i często podaje jakie wartości mogą przyjmować poszczególne znaczniki. Zawsze aktualna DTD wersja jest dostępna pod adresem http://www.insecure.org/nmap/data/nmap.dtd.

XML jest stabilnym formatem, który może być łatwo przetwarzany przez inne programy. Darmowe biblioteki do przetwarzania XML są dostępne dla większości języków programowania, takich jak C/C++, Perl, Python czy Java. Napisano nawet wiele procedur dostosowanych specjalnie do potrzeb Nmapa. Przykładami są Nmap::Scanner i Nmap::Parser dla Perla (CPAN). W wiekszości dużych aplikacji korzystających z Nmapa preferowany jest właśnie format XML.

W formacie XML jest również opisany styl XSL, który może zostać wykorzystany do konwersji do HTML. Najprostrzym sposobem jest po prostu wczytanie pliku XML do przeglądarki internetowej, takiej jak Firefox czy IE. Domyślnie zadziała to tylko na komputerze na którym był uruchamiany Nmap (lub skonfigurowanym podobnie), z powodu umieszczenia ścieżki do pliku nmap.xsl właściwej dla danego systemu. Za pomocą opcji --webxml lub --stylesheet można utworzyć przenośny raport XML, możliwy do obejrzenia w formacie HTML na każdym komputerze podłączonym do Internetu.

-oS <nazwapliku> (Format ScRipT KIdd|3)
Format script kiddie jest podobny do interaktywnego, jednak jest dodatkowo przetworzony na potrzeby l33t HaXXorZ, którzy nie byli zadowoleni z domyślnego, uporządkowanego formatu Nmapa. Osoby bez poczucia humoru powinny wiedzieć przed zarzucaniem mi „pomagania script kiddies ”, że opcja ta jest tylko żartem, a nie pomocą.

-oG <nazwapliku> (Format "grepowalny")
Ten format został opisany jako ostatni, jako że jest już przestarzały. Format XML jest dużo lepszy i jest prawie tak samo wygodny dla zaawansowanych użytkowników. XML jest standardem, do którego napisano dziesiątki bibliotek, podczas gdy format grepowalny jest moim osobistym wymysłem. XML pozwala również na łatwe rozszerzanie o nowe funkcje Nmapa w miarę ich dodawania, podczas gdy w formacie grepowalnym muszą one być pomijane z powodu braku miejsca.

Niezależnie od tego, format ten jest nadal całkiem popularny. Jest prostym formatem opisującym każdy host w oddzielnej linii i umożliwiający bardzo proste wyszukiwanie i przetwarzanie za pomocą standardowych narzędzi systemów UNIX takich jak grep, awk, cut, sed, diff i Perl. Format ten jest wygodny do szybkiego odnajdywania potrzebnych danych, na przykład hostów z otwartym portem SSH lub używających systemu Solaris i jest to możliwe za pomocą wycinania interesujących informacji za pomocą prostych poleceń awk czy cut.

Format grepowalny składa sie z linii komentarzy (rozpoczynających się od znaku #) i linii wyników. Linia wyników składa się z sześciu pól, oddzielonych znakami tabulacji i przecinkami. Polami tymi są Host, Ports, Protocols, Ignored State, OS, Seq Index, IPID i Status.

Najważniejszymi z tych pól są najczęściej pola Ports, które zawierają informacje o interesujących portach, w postaci listy oddzielonej przecinkami. Każda pozycja na liście reprezentuje jeden otwarty port i opisuje go siedmioma, oddzielonymi znakami (/) subpolami: Port number, State, Protocol, Owner, Service, SunRPC info i Version info.

Tak jak i w przypadku formaty XML, dokładny opis formatu grepowalnego przekracza zakres tej dokumentacji i jest dostępny pod adresem http://www.unspecific.com/nmap-oG-output.

-oA <nazwa> (Wyjście we wszystkich formatach)
Dla wygody można podać opcję -oA<nazwa> do zapisywania wyników w formacie normalnym, XML i grepowalnym równocześnie. Wyniki zostaną zapisane odpowiednio w plikach o nazwach <nazwa>.nmap, <nazwa>.xml i <nazwa>.gnmap. Tak jak i w przypadku innych programów, nazwa może zostać poprzedzona scieżką, na przykład ~/nmaplogs/foocorp/ w systemach UNIX lub c:\hacking\sco pod Windows.

Poziom szczegółowości i opcje diagnozowania błędów

-v (Podwyższenie poziomu raportowania)
Podwyższenie poziomu raportowania powoduje wyświetlanie przez Nmapa większej ilości informacji na temat postępów skanowania. Otwarte porty są pokazywane zaraz po ich wykryciu, podawany jest także przewidywany czas zakończenia skanowania w przypadku kiedy Nmap zakłada, że test potrwa dłużej niż kilka minut. Dwukrotne użycie tej opcji powoduje dalsze powiększenie poziomu szczegółowości, trzykrotne i dalsze nie dają już żadnego efektu.

Większość zmian dotyczy trybu interaktywnego, niektóre odnoszą się także do trybu normalnego i script kiddie. Pozostałe formaty są przystosowane do przetwarzania przez maszyny, więc Nmap może zawsze podawać szczegółowe informacje bez zmniejszania czytelności dla człowieka. Są jednak i drobne różnice w innych formatach, na przykład w formacie grepowalnym linia komentarza zawierająca listę skanowanych hostów jest dodawana tylko w trybie podwyższonej szczegółowości, ze względu na swoją dosyć znaczną długość.

-d [poziom] (Ustawianie poziomu śledzenia błędów)
Jeśli dostępne poziomy szczegółowości nie dostarczają wystarczającej ilości informacji, opcje śledzenia błędów mogą Cię wrecz nimi zasypać! Podobnie jak w przypadku wykorzystania opcji podwyższania szczegółowości (-v), opcja włączająca umowanie nazwane śledzenie błędów, włączana jest za pomocą parametru (-d) i możliwe jest jej wielokrotne dodawanie powiększające skutek. Alternatywnie można podać poziom jako argument do opcji -d. Na przykład -d9 ustawia poziom na dziewięć. Jest to najwyższy możliwy poziom produkujący setki linii, o ile nie jest to proste skanowanie kilku portów i hostów.

Format ten jest użyteczny jeśli podejrzewamy istnienie błędu w Nmapie lub jeśli po prostu chcemy wiedzieć co Nmap robi i czemu. Jako że opcja ta jest przeznaczona głównie dla autorów, wyświetlane linie nie zawsze są do końca zrozumiałe. Można otrzymać na przykład coś w stylu: Timeout vals: srtt: -1 rttvar: -1 to: 1000000 delta 14987 ==> srtt: 14987 rttvar: 14987 to: 100000. Jeśli nie rozumiesz takiego zapisu, możesz go po prostu zignorować, poszukać w kodzie źródłowym lub poprosić o pomoc na liście dyskusyjnej twórców Nmapa (nmap-dev). Niektóre linie są dosyć czytelne, ale stają się coraz bardziej skomplikowane wraz ze wzrostem poziomu śledzenia błędów.

--packet-trace (Śledzenie wysyłanych i odbieranych pakietów)
Powoduje wyświetlanie przez Nmapa krótkiej informacji na temat każdego wysyłanego i odbieranego pakietu. Opcja ta jest często używana podczas śledzenia błędów, ale zawiera również wartościowe informacje dla nowych użytkowników, pozwalające zrozumieć co Nmap robi. Uniknięcie wyświetlania tysięcy linii możliwe jest poprzez ograniczenie ilości portów do skanowania, na przykład za pomocą -p20-30. Jeśli chcesz zobaczyć tylko to, co dzieje się w trakcie wykrywania wersji, użyj raczej opcji --version-trace.

--iflist (Pokazuj interfejsy i tablicę routingu)
Wyświetla listę interfejsów i tablice routingu wykryte przez Nmapa. Opcja jest przydatna przy śledzeniu błędów w routingu lub niepoprawnym wykrywaniu typów interfejsów (na przykład jeśli Nmap traktuje połączenie PPP jako ethernet).

Pozostałe opcje

--append-output (Dołączaj wyniki do pliku)
Jeśli zostanie podana nazwa pliku jako argument do opcji takiej jak -oX czy -oN, domyślnie poprzednia zawartość pliku zostanie usunęta i zastąpiona nową. Jeśli zachodzi potrzeba zachowania poprzedniej zawartości pliku i dołączenie nowych wyników, należy dodać opcję --append-output. Potraktowane tak zostaną wszystkie podane pliki. Opcja nie działa zbyt dobrze z formatem XML, jako że wynikowy plik nie może być pożniej bezbłędnie przetworzony bez ręcznych poprawek.

--resume <nazwapliku> (Wznowienie przerwanego skanowania)
Niektóre skanowania Nmapa mogą trwać bardzo długo, nawet kilka dni. Problem pojawia się wtedy, kiedy nie jest możliwe ciągłe prowadzenie skanowania, na przykład z powodu potrzeby działania tylko w godzinach pracy, problemów z dostępnością sieci, (nie)przypadkowym restartem komputera na którym działa Nmap lub wykonaniem przez niego nieprawidłowej operacji. Użytkownik może również przerwać w każdej chwili skanowanie za pomocą kombinacji ctrl-C. W takich przypadkach ponowne rozpoczynanie testów od początku może nie być pożądane. Na szczęście, jeśli pozostały wyniki przerwanych testów w formacie normalnym (-oN) lub grepowalnym (-oG), możliwe jest ich wznowienie od momentu przerwania. Służy do tego opcja --resume dla której argumentem musi byc nazwa pliku w formacie normalnym lub grepowalnym. W tym przypadku nie jest możliwe podawanie żadnych innych opcji, jako że Nmap przetworzy podany plik i odtworzy wcześniej podane opcje. Po prostu uruchom nmap --resume <nazwapliku>, a Nmap dołączy do wskazanego pliku nowe wyniki. Opcja ta nie obsługuje formatu XML, jako że łączenie dwóch oddzielnych wynikóę skanowań w jeden plik jest dosyć trudne.

--stylesheet <ścieżka lub URL> (Styl XSL do transformacji formatu XML)
Nmap posiada domyślny styl XSL do przeglądania lub konwersji do formatu XML w pliku nmap.xsl. Plik wyjściowy XML zawiera dyrektywę xml-stylesheet wskazującą na nmap.xml, ze ścieżką do domyślej lokalizacji tego pliku (lub bierzącego katalogu pod Windows). Dzięki temu wystarczy po prostu załadować plik XML Nmapa do przeglądarki, która sama odczyta sobie plik nmap.xsl i użyje go do prawidłowego wyświetlenia wyników. Możliwe jest również użycie innego stylu poprzez podanie nazwy pliku jako argumentu dla opcji --stylesheet. W tym przypadku konieczne jest podanie pełnej ścieżki lub adresu URL. Typowe wywołanie ma postać --stylesheet http://www.insecure.org/nmap/data/nmap.xsl. Dyrektywa ta nakazuje pobranie najnowszej wersji pliku ze stylem ze strony Insecure.Org. Opcja --webxml robi dokładnie to samo, będąc łatwiejszą do wpisania i zapamiętania. Używanie pliku XSL ze strony Insecure.Org ułatwia przeglądanie wyników na systemie nie posiadającym zainstalowanego Nmapa (czyli nie posiadającym pliku nmap.xsl). Podawanie adresu URL jest wygodniejsze, jednak domyślnie używany jest plik lokalny ze względu za zachowanie poufności użytkownika.

--webxml (Użyj stylu ze strony Insecure.Org)
Opcja jest wygodniejszym zapisem analogicznego --stylesheet http://www.insecure.org/nmap/data/nmap.xsl.

--no-stylesheet (Nie używaj deklaracji stylu XSL w formacie XML)
Dodanie tej opcji powoduje wyłączenie dołączania stylu XSL do pliku z wynikami w formacie XML. Zostaje pominięta dyrektywa xml-stylesheet.


### Różne opcje
Sekcja ta opisuje istotne (i nie istotne) opcje, które nie pasowały gdzie indziej.

-6 (Włączenie skanowania IPv6)
Od roku 2002 Nmap obsługuje IPv6, w zakresie jego najpopularniejszych funkcji. W szczególności dostępne jest skanowanie ping (tylko TCP), connect() i wykrywanie wersji. Składnia opcji jest taka sama jak zwykle, wystarczy tylko dodać opcję -6. Oczywiście w przypadku podawania adresów zamiast nazw, niezbędne jest podawanie ich zgodnie ze składnią IPv6. Jako że adres może wyglądać podobnie do 3ffe:7501:4819:2000:210:f3ff:fe03:14d0, zalecane jest używanie nazw hostów. Wyniki poza samym adresem wyglądają tak samo jak i przy innych opcjach.

Adresacja IPv6 nie zawładnęła jeszcze światem, jednak jest często wykorzystywana w niektórych krajach (zwykle azjatyckich) i większość obecnych systemów ją obsługuje. Oczywiście do używania IPv6 musi być on prawidłowo skonfigurowany i dostępny zarówno na hoście skanowanym, jak i skanującym. Jeśli dostawca usług nie umożliwia uzyskania adresów IP (najczęściej tak właśnie jest), jest dużo dostawców darmowych tuneli, które działają poprawnie z Nmapem. Jednymi z lepszych są dostarczane przez BT Exact i Hurricane Electric na http://ipv6tb.he.net/. Tunele 6to4 są innym popularnym i darmowym rozwiązaniem.

-A (Agresywne opcje skanowania)
Włącza dodatkowe zaawansowane i agresywne opcje skanowania. Aktualnie są nimi wykrywanie systemu operacyjnego (-O) i wykrywanie wersji (-sV). Więcej opcji być może zostanie dodane w przyszłości. Głównym celem jest proste włączenie najbardziej popularnych opcji skanowania bez konieczności zapamiętywania wielu parametrów. Włączane są tylko opcje włączające określoną funkcjonalność, nie zaś te dotyczące zależności czasowych (takie jak -T4) czy poziomu szczegółowości (-v), które można dodać niezależnie.

--datadir <nazwakatalogu> (Określenie lokalizacji plików z danymi)
Podczas pracy Nmap pobiera dodatkowe informacje z plików nmap-service-probes, nmap-services, nmap-protocols, nmap-rpc, nmap-mac-prefixes i nmap-os-fingerprints. Nmap rozpoczyna poszukiwania tych plików od katalogu podanego jako parametr dla opcji --datadir, jeśli została dodana. Jeśli nie znajdzie plików w podanej lokalizacji, poszukuje ich w katalogu określonych w zmiennej środowiskowej NMAPDIR, a następnie w katalogu ~/.nmap dla rzeczywistego i efektywnego UID (tylko systemy POSIX) i katalogu z programem Nmap (tylko Win32). Jeśli i to nie przyniesie skutku, poszukiwane są w lokalizacji podanej przy kompilacji, takiej jak /usr/local/share/nmap lub /usr/share/nmap. Na końcu sprawdzany jest aktualny katalog.

--send-eth (Używanie niskopoziomowych ramek ethernet)
Opcja powoduje wysyłanie bezpośrednio ramek niskiego poziomu ethernet (warstwa danych), zamiast poprzez stos IP (warstwa sieci). Domyślnie Nmap wybiera metodę, która jest ogólnie lepsza dla danej platformy, na której jest uruchomiony. Gniazda raw (warstwa IP) są efektywniejsze w przypadku systemów UNIX, podczas gdy ramki ethernet są niezbędne w przypadku systemów Windows, od czasu kiedy to Microsoft wyłączył obsługę gniazd raw. Jeśli nie ma innej możliwości, Nmap w systemach UNIX wybierze metodę ethernet, pomijając wybraną przez użytkownika i niedostępną opcję.

--send-ip (Wysyłaj pakiety raw IP)
Włącza wysyłanie pakietów przez gniazda raw IP, zamiast przez ramki ethernet. Opcja jest przeciwieństwem opisanej wyżej opcji --send-eth.

--privileged (Zakładaj że użytkownik ma odpowiednie uprawnienia)
Informuje Nmapa, że użytkownik jest wystarczająco uprzywilejowany aby korzystać z wysyłania pakietów za pomocą gniazd raw, podsłuchiwania pakietów i podobnych operacji zwykle wymagających uprwawnień roota w systemach UNIX. Domyślnie Nmap przerywa działanie w momencie wykrycia próby wykonania takich operacji i funkcja geteuid() nie zwraca wartości zero. Opcja --privileged jest użyteczna w systemach Linux posiadających możliwości odpowiedniego przywilejowania użytkowników do przeprowadzania wymienionych operacji. Upewnij się, że opcja została podana przed innymi opcjami wymagającymi podwyższonych uprwanień (skanowanie SYN, wykrywanie systemu operacyjnego itp). Zmienna NMAP_PRIVILEGED może zostać ustawiona jako alternatywa dla wykorzystania opcji --privileged.

-V; --version (Wyświetl numer wersji)
Wyświetla tylko numer wersji Nmapa.

-h; --help (Wyświetl pomoc)
Wyświetla krótki ekran pomocy opisujący najpopularniejsze opcje, podobnie jak uruchomienie Nmapa bez parametrów.


### Interakcja w czasie pracy
Podczas pracy Nmapa, przechwytywane są wszystkie naciśnięcia klawiszy. Pozwala to na interakcję z programem bez przerywania go lub restartowania. Niektóre specjalne klawisze zmieniają opcje, inne wyświetlają status skanowania. Konwencja zakłada, że małe litery zmniejszają ilość informacji, a duże litery powiększają. Można również nacisnąć ‘?’ dla

v / V
Zwiększenia / Zmniejszenia poziomu szczegółowości

d / D
Zwiększenia / Zmniejszenia poziomu śledzenia błędów

p / P
Włączenia / Wyłączenia śledzenia pakietów

?
Wyświetlenia ekranu pomocy

Wszystko inne
Wyświetla status w postaci:

Stats: 0:00:08 elapsed; 111 hosts completed (5 up), 5 undergoing Service Scan

Service scan Timing: About 28.00% done; ETC: 16:18 (0:00:15 remaining)


### Przykłady
Poniżej przedstawiono przykłady wykorzystania Nmapa, od prostych i rutynowych do trochę bardziej skomplikowanych i ezoterycznych. Przykładowe adresy IP i nazwy domen powinny zostać zastąpione adresami/nazwami z twojej własnej sieci. Nie uważam, że skanowanie portów powinno być nielegalne, jednak niektórzy administratorzy nie tolerują nie autoryzowanego skanowania ich sieci i mogą zgłaszać swoje protesty. Uzyskanie zgody jest pierwszym wyzwaniem.

Do celu testów, masz zgodę do skanowania hosta scanme.nmap.org. Zgoda pozwala jedynie na skanowanie za pomocą Nmapa, nie zaś na testowanie exploitów czy przeprowadzanie ataków typu Denial of Service. Dla oszczędności pasma, proszę nie uruchamiaj więcej niż tuzina skanowań tego hosta dziennie. W przypadku nadużyć, host zostanie wyłączony, a Nmap będzie zwracał komunikat Failed to resolve given hostname/IP: scanme.nmap.org. pozwolenie dotyczy także adresów scanme2.nmap.org, scanme3.nmap.org i następnych, choć hosty te jeszcze nie istnieją.

nmap -v scanme.nmap.org

Pozwoli na przeskanowanie wszystkich portów TCP adresu scanme.nmap.org. Opcja -v podwyższy poziom szczegółowości zwracanych informacji.

nmap -sS -O scanme.nmap.org/24

Uruchamia skanowanie SYN wszystkich 255 hostów znajdujących się w tej samej klasie „C”, co host scanme.nmap.org. Dodatkowo wykonywana jest próba detekcji systemu operacyjnego dla każdego hosta, który jest aktywny. Wymaga to uprawnień użytkownika root, z powodu wykorzystania skanowania SYN i wykrywania systemu operacyjnego.

nmap -sV -p 22,53,110,143,4564 198.116.0-255.1-127

Uruchamia enumerację hostów i skanowanie TCP pierwszej połowy każej z 255 możliwych 8-mio bitowych podsieci klasy B 198.116. Wykrywane jest działanie usług sshd, DNS, pop3d, imapd i portu 4564. Dla każdego z tych portów, który został wykryty jako otwarty przeprowadzane jest wykrywanie wersji działającej aplikacji.

nmap -v -iR 100000 -P0 -p 80

Poleca Nmapowi na wybranie 100,000 losowych hostów i przeskanowanie ich w poszukiwaniu serwerów WWW (port 80). Enumeracja hostów jest wyłączona za pomocą opcji -P0, ponieważ wysyłanie najpierw pakietów w celu określenia czy host jest aktywny nie ma sensu, jako że i tak jest wykonywany test tylko na jednym porcie per host.

nmap -P0 -p80 -oX logs/pb-port80scan.xml -oG logs/pb-port80scan.gnmap 216.163.128.20/20

Skanuje 4096 adresów IP w poszukiwaniu serwerów WWW (bez pingowania ich) i zapisuje wyniki w plikach XML i grepowalnym.

