# Model bezpieczeństwa CyberTarcza Local

## Chronione dane

- zapisane adresy e-mail i etykiety;
- lista urządzeń i notatki;
- wykonane kontrole bezpieczeństwa;
- skrócone wyniki sprawdzania wycieków;
- lokalny dziennik zmian bez treści haseł.

Aplikacja celowo nie przechowuje haseł do kont, kodów 2FA, kodów odzyskiwania, kluczy BitLocker, dokumentów tożsamości ani kluczy YubiKey.

## Zakładany przeciwnik

Projekt ogranicza ryzyko:

- skanowania portów z internetu lub sieci domowej;
- odczytu skopiowanego/ukradzionego pliku sejfu;
- manipulacji plikiem sejfu;
- prób CSRF i osadzania panelu w obcej stronie;
- powtarzanych prób logowania;
- przejęcia jednego kontenera i eskalacji przez nadmiarowe uprawnienia;
- wycieku hasła przez funkcję Pwned Passwords.

## Ograniczenia

Projekt nie chroni przed:

- całkowicie przejętym systemem hosta lub keyloggerem działającym podczas odblokowanej sesji;
- słabym lub ponownie użytym hasłem głównym;
- luką typu zero-day w systemie, Dockerze, Node.js, Caddy lub przeglądarce;
- fizycznym dostępem do odblokowanego komputera/telefonu;
- złośliwym rozszerzeniem przeglądarki z uprawnieniami do strony;
- użytkownikiem, który ręcznie wystawi port 8443 na wszystkie interfejsy lub przekaże Docker Socket;
- wyciekiem danych, który nie został jeszcze wykryty przez HIBP.

## Decyzje projektowe

- `127.0.0.1:8443` zamiast ekspozycji LAN;
- brak konta chmurowego, zdalnej synchronizacji i telemetrii;
- brak pełnego menedżera haseł — do tego służy wyspecjalizowany, audytowany produkt;
- brak automatycznego włączania BitLockera i innych zmian wysokiego ryzyka;
- audyt Windows jest tylko do odczytu;
- Android nie używa dostępności ani uprawnień administratora urządzenia;
- szyfrowanie opiera się na standardowych prymitywach platformy, nie na własnym algorytmie.

## Parametry kryptograficzne

- KDF: scrypt, `N=131072`, `r=8`, `p=1`, losowa sól 32 bajty;
- podział 64-bajtowego materiału na oddzielny klucz szyfrowania i weryfikacji;
- szyfrowanie: AES-256-GCM, losowy nonce 12 bajtów, tag 16 bajtów i stały AAD wersji formatu;
- weryfikacja hasła: HMAC-SHA-256 porównywany w stałym czasie;
- identyfikatory sesji i tokeny CSRF: po 32 losowe bajty;
- Android: AES-256-GCM z kluczem w Android Keystore.

## Zgłaszanie problemów

Nie publikuj prawdziwego sejfu, klucza HIBP, hasła głównego, kodów odzyskiwania ani zrzutu zawierającego dane osobowe. Do odtworzenia błędu użyj pustego sejfu testowego.

Podejrzaną lukę zgłoś prywatnie przez zakładkę **Security → Advisories → Report a vulnerability** w repozytorium GitHub. Nie twórz publicznego issue, dopóki poprawka nie będzie dostępna. W zgłoszeniu podaj wersję, komponent, wpływ i minimalne kroki odtworzenia na danych testowych.

## Obsługiwane wersje

Wersje `0.x` są rozwojowe i nie są produkcyjnymi wydaniami przeznaczonymi do udostępniania na rynku. Poprawki bezpieczeństwa dla etapu rozwojowego są przygotowywane dla najnowszej wersji z gałęzi `main`.

Pierwsze produkcyjne wydanie musi otrzymać jednoznaczną datę końca wsparcia, opublikowaną w metadanych wydania i instrukcji użytkownika. Deklarowany okres powinien spełniać wymagania CRA odpowiednie do oczekiwanego czasu używania produktu; nie wolno publikować wydania produkcyjnego bez zatwierdzonego procesu aktualizacji, monitorowania podatności i obsługi incydentów.

## Proces podatności i incydentów

Każde prywatne zgłoszenie powinno otrzymać identyfikator, właściciela, ocenę wpływu, listę dotkniętych wersji, decyzję naprawczą i ślad czasowy. Aktywnie wykorzystywana podatność lub poważny incydent dotyczący produktu udostępnionego na rynku UE wymaga natychmiastowej oceny pod kątem raportowania CRA.

Proces organizacyjny musi być gotowy do terminów CRA: wstępne ostrzeżenie w ciągu 24 godzin, pełne zgłoszenie w ciągu 72 godzin i raport końcowy w odpowiednim terminie. Nie publikuj szczegółów umożliwiających wykorzystanie luki przed udostępnieniem poprawki i poinformowaniem użytkowników.

Dokumentacja przygotowania do wymagań UE znajduje się w `docs/EU-SECURITY-COMPLIANCE.md`. Samo istnienie tych dokumentów nie oznacza certyfikacji ani zakończenia oceny zgodności.
