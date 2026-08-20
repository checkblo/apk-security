# Informacja o prywatności — szablon UE

CyberTarcza Local została zaprojektowana do pracy lokalnej, bez konta chmurowego, reklam, telemetrii i analityki. Ten plik jest szablonem, który musi zostać uzupełniony przez podmiot udostępniający produkcyjne wydanie.

## Administrator

**Do uzupełnienia przed dystrybucją:** nazwa prawna, adres, kontakt prywatności, przedstawiciel w UE — jeżeli wymagany — oraz inspektor ochrony danych, jeżeli został wyznaczony.

## Kategorie danych

Aplikacja może przechowywać wewnątrz lokalnego, zaszyfrowanego sejfu:

- podane przez użytkownika adresy e-mail i etykiety;
- listę urządzeń i notatki bezpieczeństwa;
- wyniki checklist i skrócone wyniki kontroli wycieków;
- lokalny dziennik zmian niezawierający haseł.

Aplikacja nie powinna przechowywać hasła głównego, haseł do kont, kodów 2FA, kodów odzyskiwania, kluczy BitLocker, dokumentów tożsamości ani prywatnych kluczy YubiKey.

## Przetwarzanie lokalne

Sejf jest szyfrowany lokalnie. Producent nie otrzymuje jego zawartości, o ile osobna funkcja chmurowa nie zostanie dodana w przyszłości. Użytkownik kontroluje eksport i usunięcie pliku `.vault`.

## Have I Been Pwned

Kontrola Pwned Passwords korzysta z k-anonimowości: pełne hasło ani pełny skrót nie są wysyłane. Kontrola adresu e-mail jest opcjonalna, wymaga własnego klucza API i może przekazać sprawdzany adres do Have I Been Pwned. Użytkownik powinien zapoznać się z aktualną polityką prywatności tego niezależnego dostawcy.

## Retencja i usunięcie

Dane pozostają w lokalnym sejfie do czasu usunięcia ich przez użytkownika lub usunięcia pliku sejfu i kopii zapasowych. Podmiot wdrażający powinien określić własne okresy retencji oraz procedurę bezpiecznego kasowania kopii.

## Prawa osób

Jeżeli RODO ma zastosowanie, administrator musi zapewnić realizację praw dostępu, sprostowania, usunięcia, ograniczenia, przenoszenia, sprzeciwu i skargi do właściwego organu nadzorczego, odpowiednio do podstawy i charakteru przetwarzania.

## Bezpieczeństwo i naruszenia

Stosowane są szyfrowanie, minimalizacja, lokalne przetwarzanie i kontrola dostępu. Żaden środek nie usuwa całego ryzyka. Administrator wdrożenia musi posiadać procedurę oceny naruszeń i zgłaszania ich organowi nadzorczemu oraz osobom, gdy wymagają tego art. 33–34 RODO.

## Zmiany

Zmiana telemetrii, synchronizacji, hostingu, dostawców lub celu przetwarzania wymaga ponownej oceny prywatności, aktualizacji tej informacji oraz — w razie potrzeby — DPIA.
