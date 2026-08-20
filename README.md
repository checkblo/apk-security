# CyberTarcza Local

Lokalne, szyfrowane centrum warstwowej ochrony dla:

- Windows 10 i Windows 11 (Home, Pro, Enterprise, Education oraz IoT);
- Androida 10 i nowszego, w tym Xiaomi 14 Pro 5G;
- routera operatora Vectra;
- kont, poczty, haseł, passkeys i kluczy YubiKey.

CyberTarcza nie udaje antywirusa. Nie zastępuje Defendera, Play Protect ani zapory routera. Bezpiecznie przechowuje stan zabezpieczeń, wykonuje kontrole wycieków i dostarcza audyt Windows tylko do odczytu.

## Najważniejsze zabezpieczenia aplikacji

- sejf szyfrowany `AES-256-GCM` z uwierzytelnieniem danych;
- klucz wyprowadzany z hasła przez pamięcioodporny `scrypt` (`N=131072`, `r=8`, `p=1`, losowa sól 256-bitowa);
- hasło główne nigdy nie jest zapisywane;
- klucz odszyfrowujący pozostaje wyłącznie w pamięci aktywnej sesji i jest zerowany po wylogowaniu;
- sesja ma 256 bitów losowości, 30 minut bezczynności i maksymalnie 8 godzin;
- ochrona CSRF, `SameSite=Strict`, `HttpOnly`, `Secure`, CSP, HSTS i blokada ramek;
- HTTPS z lokalnym urzędem certyfikacji;
- port przypięty do `127.0.0.1` — domyślnie brak dostępu z internetu i sieci domowej;
- kontenery działają bez capabilities, bez Docker Socket, z systemem plików tylko do odczytu, limitami pamięci, CPU i procesów;
- brak reklam, analityki, telemetrii i zewnętrznych skryptów;
- sprawdzanie hasła metodą k-anonimowości — pełne hasło ani pełny skrót nie opuszczają aplikacji;
- adresy e-mail, urządzenia, wyniki i dziennik są wewnątrz zaszyfrowanego sejfu.

Żaden program nie daje gwarancji „nie do zhakowania”. Ten projekt ogranicza powierzchnię ataku i stosuje bezpieczne ustawienia domyślne, ale nadal wymaga aktualizacji systemu, Dockera, telefonu i routera.

## Szybkie uruchomienie na Windows 10/11

Wymagania: 64-bitowy Windows, wirtualizacja, WSL 2 i uruchomiony Docker Desktop.

1. Otwórz PowerShell w folderze projektu.
2. Sprawdź wymagania:

   ```powershell
   .\scripts\preflight-windows.ps1
   ```

3. Uruchom aplikację:

   ```powershell
   .\scripts\start-cybertarcza.ps1
   ```

4. Opcjonalnie uruchom PowerShell jako administrator i zaufaj wyłącznie lokalnemu certyfikatowi wygenerowanemu przez Twój kontener:

   ```powershell
   .\scripts\trust-local-ca.ps1
   ```

   Skrypt pokazuje SHA-256 certyfikatu i wymaga wpisania dokładnie `TAK`. Nie instaluje certyfikatu automatycznie.

5. Otwórz `https://localhost:8443` i utwórz hasło główne o długości minimum 16 znaków. Zalecana jest fraza z 5–6 losowych słów.

Zatrzymanie:

```powershell
.\scripts\stop-cybertarcza.ps1
```

Zaszyfrowany sejf pozostaje w `data/cybertarcza.vault`.

## Monitoring Have I Been Pwned

Kontrola haseł Pwned Passwords działa bez klucza API. W celu sprawdzania adresów e-mail:

1. kup własny klucz API na oficjalnej stronie Have I Been Pwned;
2. wklej sam klucz do `.secrets/hibp_api_key.txt`;
3. uruchom ponownie kontenery: `docker compose restart app`.

Sekret jest montowany jako plik tylko w kontenerze aplikacji. Nie wpisuj go do `docker-compose.yml`, kodu ani zrzutu ekranu.

## Audyt Windows 10/11

W panelu można pobrać `windows-audit.ps1`. Skrypt:

- niczego nie zmienia;
- nie łączy się z internetem;
- nie wymaga hasła ani klucza odzyskiwania;
- sprawdza wersję Windows, Defendera, zaporę, Secure Boot, TPM, BitLocker/szyfrowanie urządzenia, ochronę ransomware, SMB1, RDP, UAC i usługę Windows Update;
- zapisuje raport JSON na pulpicie.

Przed uruchomieniem można otworzyć skrypt w Notatniku i przeczytać cały kod. Nie wyłączaj zabezpieczeń PowerShell globalnie.

Windows 10 jest obsługiwany przez audyt, ale standardowe wsparcie systemu zakończyło się 14 października 2025 r. Bez ESU aplikacja nie może zastąpić brakujących poprawek Microsoftu.

## Android 10+ i APK

Folder `android/` zawiera natywną aplikację bez WebView, reklam i analityki. Minimalna wersja to Android 10 (`API 29`). Stan checklisty jest szyfrowany `AES-256-GCM`, a klucz pozostaje w Android Keystore. Aplikacja nie prosi o dostęp do SMS, kontaktów, plików, lokalizacji, dostępności ani administratora urządzenia.

Projekt wymaga kompilacji i podpisania własnym kluczem wydawcy. Testowy APK może zbudować dołączony workflow, lecz wersję produkcyjną należy podpisać prywatnym kluczem, który nigdy nie jest dołączany do projektu.

Panel Docker jest również instalowalną PWA w Edge/Chrome. Ze względów bezpieczeństwa działa domyślnie tylko na komputerze (`localhost`) i nie jest wystawiony telefonowi przez Wi-Fi.

## Siedem warstw zawartych w aplikacji

1. dwa klucze YubiKey lub passkeys, z zapasowym kluczem przechowywanym osobno;
2. unikalne hasła i wskazówki 1Password Watchtower;
3. monitoring wycieków Have I Been Pwned;
4. wykrywanie ryzyka Windows 10 bez ESU;
5. prawidłowa konfiguracja Defendera, SmartScreen, zapory, szyfrowania i kopii offline;
6. Play Protect oraz Advanced Protection Androida, jeśli telefon ją obsługuje;
7. router: WPA3/WPA2-AES, wyłączone WPS, UPnP i zdalne zarządzanie, oddzielna sieć IoT/gości.

## Kopie zapasowe

Przycisk „Pobierz plik .vault” eksportuje już zaszyfrowany sejf. Stosuj regułę 3-2-1: trzy kopie, dwa różne nośniki, jedna kopia odłączona/offline. Hasło główne przechowuj osobno.

## Testy

```bash
npm run test:secure
```

Testy obejmują integralność AES-GCM, odrzucenie złego hasła, brak jawnych danych w pliku sejfu, sesje oraz blokadę CSRF.

## Aktualizacje

Raz w miesiącu:

```powershell
docker compose pull
docker compose up -d --build
```

Przed aktualizacją pobierz kopię `.vault`. Po aktualizacji sprawdź `docker compose ps` i uruchom testy projektu.

## Bezpieczeństwo i zgodność UE

Projekt zawiera profil przygotowania do Cyber Resilience Act, RODO i — warunkowo — NIS2, Data Act oraz wymagań sektorowych. Dokumentacja rozdziela obowiązki prawne od dobrowolnych standardów i nie składa nieuzasadnionej deklaracji certyfikacji ani zgodności CE.

- [Matryca zgodności bezpieczeństwa UE](docs/EU-SECURITY-COMPLIANCE.md)
- [Lista dokumentacji technicznej CRA](docs/CRA-TECHNICAL-FILE-CHECKLIST.md)
- [Informacja o prywatności — szablon UE](PRIVACY.md)
- [Model bezpieczeństwa i zgłaszanie podatności](SECURITY.md)

Przed komercyjnym udostępnieniem w UE należy ustalić prawnego producenta, klasyfikację produktu, okres wsparcia, proces raportowania, pełny SBOM, podpisywanie wydań oraz właściwą procedurę oceny zgodności.
