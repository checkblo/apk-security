# Zgodność bezpieczeństwa w Unii Europejskiej

Stan dokumentu: 21 sierpnia 2026 r.

## Cel i zastrzeżenie

Ten dokument opisuje przygotowanie projektu CyberTarcza Local do wymagań bezpieczeństwa obowiązujących w Unii Europejskiej. Nie stanowi porady prawnej, certyfikatu, deklaracji zgodności UE ani prawa do użycia oznakowania CE. Ostateczny zakres zależy od sposobu dystrybucji, modelu biznesowego, siedziby producenta, kategorii użytkowników i państwa członkowskiego.

Nie istnieje jedna lista „wszystkich norm UE” obowiązująca każdą aplikację. Poniżej rozdzielono akty bezpośrednio istotne, akty warunkowe oraz dobrowolne normy techniczne. Przed komercyjnym udostępnieniem produktu należy wykonać formalną analizę prawną i ocenę zgodności.

## Matryca zastosowania

| Akt lub standard | Status dla projektu | Co zostało uwzględnione | Co pozostaje przed dystrybucją |
| --- | --- | --- | --- |
| Rozporządzenie (UE) 2024/2847 — Cyber Resilience Act (CRA) | Prawdopodobnie zastosowanie, jeśli aplikacja lub obraz kontenera jest udostępniany na rynku UE w ramach działalności komercyjnej | bezpieczne ustawienia domyślne, ocena ryzyka, polityka podatności, aktualizacje zależności, SBOM Node, instrukcja bezpiecznej instalacji, brak sekretów w repozytorium | określić producenta i kontakt, klasyfikację produktu, okres wsparcia, pełny SBOM Android/Docker, podpisywanie wydań, ocenę zgodności, dokumentację z załącznika VII, deklarację zgodności UE i ewentualne CE |
| RODO — rozporządzenie (UE) 2016/679 | Zastosowanie, gdy dane osobowe są przetwarzane poza czysto osobistym/rodzinnym użyciem | privacy by design, lokalne przechowywanie, szyfrowanie, minimalizacja, brak telemetrii, kontrola eksportu i usunięcia | wskazać administratora, cele i podstawy prawne, terminy retencji, odbiorców, procedurę praw osób i naruszeń danych; wykonać DPIA, jeżeli wynika z ryzyka |
| NIS2 — dyrektywa (UE) 2022/2555 i prawo krajowe | Warunkowe; dotyczy podmiotów kluczowych/ważnych i określonych sektorów, nie każdej aplikacji | wzorzec zarządzania ryzykiem, incydenty, ciągłość działania, łańcuch dostaw, bezpieczny rozwój, kryptografia, MFA dla repozytorium | właściciel wdrożenia musi ustalić, czy podlega NIS2 i prawu krajowemu; ustanowić role, szkolenia, rejestr incydentów, ciągłość i zgłoszenia do właściwego CSIRT |
| Data Act — rozporządzenie (UE) 2023/2854 | Warunkowe; istotne dla danych z połączonych produktów/usług powiązanych | eksport zaszyfrowanego sejfu i lokalna kontrola danych | ocenić ponownie, jeśli aplikacja zacznie zbierać dane z routera/IoT albo świadczyć usługę powiązaną |
| DORA — rozporządzenie (UE) 2022/2554 | Zwykle nie dotyczy samodzielnej aplikacji konsumenckiej; warunkowe dla podmiotów finansowych i dostawców ICT w ich łańcuchu | podstawowe kontrole odporności i zależności | osobna ocena kontraktowa, testy odporności i wymagania incydentowe przy dostarczaniu do sektora finansowego |
| Cybersecurity Act — rozporządzenie (UE) 2019/881 | Ramy certyfikacji; zastosowanie zależy od użycia właściwego europejskiego programu certyfikacji | projekt nie deklaruje nieistniejącego certyfikatu | ocenić dostępne programy certyfikacji dla finalnej klasy produktu |
| RED i delegowane wymagania cyberbezpieczeństwa dla urządzeń radiowych | Nie dotyczy samej aplikacji; może dotyczyć producenta telefonu/routera/urządzenia IoT | aplikacja nie zmienia firmware radiowego | ponowna ocena, jeśli powstanie własne urządzenie radiowe lub firmware |
| AI Act — rozporządzenie (UE) 2024/1689 | Obecnie poza zakresem — projekt nie zawiera systemu AI | brak automatycznego profilowania lub decyzji AI | ponowna klasyfikacja przed dodaniem funkcji AI |
| eIDAS2 | Obecnie poza zakresem — projekt nie świadczy kwalifikowanych usług zaufania ani europejskiego portfela tożsamości | standardowe lokalne uwierzytelnianie | ponowna ocena przed dodaniem podpisów kwalifikowanych lub usług zaufania |

## CRA — wymagania produktu z elementami cyfrowymi

### Kontrole wdrożone

- model zagrożeń i decyzje bezpieczeństwa w `SECURITY.md`;
- domyślne powiązanie panelu z `127.0.0.1`, brak ekspozycji LAN i internetu;
- szyfrowanie AES-256-GCM oraz scrypt bez własnych algorytmów kryptograficznych;
- ochrona CSRF, bezpieczne ciasteczka, CSP, HSTS i ograniczenia ramek;
- kontenery bez capabilities, bez Docker Socket, z systemem plików tylko do odczytu i limitami zasobów;
- minimalizacja danych, brak telemetrii i zewnętrznych skryptów;
- automatyczne testy, lint, CodeQL, Dependabot i kontrola zmian zależności;
- generowanie SBOM dla zależności Node.js w CI;
- prywatne zgłaszanie podatności przez GitHub Security Advisories;
- instrukcje bezpiecznej instalacji i informacje o ograniczeniach produktu.

### Luki zgodności blokujące deklarację CRA/CE

1. Brak ustalonego prawnego producenta, adresu i kontaktu bezpieczeństwa.
2. Brak zatwierdzonej klasyfikacji CRA oraz procedury oceny zgodności.
3. Brak podpisanych produkcyjnych wydań APK i obrazów kontenerowych.
4. Brak kompletnego SBOM obejmującego system bazowy obrazu, Caddy i Gradle/Android.
5. Brak formalnego rejestru podatności, decyzji naprawczych i dowodów testów dla każdego wydania.
6. Brak deklaracji okresu wsparcia dla produkcyjnego wydania.
7. Brak deklaracji zgodności UE, oceny przez jednostkę notyfikowaną, jeżeli będzie wymagana, oraz podstawy do oznakowania CE.

Do czasu zamknięcia tych punktów projekt nie może być opisywany jako „certyfikowany”, „zgodny z CRA” ani oznaczany CE.

## Terminy CRA

- 10 grudnia 2024: wejście CRA w życie;
- 11 września 2026: rozpoczęcie obowiązków zgłaszania aktywnie wykorzystywanych podatności i poważnych incydentów;
- 11 grudnia 2027: stosowanie głównych obowiązków CRA.

Plan reakcji powinien umożliwiać wstępne zgłoszenie w ciągu 24 godzin, pełne zgłoszenie w ciągu 72 godzin oraz raport końcowy w terminach przewidzianych przez CRA. Zgłoszenia producentów odbywają się przez platformę CRA utrzymywaną przez ENISA i trafiają do właściwego CSIRT.

## RODO — ochrona danych

Projekt realizuje privacy by design przez lokalne przetwarzanie, szyfrowanie sejfu, brak telemetrii i zbieranie tylko danych potrzebnych użytkownikowi. Opcjonalne wywołanie Pwned Passwords wysyła jedynie prefiks skrótu; sprawdzanie adresu e-mail wymaga świadomego dodania własnego klucza HIBP.

Przed udostępnieniem produktu organizacja musi uzupełnić `PRIVACY.md`, w szczególności dane administratora, cele, podstawy prawne, retencję, odbiorców, transfery, prawa osób oraz kontakt. Należy prowadzić ocenę naruszeń danych i — gdy ryzyko tego wymaga — DPIA.

## NIS2 jako profil podwyższonego bezpieczeństwa

Nawet gdy operator nie podlega NIS2, projekt przyjmuje jej obszary kontrolne jako profil dobrych praktyk:

- polityka analizy ryzyka i bezpieczeństwa systemów;
- obsługa incydentów;
- ciągłość działania, kopie zapasowe i odtwarzanie;
- bezpieczeństwo łańcucha dostaw;
- bezpieczeństwo nabywania, rozwoju i utrzymania oraz ujawnianie podatności;
- pomiar skuteczności zabezpieczeń;
- cyberhigiena i szkolenia;
- polityka kryptografii;
- bezpieczeństwo personelu i kontrola dostępu;
- MFA i bezpieczna komunikacja.

## Normy i dobre praktyki techniczne

Poniższe pozycje są profilami docelowymi, a nie deklaracją certyfikacji:

- ISO/IEC 27001:2022 i ISO/IEC 27002:2022 — system zarządzania bezpieczeństwem informacji;
- ISO/IEC 27005 — zarządzanie ryzykiem;
- ISO/IEC 29147 i ISO/IEC 30111 — ujawnianie i obsługa podatności;
- IEC 62443-4-1 i IEC 62443-4-2 — bezpieczny cykl rozwoju i komponenty;
- ETSI EN 303 645 — bazowe bezpieczeństwo konsumenckiego IoT, jeśli projekt obejmie własne IoT;
- OWASP ASVS — panel i API;
- OWASP MASVS — natywna aplikacja Android;
- CIS Benchmarks — host Windows, Docker i system bazowy obrazu.

Komisja Europejska zleciła opracowanie 41 norm wspierających CRA. Dopiero właściwe normy zharmonizowane, zastosowane w odpowiednim zakresie i opublikowane zgodnie z prawem UE, mogą dawać domniemanie zgodności. Numery i status tych norm należy ponownie zweryfikować przed oceną zgodności.

## Źródła urzędowe

- Komisja Europejska, Cyber Resilience Act: https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act
- Komisja Europejska, podsumowanie CRA: https://digital-strategy.ec.europa.eu/en/policies/cra-summary
- Komisja Europejska, raportowanie CRA: https://digital-strategy.ec.europa.eu/en/policies/cra-reporting
- Komisja Europejska, standaryzacja CRA: https://digital-strategy.ec.europa.eu/en/policies/cra-standardisation
- EUR-Lex, rozporządzenie (UE) 2024/2847: https://eur-lex.europa.eu/eli/reg/2024/2847/oj
- EUR-Lex, RODO — rozporządzenie (UE) 2016/679: https://eur-lex.europa.eu/eli/reg/2016/679/oj
- EUR-Lex, NIS2 — dyrektywa (UE) 2022/2555: https://eur-lex.europa.eu/eli/dir/2022/2555/oj
- ENISA, NIS2 Technical Implementation Guidance: https://www.enisa.europa.eu/publications/nis2-technical-implementation-guidance
- EUR-Lex, Data Act — rozporządzenie (UE) 2023/2854: https://eur-lex.europa.eu/eli/reg/2023/2854/oj
- EUR-Lex, DORA — rozporządzenie (UE) 2022/2554: https://eur-lex.europa.eu/eli/reg/2022/2554/oj
- EUR-Lex, Cybersecurity Act — rozporządzenie (UE) 2019/881: https://eur-lex.europa.eu/eli/reg/2019/881/oj
- EUR-Lex, wymagania cyberbezpieczeństwa RED — rozporządzenie delegowane (UE) 2022/30: https://eur-lex.europa.eu/eli/reg_del/2022/30/oj
- EUR-Lex, AI Act — rozporządzenie (UE) 2024/1689: https://eur-lex.europa.eu/eli/reg/2024/1689/oj
- EUR-Lex, eIDAS2 — rozporządzenie (UE) 2024/1183: https://eur-lex.europa.eu/eli/reg/2024/1183/oj
