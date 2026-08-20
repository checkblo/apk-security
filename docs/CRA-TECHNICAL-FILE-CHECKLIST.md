# Lista dokumentacji technicznej CRA

Ta lista służy do kompletowania dowodów zgodności. Nie jest deklaracją zgodności UE.

## Identyfikacja produktu

- [ ] producent, znak handlowy, adres pocztowy i cyfrowy kontakt bezpieczeństwa;
- [ ] nazwa, wersja, numer wydania i jednoznaczny identyfikator produktu;
- [ ] opis przeznaczenia i racjonalnie przewidywalnego użycia;
- [ ] klasyfikacja CRA: zwykły, ważny klasa I/II albo krytyczny;
- [ ] wykaz państw i kanałów udostępniania na rynku;
- [ ] data końca okresu wsparcia podana użytkownikowi.

## Ocena ryzyka

- [ ] aktywa, granice zaufania i przepływy danych;
- [ ] model przeciwnika i przypadki nadużyć;
- [ ] ryzyka dla poufności, integralności, dostępności i autentyczności;
- [ ] ryzyka łańcucha dostaw i komponentów zewnętrznych;
- [ ] ryzyka domyślnej i błędnej konfiguracji;
- [ ] ryzyko po zakończeniu wsparcia;
- [ ] uzasadnienie akceptacji ryzyka resztkowego podpisane przez producenta.

## Dowody techniczne

- [ ] pełny SBOM: Node.js, Android/Gradle, obrazy bazowe, Caddy i systemowe pakiety;
- [ ] wersje źródeł, skróty commitów i deterministyczne instrukcje budowania;
- [ ] raporty SAST, dependency review, testów jednostkowych i testów bezpieczeństwa;
- [ ] testy OWASP ASVS/MASVS odpowiednie do komponentu;
- [ ] skan obrazu kontenera i APK;
- [ ] przegląd kryptografii, kluczy, nonce, KDF, sesji i rotacji;
- [ ] dowody usunięcia sekretów z repozytorium i artefaktów;
- [ ] podpisy artefaktów i instrukcja weryfikacji podpisu;
- [ ] wyniki niezależnego testu penetracyjnego przed wydaniem produkcyjnym.

## Podatności i aktualizacje

- [ ] prywatny kanał coordinated vulnerability disclosure;
- [ ] rejestr zgłoszeń, oceny CVSS, decyzji i terminów naprawy;
- [ ] procedura monitorowania KEV/CVE i zależności;
- [ ] procedura wydania, wycofania i bezpiecznej aktualizacji;
- [ ] playbook raportowania CRA 24h/72h/raport końcowy;
- [ ] szablon informacji dla użytkowników i właściwego CSIRT;
- [ ] proces informowania o końcu wsparcia.

## Ocena zgodności i wydanie

- [ ] wybór modułu oceny zgodności właściwego dla kategorii produktu;
- [ ] wskazanie zastosowanych norm zharmonizowanych i ich aktualnych wydań;
- [ ] ocena jednostki notyfikowanej, jeśli jest wymagana;
- [ ] instrukcje bezpiecznej instalacji, działania, aktualizacji i usuwania;
- [ ] deklaracja zgodności UE;
- [ ] legalna podstawa oznakowania CE;
- [ ] archiwizacja dokumentacji i dowodów przez wymagany okres.
