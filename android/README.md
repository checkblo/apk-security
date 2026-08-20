# CyberTarcza Android

Natywny klient dla Androida 10 i nowszego (`minSdk 29`). Nie korzysta z WebView ani bibliotek reklamowych/analitycznych.

Bezpieczenstwo:

- stan checklisty jest szyfrowany AES-256-GCM;
- klucz powstaje i pozostaje w Android Keystore;
- kopia danych aplikacji i transfer miedzy urzadzeniami sa zablokowane;
- polaczenia HTTP bez TLS sa zablokowane;
- aplikacja nie prosi o uprawnienia administratora, dostepnosc, SMS, kontakty ani pliki;
- otwarcie aplikacji wymaga potwierdzenia blokady ekranu, jesli telefon ja posiada.

Do zbudowania podpisanego wydania wymagany jest Android Studio/Android SDK 35, JDK 17 i prywatny magazyn klucza. Dane podpisu przekazuje sie zmiennymi `CT_KEYSTORE_FILE`, `CT_KEYSTORE_PASSWORD`, `CT_KEY_ALIAS`, `CT_KEY_PASSWORD`. Klucza podpisujacego nie wolno dodawac do repozytorium.
