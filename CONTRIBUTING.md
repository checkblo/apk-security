# Współpraca przy CyberTarcza Local

## Zasady bezpieczeństwa

- nie dodawaj sekretów, kluczy API, plików `.vault`, kluczy podpisujących Androida ani prawdziwych danych użytkownika;
- każdą zmianę kryptografii, uwierzytelniania, sesji lub nagłówków bezpieczeństwa opisz w pull requeście;
- nie osłabiaj ustawień kontenerów ani domyślnego powiązania usługi z `127.0.0.1`;
- luki zgłaszaj prywatnie zgodnie z `SECURITY.md`, a nie w publicznym issue.

## Sprawdzenie zmiany

```bash
npm ci --ignore-scripts
npm run test:secure
npm run lint
docker build -t cybertarcza-local:test .
```

Zmiana dotycząca Androida powinna dodatkowo przejść `gradle --no-daemon assembleDebug` w katalogu `android/`.

## Pull request

Opisz zakres, ryzyko bezpieczeństwa, sposób testowania i wpływ na migrację sejfu. Używaj małych, możliwych do przeglądu commitów.
