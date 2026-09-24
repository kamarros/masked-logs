# Apilia log masking

Maskowanie danych wrażliwych w logach aplikacji Spring Boot 4 (Logback). Logika maskowania żyje w bibliotece,
aplikacja dodaje tylko zależność, jedną linię w `logback-spring.xml` i ewentualnie konfigurację.

| Dane | Wynik |
|---|---|
| Numer karty (PAN, weryfikacja Luhn) | `4111-XXXX-XXXX-1111` |
| CVV/CVC, PIN | `***` |
| IBAN / NRB (weryfikacja mod-97) | `PL61********************1234` |
| PESEL (weryfikacja sumy kontrolnej) | `***********` lub `850101*****` |
| Hasła, tokeny, sekrety, `Authorization`, API key, cookie | `***` |
| E-mail | `u***r@domain.com` |
| Telefon | `*******12` |

Dodatkowo: ochrona przed log forging (escapowanie `\n`, `\r`, `\t`), limit długości komunikatu przed skanowaniem
regex, maskowanie stack trace'ów, logi JSON (`logstash-logback-encoder` 9, Jackson 3).

## Wymagania

- Java 17+
- Spring Boot 4.x (Jackson 3, Logback 1.5)

## Użycie

### 1. Zależność

```xml
<dependency>
    <groupId>pl.apilia.logging</groupId>
    <artifactId>log-masking-spring-boot-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```

`logstash-logback-encoder` przychodzi przechodnio - nie trzeba go deklarować.

### 2. `src/main/resources/logback-spring.xml`

Gotowa konfiguracja (konsola, format tekstowy; JSON przy aktywnym profilu `json-logs`):

```xml
<configuration>
    <include resource="pl/apilia/logging/masking/logback/masking-base.xml"/>
</configuration>
```

Własna konfiguracja appenderów - zamiast `org/springframework/boot/logging/logback/defaults.xml` dołącz
`masking-defaults.xml` (zawiera defaults Spring Boota) i używaj `%maskedMsg` / `%maskedEx`:

```xml
<configuration>
    <include resource="pl/apilia/logging/masking/logback/masking-defaults.xml"/>
    <include resource="pl/apilia/logging/masking/logback/masking-console-appender.xml"/>      <!-- CONSOLE -->
    <include resource="pl/apilia/logging/masking/logback/masking-json-console-appender.xml"/> <!-- JSON_CONSOLE -->

    <root level="INFO">
        <appender-ref ref="CONSOLE"/>
    </root>
</configuration>
```

Własny `logging.pattern.console` musi używać `%maskedMsg` zamiast `%m`/`%msg` oraz `%maskedEx` zamiast `%wEx`.
Przy starcie aplikacja zaloguje WARN, jeśli któryś appender tekstowy tego nie robi.

### 3. Konfiguracja (opcjonalnie)

Maskowanie jest **domyślnie włączone** - środowiska bez konfiguracji są maskowane.

```yaml
apilia:
  logging:
    masking:
      enabled: true                     # wyłączaj tylko lokalnie
      sanitize-control-characters: true # log forging
      max-message-length: 50000         # dłuższe komunikaty są przycinane przed skanowaniem regex (0 = bez limitu)
      rules:
        credentials: true
        card-numbers: true
        bank-accounts: true
        pesel: true
        pesel-mode: FULL                # FULL | BIRTH_DATE
        emails: true
        phone-numbers: true
      # klucze maskowane zawsze w całości - WYŁĄCZNIE jako string rozdzielony przecinkami (nie lista YAML)
      additional-sensitive-keys: identityNo,documentNumber
```

Konfiguracja jest czytana przez Logback (`<springProperty>`) przed startem kontekstu Springa, dlatego działa
już dla logów ze startu aplikacji i nie wymaga żadnej adnotacji.

### Użycie konwerterów poza plikiem XML

Np. własny `PatternLayout` tworzony w kodzie:

```java
layout.getInstanceConverterMap().put("maskedMsg", MaskingMessageConverter::new);
layout.getInstanceConverterMap().put("maskedEx", MaskingThrowableConverter::new);
```

## Jak to działa

- **Po kluczu** - wartości kluczy wrażliwych w formatach `key=value`, `key: value`, JSON, escapowany JSON,
  nagłówki HTTP (`Authorization: Bearer ...`), query string, `toString()` Lomboka. Typ klucza decyduje o sposobie
  maskowania (np. `pesel=` -> PESEL, `accountNumber=` -> rachunek).
- **Po wartości** - skanowanie tekstu pod kątem PAN, IBAN/NRB, PESEL, e-maili i telefonów w formacie
  międzynarodowym; kandydaci weryfikowani sumami kontrolnymi, żeby nie maskować identyfikatorów i timestampów.
  Numery telefonów bez prefiksu kraju maskowane są tylko po kluczu (`phone`, `mobile`, ...).
- **JSON** - pola z hasłami/tokenami maskowane po nazwie pola (O(1)), pozostałe wartości przez `ValueMasker`.
- **Bezpieczeństwo regex** - wyłącznie kwantyfikatory possessive/ograniczone, wartości dopasowywane tylko po
  kluczach wrażliwych; testy na złośliwe wejścia pilnują liniowego czasu działania.

## Wersjonowanie, build i publikacja

Wersja jest ustawiana w jednym miejscu - właściwość `revision` w głównym `pom.xml` (CI-friendly versions,
`flatten-maven-plugin` wstawia prawdziwą wersję do instalowanych/publikowanych pom-ów).

- w repozytorium zawsze wersja deweloperska, np. `1.0.1-SNAPSHOT`,
- wydanie = ta sama wersja bez `-SNAPSHOT`, podawana przy publikacji.

```bash
# wersja deweloperska do ~/.m2 (debugowanie w aplikacji - patrz niżej)
mvn clean install

# wydanie do repozytorium plików aplikacji (do czasu firmowego Nexusa)
./scripts/publish-to-project-repo.sh /c/Software/santirek/santirek-backend/devops/libs 1.0.1
```

Po wydaniu podbij `revision` na kolejny SNAPSHOT (np. `1.0.2-SNAPSHOT`), a w aplikacji `log-masking.version`
na wydaną wersję i zacommituj `devops/libs/pl/apilia/logging`.

Skrypt odmawia publikacji SNAPSHOT-a oraz nadpisania istniejącej wersji (wydania są niezmienne - Maven cache'uje
je w `~/.m2` i aplikacje nie zobaczyłyby zmiany). Zostawia tylko sumy `.sha1` - bez sum Maven przy każdym
świeżym buildzie (np. CI) loguje `Could not validate integrity`; `.md5` są zbędne.

## Debugowanie w aplikacji

1. **Tylko podgląd / breakpointy** - nic nie trzeba zmieniać: wydanie zawiera `-sources.jar`, IntelliJ pokaże
   źródła biblioteki (Ctrl+klik, *Download Sources*) i zatrzyma się na breakpointach w jej kodzie.
2. **Zmiany w bibliotece na żywo** - aplikacja używa wersji SNAPSHOT zamiast wydania:
   - w aplikacji utwórz `.mvn/maven.config` (git-ignored) z linią `-Dlog-masking.version=1.0.1-SNAPSHOT`,
   - w oknie IntelliJ aplikacji: *Maven* -> *+* (Add Maven Project) -> `erste-log-masking/pom.xml`,
     (biblioteka otwarta w **osobnym** oknie IntelliJ nie wystarczy - aplikacja widzi wtedy jar w *External Libraries*;
     biblioteki nie trzeba uruchamiać, to zwykły moduł - debugujesz aplikację, breakpointy w kodzie biblioteki działają),
     następnie *Reload All Maven Projects*. IntelliJ podepnie moduł biblioteki bezpośrednio (bez `mvn install`),
     więc zmiany w jej kodzie są widoczne po zwykłym *Build*,
   - build z linii poleceń (`mvn` w aplikacji) wymaga wcześniej `mvn install` w bibliotece,
   - powrót do wydania: usuń `.mvn/maven.config` i przeładuj projekt Maven.

Profil Maven (`-P`) nie jest używany celowo - jawne włączenie profilu wyłącza profile `activeByDefault`
aplikacji (w santirek: `test-ignore-all`).
