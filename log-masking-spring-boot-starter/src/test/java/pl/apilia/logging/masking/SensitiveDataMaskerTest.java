package pl.apilia.logging.masking;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

class SensitiveDataMaskerTest {

    private final SensitiveDataMasker masker = new SensitiveDataMasker(MaskingSettings.defaults());

    @Nested
    class CardNumbers {

        @ParameterizedTest
        @CsvSource(delimiter = '|', quoteCharacter = '~', value = {
                "card 4111111111111111 charged      | card 4111-XXXX-XXXX-1111 charged",
                "card 4111 1111 1111 1111 charged   | card 4111-XXXX-XXXX-1111 charged",
                "card 4111-1111-1111-1111 charged   | card 4111-XXXX-XXXX-1111 charged",
                "amex 378282246310005               | amex 3782-XXXX-XXXX-0005",
                "amex 3782 822463 10005             | amex 3782-XXXX-XXXX-0005",
                "mc 5555555555554444                | mc 5555-XXXX-XXXX-4444",
        })
        void shouldMaskPanInFreeText(String input, String expected) {
            assertThat(masker.mask(input)).isEqualTo(expected);
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "invalid luhn 4111111111111112",
                "timestamp 1727088000000",
                "already masked 421352******6982",
                "uuid 3f2504e0-4f89-11d3-9a0c-0305e82c3301",
        })
        void shouldNotMaskNonPan(String input) {
            assertThat(masker.mask(input)).isEqualTo(input);
        }

        @Test
        void shouldMaskPanByKey() {
            assertThat(masker.mask("CardDTO(cardNumber=4111111111111111, type=VISA)"))
                    .isEqualTo("CardDTO(cardNumber=4111-XXXX-XXXX-1111, type=VISA)");
            assertThat(masker.mask("{\"virtualCardNumber\":\"4111111111111111\"}"))
                    .isEqualTo("{\"virtualCardNumber\":\"4111-XXXX-XXXX-1111\"}");
        }

        @ParameterizedTest
        @ValueSource(strings = {"cvv=123", "cvc2: 123", "\"cvv\":\"123\"", "pin=1234", "PIN: 1234"})
        void shouldFullyMaskCvvAndPin(String input) {
            assertThat(masker.mask(input)).doesNotContain("123").contains(SensitiveDataMasker.MASK);
        }
    }

    @Nested
    class BankAccounts {

        @ParameterizedTest
        @CsvSource(delimiter = '|', quoteCharacter = '~', value = {
                "iban PL61109010140000071219812874         | iban PL61********************2874",
                "iban PL61 1090 1014 0000 0712 1981 2874   | iban PL61********************2874",
                "nrb 61109010140000071219812874            | nrb 61********************2874",
                "nrb 61 1090 1014 0000 0712 1981 2874      | nrb 61********************2874",
                "iban DE89370400440532013000               | iban DE89**************3000",
        })
        void shouldMaskIbanAndNrbInFreeText(String input, String expected) {
            assertThat(masker.mask(input)).isEqualTo(expected);
        }

        @Test
        void shouldNotMaskAccountWithInvalidChecksumInFreeText() {
            String input = "number 61109010140000071219812875";

            assertThat(masker.mask(input)).isEqualTo(input);
        }

        @Test
        void shouldMaskAccountByKeyEvenWithoutValidChecksum() {
            assertThat(masker.mask("accountNumber=12345678901234567890123456"))
                    .isEqualTo("accountNumber=12********************3456");
            assertThat(masker.mask("\"iban\": \"PL00123456789012345678901234\""))
                    .isEqualTo("\"iban\": \"PL00********************1234\"");
        }
    }

    @Nested
    class Pesel {

        @Test
        void shouldFullyMaskValidPeselInFreeText() {
            assertThat(masker.mask("client 44051401359 found")).isEqualTo("client *********** found");
        }

        @Test
        void shouldKeepBirthDateInBirthDateMode() {
            var birthDateMasker = new SensitiveDataMasker(settings(MaskingSettings.PeselMaskMode.BIRTH_DATE, Set.of()));

            assertThat(birthDateMasker.mask("client 44051401359 found")).isEqualTo("client 440514***** found");
        }

        @ParameterizedTest
        @ValueSource(strings = {"id 44051401358", "id 12345678901", "id 99999999999"})
        void shouldNotMaskElevenDigitsWithoutValidPeselChecksumInFreeText(String input) {
            assertThat(masker.mask(input)).isEqualTo(input);
        }

        @Test
        void shouldMaskPeselByKeyEvenWithoutValidChecksum() {
            assertThat(masker.mask("ClientDTO(pesel=12345678901, name=Jan)")).isEqualTo("ClientDTO(pesel=***********, name=Jan)");
            assertThat(masker.mask("{\"pesel\":12345678901}")).isEqualTo("{\"pesel\":***********}");
        }
    }

    @Nested
    class Credentials {

        @ParameterizedTest
        @CsvSource(delimiter = '|', quoteCharacter = '~', value = {
                "password=Secret123!                               | password=***",
                "user.password = Secret123                         | user.password = ***",
                "{\"password\":\"Secr\\\"et 1\",\"login\":\"jan\"} | {\"password\":\"***\",\"login\":\"jan\"}",
                "{\\\"clientSecret\\\":\\\"abc\\\"}                 | {\\\"clientSecret\\\":\\\"***\\\"}",
                "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.x  | Authorization: ***",
                "[Authorization:\"Bearer abc.def\", Accept:\"*/*\"] | [Authorization:\"***\", Accept:\"*/*\"]",
                "{Authorization=[Basic YWxhOmtvdA==]}              | {Authorization=[***]}",
                "GET /api?access_token=abc123&page=1               | GET /api?access_token=***&page=1",
                "X-Api-Key: 123e4567                               | X-Api-Key: ***",
                "apiKey='k3y'                                      | apiKey='***'",
                "refresh_token=abc; path=/                         | refresh_token=***; path=/",
                "Cookie: JSESSIONID=ABC123                         | Cookie: ***",
        })
        void shouldFullyMaskCredentials(String input, String expected) {
            assertThat(masker.mask(input)).isEqualTo(expected);
        }

        @Test
        void shouldMaskNestedCredentialsInsideNonSensitiveValue() {
            String input = "body={\"data\":\"{\\\"password\\\":\\\"abc\\\"}\"}";

            assertThat(masker.mask(input)).doesNotContain("abc");
        }

        @Test
        void shouldKeepNullValues() {
            assertThat(masker.mask("{\"password\":null}")).isEqualTo("{\"password\":null}");
        }

        @Test
        void shouldMaskAdditionalConfiguredKeys() {
            var customMasker = new SensitiveDataMasker(settings(MaskingSettings.PeselMaskMode.FULL, Set.of("identityNo", "document_number")));

            assertThat(customMasker.mask("identityNo=ABC123456, DOCUMENT-NUMBER: XYZ, other=1"))
                    .isEqualTo("identityNo=***, DOCUMENT-NUMBER: ***, other=1");
        }
    }

    @Nested
    class EmailsAndPhones {

        @ParameterizedTest
        @CsvSource(delimiter = '|', quoteCharacter = '~', value = {
                "sent to jan.kowalski@example.com         | sent to j***i@example.com",
                "sent to user@domain.com.pl, cc ab@x.io  | sent to u***r@domain.com.pl, cc a***@x.io",
                "email=jan@example.com                   | email=j***n@example.com",
        })
        void shouldMaskEmails(String input, String expected) {
            assertThat(masker.mask(input)).isEqualTo(expected);
        }

        @ParameterizedTest
        @CsvSource(delimiter = '|', quoteCharacter = '~', value = {
                "call +48 123 456 789 now           | call *********89 now",
                "call +48123456789                  | call *********89",
                "phoneNumber=123456789              | phoneNumber=*******89",
                "{\"mobileNo\":\"600 700 812\"}      | {\"mobileNo\":\"*******12\"}",
        })
        void shouldMaskPhoneNumbers(String input, String expected) {
            assertThat(masker.mask(input)).isEqualTo(expected);
        }

        @ParameterizedTest
        @ValueSource(strings = {"issueId=123456789", "mobileNoPrefix=48", "emailTemplate=WELCOME"})
        void shouldNotMaskNonSensitiveValues(String input) {
            assertThat(masker.mask(input)).isEqualTo(input);
        }
    }

    @Nested
    class LogForging {

        @Test
        void shouldEscapeControlCharacters() {
            String forged = "login failed for admin\n2026-01-01 INFO login success for admin\r\tdone" + (char) 0x2028;

            assertThat(masker.sanitizeControlCharacters(forged))
                    .isEqualTo("login failed for admin\\n2026-01-01 INFO login success for admin\\r\\tdone\\" + "u2028")
                    .doesNotContain("\n", "\r", "\t");
        }

        @Test
        void shouldReturnSameInstanceWhenNothingToSanitize() {
            String text = "plain message";

            assertThat(masker.sanitizeControlCharacters(text)).isSameAs(text);
        }
    }

    @Nested
    class Configuration {

        @Test
        void shouldNotMaskWhenDisabled() {
            var disabled = new SensitiveDataMasker(new MaskingSettings(false, false, 10, true, true, true, true,
                    MaskingSettings.PeselMaskMode.FULL, true, true, Set.of()));
            String input = "password=abc card 4111111111111111\n";

            assertThat(disabled.mask(input)).isSameAs(input);
            assertThat(disabled.sanitizeControlCharacters(input)).isSameAs(input);
        }

        @Test
        void shouldApplyOnlyEnabledRules() {
            var onlyCredentials = new SensitiveDataMasker(new MaskingSettings(true, true, 1000, true, false, false, false,
                    MaskingSettings.PeselMaskMode.FULL, false, false, Set.of()));

            assertThat(onlyCredentials.mask("password=abc card 4111111111111111 jan@example.com 44051401359"))
                    .isEqualTo("password=*** card 4111111111111111 jan@example.com 44051401359");
        }

        @Test
        void shouldTruncateTooLongMessages() {
            var limited = new SensitiveDataMasker(new MaskingSettings(true, true, 10, true, true, true, true,
                    MaskingSettings.PeselMaskMode.FULL, true, true, Set.of()));

            assertThat(limited.mask("0123456789ABCDEF")).isEqualTo("0123456789... [truncated 6 chars]");
        }

        @Test
        void shouldReturnSameInstanceWhenNothingMasked() {
            String text = "Issue 123 created by user KOWALSKI: status=NEW";

            assertThat(masker.mask(text)).isSameAs(text);
        }
    }

    @Nested
    class RegexSafety {

        @ParameterizedTest
        @ValueSource(ints = {0, 1, 2, 3, 4, 5, 6, 7, 8})
        void shouldProcessAdversarialInputInLinearTime(int variant) {
            String input = switch (variant) {
                case 0 -> "a".repeat(49_000) + "@";
                case 1 -> "4 ".repeat(24_000);
                case 2 -> "\"password\":\"" + "x\\".repeat(24_000);
                case 3 -> "a=".repeat(24_000);
                case 4 -> "1-".repeat(24_000) + "x";
                case 5 -> "pin=[".repeat(9_000);
                case 6 -> "token='".repeat(7_000);
                case 7 -> "PL61 ".repeat(9_000);
                default -> "a.".repeat(24_000) + "@b";
            };

            assertTimeoutPreemptively(Duration.ofSeconds(2), () -> masker.mask(input));
        }
    }

    private static MaskingSettings settings(MaskingSettings.PeselMaskMode peselMode, Set<String> additionalKeys) {
        return new MaskingSettings(true, true, MaskingSettings.DEFAULT_MAX_MESSAGE_LENGTH, true, true, true, true,
                peselMode, true, true, additionalKeys);
    }
}
