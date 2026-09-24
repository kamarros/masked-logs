package pl.apilia.logging.masking;

import java.time.DateTimeException;
import java.time.LocalDate;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Masks sensitive data (credentials, PAN, IBAN/NRB, PESEL, e-mails, phone numbers) in log output.
 * <p>
 * Used only by the logging infrastructure (Logback converters, JSON encoder decorator) - business code must not call it.
 * <p>
 * Two strategies are applied, in this order:
 * <ol>
 *     <li>key-based - values of sensitive keys ({@code password=...}, {@code "pesel":"..."}, {@code Authorization: Bearer ...})
 *     are masked according to the key type,</li>
 *     <li>value-based - free text is scanned for well-known formats; candidates are verified with checksums
 *     (Luhn for PAN, mod-97 for IBAN/NRB, PESEL control digit) to keep false positives low.</li>
 * </ol>
 * Regex safety: patterns use possessive or bounded quantifiers only, without nested ambiguous repetitions, and input
 * length is capped with {@link MaskingSettings#maxMessageLength()}, so matching time is linear in the message length.
 * <p>
 * Instances are immutable and thread-safe.
 */
public final class SensitiveDataMasker {

    public static final String MASK = "***";

    private static final String TRUNCATION_MARKER = "... [truncated %d chars]";
    private static final String PAN_MIDDLE_MASK = "-XXXX-XXXX-";

    enum SensitiveKeyType { CREDENTIAL, ADDITIONAL, CARD_NUMBER, BANK_ACCOUNT, PESEL, EMAIL, PHONE }

    // key fragments are matched against normalized keys (lower-case, without '-' and '_'), see MaskingSettings#normalizeKey
    private static final List<String> CREDENTIAL_KEY_FRAGMENTS = List.of(
            "password", "passwd", "passphrase", "secret", "token", "authorization", "apikey", "credential", "privatekey", "cookie");
    private static final Set<String> CREDENTIAL_KEYS = Set.of("pwd", "pass", "pin", "cvv", "cvv2", "cvc", "cvc2", "cvn", "otp");
    private static final Set<String> CARD_NUMBER_KEYS = Set.of("pan", "cardno", "cardnum");
    private static final Set<String> BANK_ACCOUNT_KEYS = Set.of("nrb", "iban", "accountno", "accountnumber", "bankaccount");
    private static final Set<String> EMAIL_KEYS = Set.of("mail");
    private static final Set<String> PHONE_KEYS = Set.of("tel", "msisdn");
    private static final List<String> PHONE_KEY_FRAGMENTS = List.of("phone", "mobile", "telefon");

    /**
     * Exact JSON field names masked with {@code MaskingJsonGeneratorDecorator} path masks (O(1) lookup, no regex).
     */
    public static final Set<String> CREDENTIAL_FIELD_NAMES = Set.of(
            "password", "Password", "passwd", "pwd", "secret", "clientSecret", "client_secret",
            "token", "accessToken", "access_token", "refreshToken", "refresh_token", "idToken", "id_token",
            "authorization", "Authorization", "apiKey", "api_key", "x-api-key", "X-Api-Key",
            "cookie", "Cookie", "Set-Cookie", "cvv", "cvc", "cvv2", "cvc2", "pin");

    /*
     * <key><separator><value>, e.g. password=abc | "password": "abc" | \"token\":\"abc\" | Authorization: Bearer abc
     * | headers=[Authorization:"Bearer abc"] | {Authorization=[Bearer abc]}
     * Key and value are matched separately: the value is matched (anchored) only after a sensitive key, so values of
     * non-sensitive keys are never consumed - nested pairs inside them are still found and the scan stays linear.
     * The key is bounded and possessive; every value alternative starts with a distinct character and uses possessive
     * quantifiers - no backtracking is possible inside a value.
     */
    private static final Pattern KEY_PATTERN = Pattern.compile(
            "(?<![\\w.-])(?<key>[A-Za-z_][\\w.-]{0,63}+)\\\\?[\"']?[ \\t]{0,8}+[:=][ \\t]{0,8}+");
    private static final Pattern VALUE_PATTERN = Pattern.compile(
            "\"(?<dq>[^\"\\\\\\r\\n]*+(?:\\\\.[^\"\\\\\\r\\n]*+)*+)\""
                    + "|\\\\\"(?<edq>[^\"\\\\\\r\\n]*+)\\\\\""
                    + "|'(?<sq>[^'\\r\\n]*+)'"
                    + "|\\[(?<br>[^\\[\\]\\r\\n]*+)]"
                    + "|(?<uq>(?:(?:Bearer|Basic|Digest|Negotiate)[ \\t]++)?[^\\s\"'\\\\,;&\\[\\](){}<>]++)",
            Pattern.CASE_INSENSITIVE);
    private static final String[] VALUE_GROUPS = {"dq", "edq", "sq", "br", "uq"};

    // PL IBAN 28 chars; other countries 15-34; optional single spaces between groups of 4
    private static final Pattern IBAN_PATTERN = Pattern.compile(
            "(?<![\\w])[A-Z]{2}\\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?(?![\\w])");
    // NRB: 26 digits, optionally 2 + 6 groups of 4 separated by single spaces
    private static final Pattern NRB_PATTERN = Pattern.compile(
            "(?<![\\w])\\d{2}(?: ?\\d{4}){6}(?![\\w])");
    // PAN 15-19 digits: contiguous, 4-4-4-(3..7) with consistent separator, or AMEX 4-6-5
    private static final Pattern PAN_PATTERN = Pattern.compile(
            "(?<![\\w-])(?:[2-6]\\d{14,18}|[2-6]\\d{3}([ -])\\d{4}\\1\\d{4}\\1\\d{3,7}|3\\d{3}([ -])\\d{6}\\2\\d{5})(?![\\w-])");
    private static final Pattern PESEL_PATTERN = Pattern.compile(
            "(?<![\\w])\\d{11}(?![\\w])");
    // international format only - plain 9-digit numbers are indistinguishable from identifiers, those are masked by key
    private static final Pattern PHONE_PATTERN = Pattern.compile(
            "(?<![\\w+])(?:\\+|00)\\d{2}(?:[ -]?\\d){7,11}(?![\\w])");
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "(?<![\\w.%+*-])([A-Za-z0-9._%+-]{1,64})@((?:[A-Za-z0-9-]{1,63}\\.){1,8}[A-Za-z]{2,24})(?![\\w])");

    // unicode line terminators as numeric constants - literal or escaped forms break compilation
    // when the compiler does not read sources as UTF-8
    private static final char NEXT_LINE = 0x85;
    private static final char LINE_SEPARATOR = 0x2028;
    private static final char PARAGRAPH_SEPARATOR = 0x2029;

    private static final int[] PESEL_WEIGHTS = {1, 3, 7, 9, 1, 3, 7, 9, 1, 3};

    private final MaskingSettings settings;

    public SensitiveDataMasker(MaskingSettings settings) {
        this.settings = settings;
    }

    public MaskingSettings settings() {
        return settings;
    }

    public boolean isEnabled() {
        return settings.enabled();
    }

    /**
     * Masks sensitive data in free text. Returns the same instance when nothing was masked.
     */
    public String mask(String text) {
        if (!settings.enabled() || text == null || text.isEmpty()) {
            return text;
        }
        String result = truncate(text);
        if (result.indexOf('=') >= 0 || result.indexOf(':') >= 0) {
            result = maskKeyValues(result);
        }
        if (containsDigit(result)) {
            if (settings.maskBankAccounts()) {
                result = replace(IBAN_PATTERN, result, this::maskIbanMatch);
                result = replace(NRB_PATTERN, result, this::maskNrbMatch);
            }
            if (settings.maskCardNumbers()) {
                result = replace(PAN_PATTERN, result, this::maskPanMatch);
            }
            if (settings.maskPesel()) {
                result = replace(PESEL_PATTERN, result, this::maskPeselMatch);
            }
            if (settings.maskPhoneNumbers()) {
                result = replace(PHONE_PATTERN, result, match -> maskPhone(digitsOf(match.group())));
            }
        }
        if (settings.maskEmails() && result.indexOf('@') >= 0) {
            result = replace(EMAIL_PATTERN, result, match -> maskEmail(match.group(1), match.group(2)));
        }
        return result;
    }

    /**
     * Masks a single value of a structured field (e.g. JSON). The field name decides the masking strategy;
     * values of non-sensitive fields are scanned like free text.
     */
    public String maskValue(String fieldName, String value) {
        if (!settings.enabled() || value == null || value.isEmpty()) {
            return value;
        }
        Optional<SensitiveKeyType> keyType = classifyKey(fieldName);
        if (keyType.isPresent()) {
            return maskByKeyType(keyType.get(), value);
        }
        return mask(value);
    }

    /**
     * Log forging / log injection protection - escapes line breaks and tabs, so a single log event can not pretend
     * to be several entries.
     */
    public String sanitizeControlCharacters(String text) {
        if (!settings.sanitizeControlCharacters() || text == null) {
            return text;
        }
        StringBuilder sanitized = null;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            String replacement = switch (c) {
                case '\n' -> "\\n";
                case '\r' -> "\\r";
                case '\t' -> "\\t";
                case NEXT_LINE, LINE_SEPARATOR, PARAGRAPH_SEPARATOR -> "\\" + "u%04x".formatted((int) c);
                default -> null;
            };
            if (replacement != null && sanitized == null) {
                sanitized = new StringBuilder(text.length() + 16).append(text, 0, i);
            }
            if (sanitized != null) {
                if (replacement != null) {
                    sanitized.append(replacement);
                } else {
                    sanitized.append(c);
                }
            }
        }
        return sanitized == null ? text : sanitized.toString();
    }

    Optional<SensitiveKeyType> classifyKey(String key) {
        String normalized = MaskingSettings.normalizeKey(key);
        if (normalized.isEmpty()) {
            return Optional.empty();
        }
        if (settings.additionalSensitiveKeys().contains(normalized)) {
            return Optional.of(SensitiveKeyType.ADDITIONAL);
        }
        if (settings.maskCredentials()
                && (CREDENTIAL_KEYS.contains(normalized) || containsAny(normalized, CREDENTIAL_KEY_FRAGMENTS))) {
            return Optional.of(SensitiveKeyType.CREDENTIAL);
        }
        if (settings.maskCardNumbers() && (CARD_NUMBER_KEYS.contains(normalized) || normalized.contains("cardnumber"))) {
            return Optional.of(SensitiveKeyType.CARD_NUMBER);
        }
        if (settings.maskBankAccounts() && (BANK_ACCOUNT_KEYS.contains(normalized)
                || normalized.contains("iban") || normalized.contains("accountnumber"))) {
            return Optional.of(SensitiveKeyType.BANK_ACCOUNT);
        }
        if (settings.maskPesel() && (normalized.contains("pesel") || normalized.equals("ssn"))) {
            return Optional.of(SensitiveKeyType.PESEL);
        }
        if (settings.maskEmails() && (EMAIL_KEYS.contains(normalized) || normalized.contains("email"))) {
            return Optional.of(SensitiveKeyType.EMAIL);
        }
        if (settings.maskPhoneNumbers() && (PHONE_KEYS.contains(normalized) || containsAny(normalized, PHONE_KEY_FRAGMENTS))) {
            return Optional.of(SensitiveKeyType.PHONE);
        }
        return Optional.empty();
    }

    private String maskKeyValues(String text) {
        Matcher keyMatcher = KEY_PATTERN.matcher(text);
        Matcher valueMatcher = VALUE_PATTERN.matcher(text);
        StringBuilder result = null;
        int copiedUpTo = 0;
        int position = 0;
        while (position < text.length() && keyMatcher.find(position)) {
            position = keyMatcher.end();
            Optional<SensitiveKeyType> keyType = classifyKey(keyMatcher.group("key"));
            if (keyType.isEmpty()) {
                continue;
            }
            valueMatcher.region(keyMatcher.end(), text.length());
            if (!valueMatcher.lookingAt()) {
                continue;
            }
            String valueGroup = valueGroup(valueMatcher);
            String value = valueMatcher.group(valueGroup);
            String masked = maskByKeyType(keyType.get(), value);
            if (!masked.equals(value)) {
                if (result == null) {
                    result = new StringBuilder(text.length());
                }
                result.append(text, copiedUpTo, valueMatcher.start(valueGroup)).append(masked);
                copiedUpTo = valueMatcher.end(valueGroup);
            }
            position = valueMatcher.end();
        }
        if (result == null) {
            return text;
        }
        return result.append(text, copiedUpTo, text.length()).toString();
    }

    private static String valueGroup(Matcher matcher) {
        for (String group : VALUE_GROUPS) {
            if (matcher.start(group) >= 0) {
                return group;
            }
        }
        throw new IllegalStateException("No value group matched");
    }

    private String maskByKeyType(SensitiveKeyType type, String value) {
        if (value.isBlank() || "null".equalsIgnoreCase(value)) {
            return value;
        }
        return switch (type) {
            case CREDENTIAL, ADDITIONAL -> MASK;
            case CARD_NUMBER -> maskCardNumberValue(value);
            case BANK_ACCOUNT -> maskBankAccountValue(value);
            case PESEL -> maskPeselValue(value);
            case EMAIL -> maskEmailValue(value);
            case PHONE -> maskPhoneValue(value);
        };
    }

    private String maskCardNumberValue(String value) {
        String digits = digitsOf(value);
        // shorter values are either not a PAN or are already masked (e.g. 421352******6982)
        return digits.length() >= 12 && !isAlreadyMasked(value) ? maskPan(digits) : value;
    }

    private String maskBankAccountValue(String value) {
        String compact = value.replace(" ", "").replace("-", "").toUpperCase(Locale.ROOT);
        if (isAlreadyMasked(compact)) {
            return value;
        }
        if (compact.matches("[A-Z]{2}\\d{2}[A-Z0-9]{11,30}")) {
            return maskIban(compact);
        }
        if (compact.length() >= 10 && compact.chars().allMatch(Character::isDigit)) {
            return compact.substring(0, 2) + "*".repeat(compact.length() - 6) + compact.substring(compact.length() - 4);
        }
        return value;
    }

    private String maskPeselValue(String value) {
        String trimmed = value.trim();
        if (trimmed.length() == 11 && trimmed.chars().allMatch(Character::isDigit)) {
            return maskPesel(trimmed);
        }
        return containsDigit(value) && !isAlreadyMasked(value) ? MASK : value;
    }

    private String maskEmailValue(String value) {
        if (value.indexOf('@') < 0) {
            return value;
        }
        String masked = replace(EMAIL_PATTERN, value, match -> maskEmail(match.group(1), match.group(2)));
        return masked.equals(value) ? MASK : masked;
    }

    private String maskPhoneValue(String value) {
        String digits = digitsOf(value);
        return digits.length() >= 5 ? maskPhone(digits) : value;
    }

    private String maskIbanMatch(MatchResult match) {
        String compact = match.group().replace(" ", "");
        return isValidIban(compact) ? maskIban(compact) : match.group();
    }

    private String maskNrbMatch(MatchResult match) {
        String digits = match.group().replace(" ", "");
        return isValidIban("PL" + digits) ? maskBankAccountValue(digits) : match.group();
    }

    private String maskPanMatch(MatchResult match) {
        String digits = digitsOf(match.group());
        return isLuhnValid(digits) ? maskPan(digits) : match.group();
    }

    private String maskPeselMatch(MatchResult match) {
        return isValidPesel(match.group()) ? maskPesel(match.group()) : match.group();
    }

    static String maskPan(String digits) {
        return digits.substring(0, 4) + PAN_MIDDLE_MASK + digits.substring(digits.length() - 4);
    }

    static String maskIban(String compactIban) {
        return compactIban.substring(0, 4) + "*".repeat(compactIban.length() - 8) + compactIban.substring(compactIban.length() - 4);
    }

    String maskPesel(String pesel) {
        return settings.peselMaskMode() == MaskingSettings.PeselMaskMode.BIRTH_DATE
                ? pesel.substring(0, 6) + "*".repeat(5)
                : "*".repeat(11);
    }

    static String maskEmail(String local, String domain) {
        String maskedLocal = local.length() <= 2
                ? local.charAt(0) + MASK
                : local.charAt(0) + MASK + local.charAt(local.length() - 1);
        return maskedLocal + "@" + domain;
    }

    static String maskPhone(String digits) {
        return "*".repeat(digits.length() - 2) + digits.substring(digits.length() - 2);
    }

    static boolean isLuhnValid(String digits) {
        int sum = 0;
        boolean doubleDigit = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int digit = digits.charAt(i) - '0';
            if (doubleDigit) {
                digit *= 2;
                if (digit > 9) {
                    digit -= 9;
                }
            }
            sum += digit;
            doubleDigit = !doubleDigit;
        }
        return sum % 10 == 0;
    }

    static boolean isValidIban(String iban) {
        if (iban.length() < 15 || iban.length() > 34) {
            return false;
        }
        String rearranged = iban.substring(4) + iban.substring(0, 4);
        int remainder = 0;
        for (int i = 0; i < rearranged.length(); i++) {
            int value = Character.getNumericValue(rearranged.charAt(i));
            if (value < 0 || value > 35) {
                return false;
            }
            remainder = (value > 9 ? remainder * 100 : remainder * 10) + value;
            remainder %= 97;
        }
        return remainder == 1;
    }

    static boolean isValidPesel(String pesel) {
        int sum = 0;
        for (int i = 0; i < PESEL_WEIGHTS.length; i++) {
            sum += (pesel.charAt(i) - '0') * PESEL_WEIGHTS[i];
        }
        if ((10 - sum % 10) % 10 != pesel.charAt(10) - '0') {
            return false;
        }
        int year = Integer.parseInt(pesel.substring(0, 2));
        int encodedMonth = Integer.parseInt(pesel.substring(2, 4));
        int day = Integer.parseInt(pesel.substring(4, 6));
        int century = switch (encodedMonth / 20) {
            case 0 -> 1900;
            case 1 -> 2000;
            case 2 -> 2100;
            case 3 -> 2200;
            default -> 1800;
        };
        try {
            LocalDate.of(century + year, encodedMonth % 20, day);
            return true;
        } catch (DateTimeException e) {
            return false;
        }
    }

    private String truncate(String text) {
        int maxLength = settings.maxMessageLength();
        if (maxLength <= 0 || text.length() <= maxLength) {
            return text;
        }
        return text.substring(0, maxLength) + TRUNCATION_MARKER.formatted(text.length() - maxLength);
    }

    private static String replace(Pattern pattern, String text, Function<MatchResult, String> replacer) {
        return pattern.matcher(text).replaceAll(match -> Matcher.quoteReplacement(replacer.apply(match)));
    }

    private static boolean isAlreadyMasked(String value) {
        return value.indexOf('*') >= 0 || value.indexOf('X') >= 0 || value.indexOf('x') >= 0;
    }

    private static boolean containsAny(String value, List<String> fragments) {
        for (String fragment : fragments) {
            if (value.contains(fragment)) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsDigit(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (Character.isDigit(value.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    private static String digitsOf(String value) {
        StringBuilder digits = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c >= '0' && c <= '9') {
                digits.append(c);
            }
        }
        return digits.toString();
    }
}
