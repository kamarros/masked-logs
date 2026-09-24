package pl.apilia.logging.masking;

import ch.qos.logback.core.Context;

import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Log masking configuration.
 * <p>
 * Values are provided to the Logback context by {@code <springProperty>} entries in {@code logback-spring.xml},
 * which map them from the {@code apilia.logging.masking.*} Spring properties. Missing values fall back to
 * secure defaults (masking enabled), so an environment without explicit configuration is always masked.
 */
public record MaskingSettings(
        boolean enabled,
        boolean sanitizeControlCharacters,
        int maxMessageLength,
        boolean maskCredentials,
        boolean maskCardNumbers,
        boolean maskBankAccounts,
        boolean maskPesel,
        PeselMaskMode peselMaskMode,
        boolean maskEmails,
        boolean maskPhoneNumbers,
        Set<String> additionalSensitiveKeys
) {

    public static final String ENABLED = "LOG_MASKING_ENABLED";
    public static final String SANITIZE_CONTROL_CHARACTERS = "LOG_MASKING_SANITIZE_CONTROL_CHARACTERS";
    public static final String MAX_MESSAGE_LENGTH = "LOG_MASKING_MAX_MESSAGE_LENGTH";
    public static final String CREDENTIALS = "LOG_MASKING_CREDENTIALS";
    public static final String CARD_NUMBERS = "LOG_MASKING_CARD_NUMBERS";
    public static final String BANK_ACCOUNTS = "LOG_MASKING_BANK_ACCOUNTS";
    public static final String PESEL = "LOG_MASKING_PESEL";
    public static final String PESEL_MODE = "LOG_MASKING_PESEL_MODE";
    public static final String EMAILS = "LOG_MASKING_EMAILS";
    public static final String PHONE_NUMBERS = "LOG_MASKING_PHONE_NUMBERS";
    public static final String ADDITIONAL_SENSITIVE_KEYS = "LOG_MASKING_ADDITIONAL_SENSITIVE_KEYS";

    public static final int DEFAULT_MAX_MESSAGE_LENGTH = 50_000;

    public enum PeselMaskMode {
        /** {@code ***********} */
        FULL,
        /** keeps date of birth, e.g. {@code 850101*****} */
        BIRTH_DATE
    }

    public MaskingSettings {
        additionalSensitiveKeys = additionalSensitiveKeys == null ? Set.of() : additionalSensitiveKeys.stream()
                .map(MaskingSettings::normalizeKey)
                .filter(key -> !key.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
        peselMaskMode = peselMaskMode == null ? PeselMaskMode.FULL : peselMaskMode;
    }

    public static MaskingSettings defaults() {
        return new MaskingSettings(true, true, DEFAULT_MAX_MESSAGE_LENGTH,
                true, true, true, true, PeselMaskMode.FULL, true, true, Set.of());
    }

    public static MaskingSettings fromContext(Context context) {
        if (context == null) {
            return defaults();
        }
        return new MaskingSettings(
                bool(context, ENABLED),
                bool(context, SANITIZE_CONTROL_CHARACTERS),
                integer(context, MAX_MESSAGE_LENGTH),
                bool(context, CREDENTIALS),
                bool(context, CARD_NUMBERS),
                bool(context, BANK_ACCOUNTS),
                bool(context, PESEL),
                peselMode(context.getProperty(PESEL_MODE)),
                bool(context, EMAILS),
                bool(context, PHONE_NUMBERS),
                csv(context.getProperty(ADDITIONAL_SENSITIVE_KEYS))
        );
    }

    /**
     * Key normalization used for key-based matching: case-insensitive, separators ({@code -}, {@code _}) ignored,
     * only the last segment of dotted keys taken into account ({@code spring.datasource.password -> password}).
     */
    static String normalizeKey(String key) {
        if (key == null) {
            return "";
        }
        String lastSegment = key.substring(key.lastIndexOf('.') + 1);
        StringBuilder normalized = new StringBuilder(lastSegment.length());
        for (int i = 0; i < lastSegment.length(); i++) {
            char c = lastSegment.charAt(i);
            if (c != '-' && c != '_' && !Character.isWhitespace(c)) {
                normalized.append(Character.toLowerCase(c));
            }
        }
        return normalized.toString();
    }

    private static boolean bool(Context context, String name) {
        String value = context.getProperty(name);
        // anything other than an explicit "false" keeps masking on - fail safe
        return value == null || !"false".equalsIgnoreCase(value.trim());
    }

    private static int integer(Context context, String name) {
        String value = context.getProperty(name);
        if (value == null || value.isBlank()) {
            return DEFAULT_MAX_MESSAGE_LENGTH;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return DEFAULT_MAX_MESSAGE_LENGTH;
        }
    }

    private static PeselMaskMode peselMode(String value) {
        if (value == null || value.isBlank()) {
            return PeselMaskMode.FULL;
        }
        try {
            return PeselMaskMode.valueOf(value.trim().toUpperCase(Locale.ROOT).replace('-', '_'));
        } catch (IllegalArgumentException e) {
            return PeselMaskMode.FULL;
        }
    }

    private static Set<String> csv(String value) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
    }
}
