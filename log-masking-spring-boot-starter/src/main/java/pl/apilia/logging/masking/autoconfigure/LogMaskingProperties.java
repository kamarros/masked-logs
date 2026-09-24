package pl.apilia.logging.masking.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import pl.apilia.logging.masking.MaskingSettings;

import java.util.List;

/**
 * Log masking configuration ({@code apilia.logging.masking.*}).
 * <p>
 * The values are consumed by Logback through {@code <springProperty>} entries in {@code masking-defaults.xml}, because
 * logging is configured before the application context starts. This class documents the properties (IDE metadata)
 * and is used for startup verification. Defaults must stay in sync with {@link MaskingSettings#defaults()}.
 *
 * @param enabled                   masking on/off - keep enabled on every shared environment
 * @param sanitizeControlCharacters escape CR, LF and TAB in log messages (log forging / log injection protection)
 * @param maxMessageLength          longer messages are truncated before regex scanning ({@code 0} - no limit)
 * @param rules                     masking rules toggles
 * @param additionalSensitiveKeys   keys whose values are always fully masked (case and '-'/'_' insensitive);
 *                                  must be given as a comma separated string, not a YAML list
 */
@ConfigurationProperties("apilia.logging.masking")
public record LogMaskingProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("true") boolean sanitizeControlCharacters,
        @DefaultValue("" + MaskingSettings.DEFAULT_MAX_MESSAGE_LENGTH) int maxMessageLength,
        @DefaultValue Rules rules,
        @DefaultValue List<String> additionalSensitiveKeys
) {

    /**
     * @param credentials  password, secret, token, authorization, apiKey, cookie, pin, cvv/cvc: {@code ***}
     * @param cardNumbers  PAN: {@code 4111-XXXX-XXXX-1111}
     * @param bankAccounts IBAN / NRB: {@code PL61********************1234}
     * @param pesel        PESEL, see {@code peselMode}
     * @param peselMode    {@code FULL}: {@code ***********}, {@code BIRTH_DATE}: {@code 850101*****}
     * @param emails       {@code u***r@domain.com}
     * @param phoneNumbers {@code *******12}
     */
    public record Rules(
            @DefaultValue("true") boolean credentials,
            @DefaultValue("true") boolean cardNumbers,
            @DefaultValue("true") boolean bankAccounts,
            @DefaultValue("true") boolean pesel,
            @DefaultValue("FULL") MaskingSettings.PeselMaskMode peselMode,
            @DefaultValue("true") boolean emails,
            @DefaultValue("true") boolean phoneNumbers
    ) {
    }
}
