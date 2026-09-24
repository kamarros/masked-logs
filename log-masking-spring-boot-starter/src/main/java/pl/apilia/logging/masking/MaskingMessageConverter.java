package pl.apilia.logging.masking;

import ch.qos.logback.classic.pattern.ClassicConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

/**
 * Logback {@code %maskedMsg} conversion word - formatted log message with sensitive data masked and control characters
 * escaped (log forging protection). Registered in {@code logback-spring.xml}.
 */
public class MaskingMessageConverter extends ClassicConverter {

    private SensitiveDataMasker masker = new SensitiveDataMasker(MaskingSettings.defaults());

    @Override
    public void start() {
        masker = new SensitiveDataMasker(MaskingSettings.fromContext(getContext()));
        super.start();
    }

    @Override
    public String convert(ILoggingEvent event) {
        return masker.sanitizeControlCharacters(masker.mask(event.getFormattedMessage()));
    }
}
