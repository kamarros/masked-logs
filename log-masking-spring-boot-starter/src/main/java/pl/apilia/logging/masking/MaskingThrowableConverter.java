package pl.apilia.logging.masking;

import ch.qos.logback.classic.spi.IThrowableProxy;
import org.springframework.boot.logging.logback.ExtendedWhitespaceThrowableProxyConverter;

/**
 * Logback {@code %maskedEx} conversion word - Spring Boot's {@code %wEx} with sensitive data masked. Exception messages
 * often carry request/response fragments (e.g. {@code WebClientResponseException} bodies).
 * <p>
 * Line breaks are kept - a stack trace is multi-line by nature.
 */
public class MaskingThrowableConverter extends ExtendedWhitespaceThrowableProxyConverter {

    private SensitiveDataMasker masker = new SensitiveDataMasker(MaskingSettings.defaults());

    @Override
    public void start() {
        masker = new SensitiveDataMasker(MaskingSettings.fromContext(getContext()));
        super.start();
    }

    @Override
    protected String throwableProxyToString(IThrowableProxy throwableProxy) {
        return masker.mask(super.throwableProxyToString(throwableProxy));
    }
}
