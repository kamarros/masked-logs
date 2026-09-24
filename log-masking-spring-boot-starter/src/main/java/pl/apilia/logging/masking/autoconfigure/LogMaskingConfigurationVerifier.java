package pl.apilia.logging.masking.autoconfigure;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.PatternLayout;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.OutputStreamAppender;
import ch.qos.logback.core.encoder.LayoutWrappingEncoder;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.core.env.Environment;
import pl.apilia.logging.masking.MaskingSettings;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Startup checks - reports (WARN) configurations in which sensitive data would reach the logs unmasked.
 */
public class LogMaskingConfigurationVerifier implements SmartInitializingSingleton {

    private static final org.slf4j.Logger log = LoggerFactory.getLogger(LogMaskingConfigurationVerifier.class);

    private static final String MASKED_MESSAGE = "%maskedMsg";

    private final LogMaskingProperties properties;
    private final Environment environment;

    public LogMaskingConfigurationVerifier(LogMaskingProperties properties, Environment environment) {
        this.properties = properties;
        this.environment = environment;
    }

    @Override
    public void afterSingletonsInstantiated() {
        verify().forEach(log::warn);
        if (properties.enabled()) {
            log.info("Log masking enabled: true");
        }
    }

    /**
     * @return warnings describing unsafe configuration
     */
    public List<String> verify() {
        List<String> warnings = new ArrayList<>();
        if (!properties.enabled()) {
            warnings.add("Log masking enabled: false - sensitive data may be written to logs");
            return warnings;
        }
        if (environment.containsProperty("apilia.logging.masking.additional-sensitive-keys[0]")) {
            warnings.add("apilia.logging.masking.additional-sensitive-keys is defined as a YAML list and is ignored by Logback"
                    + " - use a comma separated string instead");
        }
        if (!(LoggerFactory.getILoggerFactory() instanceof LoggerContext loggerContext)) {
            return warnings;
        }
        if (loggerContext.getProperty(MaskingSettings.ENABLED) == null) {
            warnings.add("Log masking is not configured in Logback - include"
                    + " pl/apilia/logging/masking/logback/masking-base.xml (or masking-defaults.xml) in logback-spring.xml");
        }
        Logger root = loggerContext.getLogger(Logger.ROOT_LOGGER_NAME);
        for (Iterator<Appender<ILoggingEvent>> it = root.iteratorForAppenders(); it.hasNext(); ) {
            Appender<ILoggingEvent> appender = it.next();
            String pattern = patternOf(appender);
            if (pattern != null && !pattern.contains(MASKED_MESSAGE)) {
                warnings.add("Appender '" + appender.getName() + "' writes log messages without masking - use "
                        + MASKED_MESSAGE + " instead of %m/%msg in its pattern: " + pattern);
            }
        }
        return warnings;
    }

    private static String patternOf(Appender<ILoggingEvent> appender) {
        if (appender instanceof OutputStreamAppender<ILoggingEvent> streamAppender
                && streamAppender.getEncoder() instanceof LayoutWrappingEncoder<ILoggingEvent> encoder
                && encoder.getLayout() instanceof PatternLayout layout) {
            return layout.getPattern();
        }
        return null;
    }
}
