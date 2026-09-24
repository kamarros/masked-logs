package pl.apilia.logging.masking.autoconfigure;

import ch.qos.logback.classic.LoggerContext;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * Registers {@link LogMaskingProperties} and verifies at startup that logs are actually masked.
 * <p>
 * Masking itself is configured in Logback ({@code masking-defaults.xml}) - it has to work before the application
 * context exists, so no annotation or bean is needed to enable it.
 */
@AutoConfiguration
@ConditionalOnClass(LoggerContext.class)
@EnableConfigurationProperties(LogMaskingProperties.class)
public class LogMaskingAutoConfiguration {

    @Bean
    LogMaskingConfigurationVerifier logMaskingConfigurationVerifier(LogMaskingProperties properties, Environment environment) {
        return new LogMaskingConfigurationVerifier(properties, environment);
    }
}
