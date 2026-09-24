package pl.apilia.logging.masking;

import ch.qos.logback.classic.LoggerContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.LoggerFactory;
import org.springframework.boot.logging.LoggingInitializationContext;
import org.springframework.boot.logging.logback.LogbackLoggingSystem;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static net.logstash.logback.argument.StructuredArguments.kv;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the Logback resources shipped with the starter, initialized the same way Spring Boot does it.
 */
@ExtendWith(OutputCaptureExtension.class)
class LogbackConfigurationTest {

    private static final String LOGGER_NAME = "pl.apilia.logging.masking.configuration-test";

    private final LogbackLoggingSystem loggingSystem = new LogbackLoggingSystem(getClass().getClassLoader());

    @AfterEach
    void cleanUp() {
        System.clearProperty("CONSOLE_LOG_PATTERN");
        initialize(Map.of());
    }

    @Test
    void shouldMaskTextLogsWithDefaultPattern(CapturedOutput output) {
        initialize(Map.of());

        LoggerFactory.getLogger(LOGGER_NAME).info("login {} password={} card {}\nforged INFO entry",
                "jan.kowalski@example.com", "Secret123", "4111111111111111");

        assertThat(output.getOut())
                .contains("login j***i@example.com password=*** card 4111-XXXX-XXXX-1111\\nforged INFO entry")
                .doesNotContain("Secret123", "jan.kowalski@example.com", "4111111111111111");
    }

    @Test
    void shouldMaskExceptions(CapturedOutput output) {
        initialize(Map.of());

        LoggerFactory.getLogger(LOGGER_NAME).error("call failed", new IllegalStateException("{\"pesel\":\"44051401359\"}"));

        assertThat(output.getOut())
                .contains("{\"pesel\":\"***********\"}", "at pl.apilia.logging.masking.LogbackConfigurationTest")
                .doesNotContain("44051401359");
    }

    @Test
    void shouldUseCustomPatternFromLoggingPatternConsole(CapturedOutput output) {
        initialize(Map.of("logging.pattern.console", "CUSTOM %level %maskedMsg%n"));

        LoggerFactory.getLogger(LOGGER_NAME).info("password={}", "Secret123");

        assertThat(output.getOut()).contains("CUSTOM INFO password=***");
    }

    @Test
    void shouldMaskJsonLogsAndKeepValidJson(CapturedOutput output) {
        initialize(Map.of(), "json-logs");

        LoggerFactory.getLogger(LOGGER_NAME).info("customer {} {}", kv("pesel", "44051401359"), kv("password", "Secret123"));

        JsonNode json = lastJsonLine(output);
        assertThat(json.get("logger_name").asString()).isEqualTo(LOGGER_NAME);
        assertThat(json.get("message").asString()).isEqualTo("customer pesel=*********** password=***");
        assertThat(json.get("pesel").asString()).isEqualTo("***********");
        assertThat(json.get("password").asString()).isEqualTo("***");
        assertThat(json.has(MaskingSettings.ENABLED)).isFalse();
    }

    @Test
    void shouldNotMaskWhenDisabledByProperty(CapturedOutput output) {
        initialize(Map.of("apilia.logging.masking.enabled", "false"));

        LoggerFactory.getLogger(LOGGER_NAME).info("password={}", "Secret123");

        assertThat(output.getOut()).contains("password=Secret123");
    }

    @Test
    void shouldUseXmlDefaultsEqualToMaskingSettingsDefaults() {
        initialize(Map.of());

        assertThat(MaskingSettings.fromContext(loggerContext())).isEqualTo(MaskingSettings.defaults());
    }

    @Test
    void shouldMapSpringPropertiesToMaskingSettings() {
        initialize(Map.of(
                "apilia.logging.masking.sanitize-control-characters", "false",
                "apilia.logging.masking.max-message-length", "1000",
                "apilia.logging.masking.rules.emails", "false",
                "apilia.logging.masking.rules.pesel-mode", "birth-date",
                "apilia.logging.masking.additional-sensitive-keys", "nik, cif"));

        MaskingSettings settings = MaskingSettings.fromContext(loggerContext());

        assertThat(settings.sanitizeControlCharacters()).isFalse();
        assertThat(settings.maxMessageLength()).isEqualTo(1000);
        assertThat(settings.maskEmails()).isFalse();
        assertThat(settings.maskCredentials()).isTrue();
        assertThat(settings.peselMaskMode()).isEqualTo(MaskingSettings.PeselMaskMode.BIRTH_DATE);
        assertThat(settings.additionalSensitiveKeys()).isEqualTo(Set.of("nik", "cif"));
    }

    private void initialize(Map<String, Object> properties, String... profiles) {
        var environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("test", properties));
        environment.setActiveProfiles(profiles);
        loggingSystem.cleanUp();
        loggingSystem.beforeInitialize();
        loggingSystem.initialize(new LoggingInitializationContext(environment), "classpath:logback-masking-test.xml", null);
    }

    private static LoggerContext loggerContext() {
        return (LoggerContext) LoggerFactory.getILoggerFactory();
    }

    private static JsonNode lastJsonLine(CapturedOutput output) {
        List<String> jsonLines = output.getOut().lines()
                .filter(line -> line.startsWith("{") && line.contains(LOGGER_NAME))
                .toList();
        assertThat(jsonLines).isNotEmpty();
        return JsonMapper.builder().build().readTree(jsonLines.get(jsonLines.size() - 1));
    }
}
