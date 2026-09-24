package pl.apilia.logging.masking;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.PatternLayout;
import ch.qos.logback.classic.spi.LoggingEvent;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class MaskingMessageConverterTest {

    @Test
    void shouldMaskFormattedMessageIncludingArguments() {
        var context = new LoggerContext();

        String output = format(context, "%maskedMsg", "Request {} from {}", new Object[]{"password=abc", "jan.kowalski@example.com"}, null);

        assertThat(output).isEqualTo("Request password=*** from j***i@example.com");
    }

    @Test
    void shouldEscapeLineBreaksToPreventLogForging() {
        var context = new LoggerContext();

        String output = format(context, "%maskedMsg%n", "user {} logged in", new Object[]{"admin\n2026-01-01 INFO user root logged in"}, null);

        assertThat(output.lines()).hasSize(1);
        assertThat(output).contains("admin\\n2026-01-01 INFO user root logged in");
    }

    @Test
    void shouldMaskExceptionMessagesAndKeepStackTraceLines() {
        var context = new LoggerContext();
        var exception = new IllegalStateException("400 Bad Request: {\"pesel\":\"44051401359\",\"token\":\"abc\"}");

        String output = format(context, "%maskedMsg%maskedEx", "call failed", new Object[0], exception);

        assertThat(output)
                .contains("{\"pesel\":\"***********\",\"token\":\"***\"}")
                .doesNotContain("44051401359", "\"abc\"")
                .contains("at pl.apilia.logging.masking.MaskingMessageConverterTest");
        assertThat(output.lines().count()).isGreaterThan(2);
    }

    @Test
    void shouldReadSettingsFromLoggerContextProperties() {
        var context = new LoggerContext();
        context.putProperty(MaskingSettings.ENABLED, "false");
        context.putProperty(MaskingSettings.SANITIZE_CONTROL_CHARACTERS, "false");

        String output = format(context, "%maskedMsg", "password=abc\nnext", new Object[0], null);

        assertThat(output).isEqualTo("password=abc\nnext");
    }

    @Test
    void shouldApplyRuleTogglesFromLoggerContextProperties() {
        var context = new LoggerContext();
        context.putProperty(MaskingSettings.EMAILS, "false");
        context.putProperty(MaskingSettings.PESEL_MODE, "birth_date");
        context.putProperty(MaskingSettings.ADDITIONAL_SENSITIVE_KEYS, "nik, cif");

        String output = format(context, "%maskedMsg", "jan@example.com 44051401359 nik=123 cif=456", new Object[0], null);

        assertThat(output).isEqualTo("jan@example.com 440514***** nik=*** cif=***");
    }

    private static String format(LoggerContext context, String pattern, String message, Object[] args, Throwable throwable) {
        var layout = new PatternLayout();
        layout.getInstanceConverterMap().put("maskedMsg", MaskingMessageConverter::new);
        layout.getInstanceConverterMap().put("maskedEx", MaskingThrowableConverter::new);
        layout.setContext(context);
        layout.setPattern(pattern);
        layout.start();
        var event = new LoggingEvent(MaskingMessageConverterTest.class.getName(), context.getLogger("test"), Level.INFO, message, throwable, args);
        return layout.doLayout(event);
    }
}
