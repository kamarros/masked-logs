package pl.apilia.logging.masking;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.LoggingEvent;
import net.logstash.logback.encoder.LogstashEncoder;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static net.logstash.logback.argument.StructuredArguments.kv;
import static net.logstash.logback.argument.StructuredArguments.value;
import static org.assertj.core.api.Assertions.assertThat;

class SensitiveDataJsonGeneratorDecoratorTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    @Test
    void shouldProduceValidJsonWithMaskedSensitiveData() {
        var context = new LoggerContext();
        var event = new LoggingEvent(getClass().getName(), context.getLogger("test"), Level.INFO,
                "Customer {} registered, card {}, {}",
                null, new Object[]{kv("pesel", "44051401359"), "4111111111111111", kv("password", "Secret123")});
        event.setMDCPropertyMap(Map.of("CORRELATION_ID", "abc-123", "Authorization", "Bearer xyz"));

        JsonNode json = encode(context, event);

        assertThat(json.isObject()).isTrue();
        assertThat(json.get("@timestamp").asString()).isNotBlank();
        assertThat(json.get("level").asString()).isEqualTo("INFO");
        assertThat(json.get("logger_name").asString()).isEqualTo("test");
        assertThat(json.get("message").asString())
                .isEqualTo("Customer pesel=*********** registered, card 4111-XXXX-XXXX-1111, password=***");
        assertThat(json.get("pesel").asString()).isEqualTo("***********");
        assertThat(json.get("password").asString()).isEqualTo("***");
        assertThat(json.get("CORRELATION_ID").asString()).isEqualTo("abc-123");
        assertThat(json.get("Authorization").asString()).isEqualTo("***");
    }

    @Test
    void shouldMaskNestedObjectsAndArraysWithoutBreakingStructure() {
        var context = new LoggerContext();
        var customer = Map.of(
                "issueId", 123456789,
                "email", "jan.kowalski@example.com",
                "phones", List.of("+48 600 700 812"),
                "accounts", List.of(Map.of("iban", "PL61109010140000071219812874", "currency", "PLN")),
                "credentials", Map.of("accessToken", "eyJhbGciOiJIUzI1NiJ9", "clientId", "my-app"));
        var event = event(context, "customer loaded", value("customer", customer));

        JsonNode node = encode(context, event).get("customer");

        assertThat(node.get("issueId").asInt()).isEqualTo(123456789);
        assertThat(node.get("email").asString()).isEqualTo("j***i@example.com");
        assertThat(node.get("phones").isArray()).isTrue();
        assertThat(node.get("phones").get(0).asString()).isEqualTo("*********12");
        assertThat(node.get("accounts").get(0).get("iban").asString()).isEqualTo("PL61********************2874");
        assertThat(node.get("accounts").get(0).get("currency").asString()).isEqualTo("PLN");
        assertThat(node.get("credentials").get("accessToken").asString()).isEqualTo("***");
        assertThat(node.get("credentials").get("clientId").asString()).isEqualTo("my-app");
    }

    @Test
    void shouldMaskStackTrace() {
        var context = new LoggerContext();
        var event = new LoggingEvent(getClass().getName(), context.getLogger("test"), Level.ERROR, "failed",
                new IllegalStateException("response {\"iban\":\"PL61109010140000071219812874\"}"), new Object[0]);
        event.setMDCPropertyMap(Map.of());

        JsonNode json = encode(context, event);

        assertThat(json.get("stack_trace").asString())
                .contains("PL61********************2874")
                .doesNotContain("PL61109010140000071219812874");
    }

    @Test
    void shouldKeepControlCharactersEscapedByJsonEncoding() {
        var context = new LoggerContext();
        var event = event(context, "user {} logged in", "admin\n{\"level\":\"INFO\"}");

        String output = encodeToString(context, event);

        assertThat(output.strip().lines()).hasSize(1);
        assertThat(JSON.readTree(output).get("message").asString()).isEqualTo("user admin\n{\"level\":\"INFO\"} logged in");
    }

    @Test
    void shouldNotMaskWhenDisabled() {
        var context = new LoggerContext();
        context.putProperty(MaskingSettings.ENABLED, "false");
        var event = event(context, "{}", kv("password", "Secret123"));

        JsonNode json = encode(context, event);

        assertThat(json.get("password").asString()).isEqualTo("Secret123");
    }

    private static LoggingEvent event(LoggerContext context, String message, Object... args) {
        var event = new LoggingEvent(SensitiveDataJsonGeneratorDecoratorTest.class.getName(), context.getLogger("test"), Level.INFO, message, null, args);
        event.setMDCPropertyMap(Map.of());
        return event;
    }

    private static JsonNode encode(LoggerContext context, LoggingEvent event) {
        return JSON.readTree(encodeToString(context, event));
    }

    private static String encodeToString(LoggerContext context, LoggingEvent event) {
        var decorator = new SensitiveDataJsonGeneratorDecorator();
        decorator.setContext(context);
        decorator.start();
        var encoder = new LogstashEncoder();
        encoder.setContext(context);
        encoder.addDecorator(decorator);
        encoder.start();
        return new String(encoder.encode(event), StandardCharsets.UTF_8);
    }
}
