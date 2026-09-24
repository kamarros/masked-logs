package pl.apilia.logging.masking.autoconfigure;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import pl.apilia.logging.masking.MaskingSettings;

import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;

class LogMaskingAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(LogMaskingAutoConfiguration.class));

    @Test
    void shouldUsePropertyDefaultsEqualToMaskingSettingsDefaults() {
        contextRunner.run(context -> {
            LogMaskingProperties properties = context.getBean(LogMaskingProperties.class);
            MaskingSettings defaults = MaskingSettings.defaults();

            assertThat(toSettings(properties)).isEqualTo(defaults);
        });
    }

    @Test
    void shouldBindProperties() {
        contextRunner
                .withPropertyValues(
                        "apilia.logging.masking.max-message-length=1000",
                        "apilia.logging.masking.rules.pesel-mode=birth-date",
                        "apilia.logging.masking.rules.phone-numbers=false",
                        "apilia.logging.masking.additional-sensitive-keys=nik,cif")
                .run(context -> {
                    LogMaskingProperties properties = context.getBean(LogMaskingProperties.class);

                    assertThat(properties.maxMessageLength()).isEqualTo(1000);
                    assertThat(properties.rules().peselMode()).isEqualTo(MaskingSettings.PeselMaskMode.BIRTH_DATE);
                    assertThat(properties.rules().phoneNumbers()).isFalse();
                    assertThat(properties.additionalSensitiveKeys()).containsExactly("nik", "cif");
                });
    }

    @Test
    void shouldWarnWhenMaskingDisabled() {
        contextRunner
                .withPropertyValues("apilia.logging.masking.enabled=false")
                .run(context -> assertThat(context.getBean(LogMaskingConfigurationVerifier.class).verify())
                        .containsExactly("Log masking enabled: false - sensitive data may be written to logs"));
    }

    @Test
    void shouldWarnWhenAdditionalKeysDefinedAsYamlList() {
        contextRunner
                .withPropertyValues(
                        "apilia.logging.masking.additional-sensitive-keys[0]=nik",
                        "apilia.logging.masking.additional-sensitive-keys[1]=cif")
                .run(context -> assertThat(context.getBean(LogMaskingConfigurationVerifier.class).verify())
                        .anyMatch(warning -> warning.contains("comma separated")));
    }

    private static MaskingSettings toSettings(LogMaskingProperties properties) {
        LogMaskingProperties.Rules rules = properties.rules();
        return new MaskingSettings(properties.enabled(), properties.sanitizeControlCharacters(), properties.maxMessageLength(),
                rules.credentials(), rules.cardNumbers(), rules.bankAccounts(), rules.pesel(), rules.peselMode(),
                rules.emails(), rules.phoneNumbers(), new HashSet<>(properties.additionalSensitiveKeys()));
    }
}
