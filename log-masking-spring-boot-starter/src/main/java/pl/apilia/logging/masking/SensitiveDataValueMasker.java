package pl.apilia.logging.masking;

import net.logstash.logback.mask.ValueMasker;
import tools.jackson.core.TokenStreamContext;

/**
 * {@link ValueMasker} for {@code logstash-logback-encoder} (Jackson 3) - masks JSON string/number values: by field name
 * when the field is sensitive (e.g. {@code pesel}, {@code iban}), otherwise by scanning the value (e.g. {@code message},
 * {@code stack_trace}, MDC values).
 */
public class SensitiveDataValueMasker implements ValueMasker {

    private final SensitiveDataMasker masker;

    public SensitiveDataValueMasker(SensitiveDataMasker masker) {
        this.masker = masker;
    }

    @Override
    public Object mask(TokenStreamContext context, Object value) {
        String fieldName = fieldName(context);
        if (value instanceof CharSequence text) {
            String original = text.toString();
            String masked = masker.maskValue(fieldName, original);
            return original.equals(masked) ? null : masked;
        }
        if (value instanceof Number number && fieldName != null && masker.classifyKey(fieldName).isPresent()) {
            String original = number.toString();
            String masked = masker.maskValue(fieldName, original);
            return original.equals(masked) ? null : masked;
        }
        return null;
    }

    private static String fieldName(TokenStreamContext context) {
        if (context == null) {
            return null;
        }
        // array elements inherit the name of the field holding the array, e.g. "emails": ["a@b.pl"]
        TokenStreamContext named = context.inArray() ? context.getParent() : context;
        return named == null ? null : named.currentName();
    }
}
