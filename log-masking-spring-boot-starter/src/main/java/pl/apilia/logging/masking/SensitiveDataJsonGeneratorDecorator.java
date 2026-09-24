package pl.apilia.logging.masking;

import ch.qos.logback.core.Context;
import ch.qos.logback.core.spi.ContextAware;
import ch.qos.logback.core.spi.ContextAwareBase;
import ch.qos.logback.core.status.Status;
import net.logstash.logback.mask.MaskingJsonGeneratorDecorator;

/**
 * JSON log masking for {@code logstash-logback-encoder}, configured from the same settings as the text converters.
 * <ul>
 *     <li>credential fields are masked by exact field name (path masks, O(1), no regex),</li>
 *     <li>other values go through {@link SensitiveDataValueMasker} (key-type aware partial masking + value scanning).</li>
 * </ul>
 * Additional {@code <path>}/{@code <value>} entries can still be declared in {@code logback-spring.xml}.
 */
public class SensitiveDataJsonGeneratorDecorator extends MaskingJsonGeneratorDecorator implements ContextAware {

    private final ContextAwareBase contextAware = new ContextAwareBase(this);
    private boolean maskersRegistered;

    public SensitiveDataJsonGeneratorDecorator() {
        setDefaultMask(SensitiveDataMasker.MASK);
    }

    @Override
    public synchronized void start() {
        if (!maskersRegistered) {
            SensitiveDataMasker masker = new SensitiveDataMasker(MaskingSettings.fromContext(getContext()));
            if (masker.isEnabled()) {
                if (masker.settings().maskCredentials()) {
                    addPaths(String.join(",", SensitiveDataMasker.CREDENTIAL_FIELD_NAMES));
                }
                addValueMasker(new SensitiveDataValueMasker(masker));
            } else {
                addWarn("Log masking is disabled - JSON logs are written without masking");
            }
            maskersRegistered = true;
        }
        super.start();
    }

    @Override
    public void setContext(Context context) {
        contextAware.setContext(context);
    }

    @Override
    public Context getContext() {
        return contextAware.getContext();
    }

    @Override
    public void addStatus(Status status) {
        contextAware.addStatus(status);
    }

    @Override
    public void addInfo(String msg) {
        contextAware.addInfo(msg);
    }

    @Override
    public void addInfo(String msg, Throwable ex) {
        contextAware.addInfo(msg, ex);
    }

    @Override
    public void addWarn(String msg) {
        contextAware.addWarn(msg);
    }

    @Override
    public void addWarn(String msg, Throwable ex) {
        contextAware.addWarn(msg, ex);
    }

    @Override
    public void addError(String msg) {
        contextAware.addError(msg);
    }

    @Override
    public void addError(String msg, Throwable ex) {
        contextAware.addError(msg, ex);
    }
}
