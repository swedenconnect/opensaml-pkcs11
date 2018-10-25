package se.swedenconnect.opensaml.pkcs11.providerimpl;

import se.swedenconnect.opensaml.pkcs11.PKCS11Provider;

import java.util.ArrayList;
import java.util.List;

/**
 * Null PKCS#11 provider
 *
 * @author Stefan Santesson (stefan@idsec.se)
 * @author Martin Lindström (martin@idsec.se)
 */
public class PKCS11NullProvider implements PKCS11Provider {

    public PKCS11NullProvider() {
    }

    @Override
    public List<String> getProviderNameList() {
        return new ArrayList<>();
    }
}
