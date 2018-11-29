package se.swedenconnect.opensaml.pkcs11.credential;

import java.security.PrivateKey;

public interface CustomKeyExtractor {
    PrivateKey getPrivateKey(String providerName, String alias, String pin);
}
