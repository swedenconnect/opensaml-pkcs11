package se.swedenconnect.opensaml.pkcs11.impl;

import se.swedenconnect.opensaml.pkcs11.PKCS11Provider;

import java.util.ArrayList;
import java.util.List;

public class PKCS11NullProvider implements PKCS11Provider {

    public PKCS11NullProvider() {
    }

    @Override
    public List<String> getProviderNameList() {
        return new ArrayList<>();
    }
}
