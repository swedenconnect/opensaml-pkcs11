/*
 * Copyright 2017-2018 E-legitimationsnämnden
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.opensaml.pkcs11.impl;

import org.opensaml.security.x509.BasicX509Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.opensaml.pkcs11.PKCS11Credential;

import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * This credential class extends the OpenSAML {@link BasicX509Credential} and provides simple credentials for
 * PKCS#11 keys based on one or more configured providers.
 * <p>
 * This is a simplified extension of the PKCS11Credential class, which do not attempt to reload the key in case the
 * connection to the key in the PKCS"11 token has been disrupted or lost.
 *
 * @author Stefan Santesson (stefan@aaa-sec.com)
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class PKCS11NoTestCredential extends PKCS11Credential {

    /**
     * The class logger instance.
     */
    private final Logger LOG = LoggerFactory.getLogger(PKCS11NoTestCredential.class);


    /**
     * Initializes the PKCS#11 credential.
     *
     * @param entityCertificate The entity certificate for this credential
     * @param providerNameList  The name of the security provider holding the private key object
     * @param alias             The alias of the private key
     * @param pin               The pin for the private key
     * @throws UnrecoverableKeyException if the private key can not be recovered
     * @throws NoSuchAlgorithmException  if the selected algorithm is not supported
     * @throws KeyStoreException         general keystore exception
     * @throws NoSuchProviderException   if no provider for PKCS11 is available
     * @throws IOException               general IO errors
     */
    public PKCS11NoTestCredential(X509Certificate entityCertificate, List<String> providerNameList, String alias, String pin) throws UnrecoverableKeyException,
            NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException {
        super(entityCertificate, providerNameList, alias, pin);
        LOG.info("Initiated PKCS11Credentials without private key testing prior to usage");
    }

    /**
     * Overrides the default method to get the private key and adds a key test before the private key is extracted and
     * returned. This allows an attempt to reload the key in case the connection to the key was lost.
     *
     * @return The tested (and possibly reloaded) private key
     */
    @Override
    public synchronized PrivateKey getPrivateKey() {
        PrivateKey privateKey = privateKeyMap.get(getRandomProviderFromPool());
        setPrivateKey(privateKey);
        return privateKey;
    }

}
