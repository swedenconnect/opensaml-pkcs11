/*
 * Copyright 2018 Sweden Connect
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
package se.swedenconnect.opensaml.pkcs11.credential;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

import org.opensaml.security.x509.BasicX509Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This credential class extends the OpenSAML {@link BasicX509Credential} and provides an auto-reloadable credential for
 * PKCS#11 keys.
 * <p>
 * The class stores the necessary data to reload the key in case the connection to the key in the PKCS"11 token has been
 * disrupted or lost.
 * <p>
 * Each time the private key is read from this credential, the private key reference is tested. If the private key can
 * not be used, an attempt to reload the key is made.
 *
 * @author Stefan Santesson (stefan@idsec.se)
 * @author Martin Lindström (martin@idsec.se)
 */
public class PKCS11Credential extends BasicX509Credential {

    /**
     * The class logger instance.
     */
    private final Logger LOG = LoggerFactory.getLogger(PKCS11Credential.class);
    private static final Random RNG = new Random();

    private List<String> providerNameList;
    protected  Map<String, PrivateKey> privateKeyMap;
    private String alias;
    private String pin;
    private String currentKeyProvider;
    private CustomKeyExtractor customKeyExtractor;

    /**
     * Initializes the PKCS#11 credential.
     *
     * @param entityCertificate  The entity certificate for this credential
     * @param providerNameList   The name of the security provider holding the private key object
     * @param alias             The alias of the private key
     * @param customKeyExtractor A custom function for extracting the private key from the provider
     * @throws UnrecoverableKeyException if the private key can not be recovered
     * @throws NoSuchAlgorithmException  if the selected algorithm is not supported
     * @throws KeyStoreException         general keystore exception
     * @throws NoSuchProviderException   if no provider for PKCS11 is available
     * @throws IOException               general IO errors
     * @throws Exception                 general errors
     */
    public PKCS11Credential(X509Certificate entityCertificate, List<String> providerNameList, String alias, CustomKeyExtractor customKeyExtractor) throws Exception {
        this(entityCertificate, providerNameList, alias, null, customKeyExtractor);
    }

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
     * @throws Exception                 general errors
     */
    public PKCS11Credential(X509Certificate entityCertificate, List<String> providerNameList, String alias, String pin) throws Exception {
        this(entityCertificate,providerNameList,alias,pin,null);
    }

    /**
     * Initializes the PKCS#11 credential.
     *
     * @param entityCertificate  The entity certificate for this credential
     * @param providerNameList   The name of the security provider holding the private key object
     * @param alias              The alias of the private key
     * @param pin                The pin for the private key
     * @param customKeyExtractor A custom function for extracting the private key from the provider
     * @throws UnrecoverableKeyException if the private key can not be recovered
     * @throws NoSuchAlgorithmException  if the selected algorithm is not supported
     * @throws KeyStoreException         general keystore exception
     * @throws NoSuchProviderException   if no provider for PKCS11 is available
     * @throws IOException               general IO errors
     * @throws Exception                 general errors
     */
    private PKCS11Credential(X509Certificate entityCertificate, List<String> providerNameList, String alias, String pin, CustomKeyExtractor customKeyExtractor) throws Exception {
        super(entityCertificate);
        if (pin == null && customKeyExtractor == null){
            LOG.error("A pin or a valid CustomKeyExtractor implementation must be provided");
            throw new IllegalArgumentException("Null pin and CustomKeyExtractor");
        }
        if(customKeyExtractor!=null){
            LOG.info("Setting up PKCS11 Credential with custom key extractor");
        }
        this.providerNameList = providerNameList;
        this.alias = alias;
        this.pin = pin;
        this.customKeyExtractor = customKeyExtractor;
        this.loadPrivateKey();
        LOG.info("Initiated PKCS11 Credential");
    }

    /**
     * Attempts to load the private key from the specified Security provider.
     *
     * @throws UnrecoverableKeyException if the private key can not be recovered
     * @throws NoSuchAlgorithmException  if the selected algorithm is not supported
     * @throws KeyStoreException         general keystore exception
     * @throws NoSuchProviderException   if no provider for PKCS11 is available
     * @throws IOException               general IO errors
     * @throws Exception                 general errors
     */
    private void loadPrivateKey() throws Exception {
        privateKeyMap = new HashMap<>();
        for (String providerName : providerNameList) {
            try {
                PrivateKey privateKey = null;
                if (customKeyExtractor == null){
                    KeyStore keyStore = KeyStore.getInstance("PKCS11", providerName);
                    keyStore.load(null, this.pin.toCharArray());
                    privateKey = (PrivateKey) keyStore.getKey(this.alias, this.pin.toCharArray());
                } else {
                    privateKey = customKeyExtractor.getPrivateKey(providerName, alias);
                }
                if (privateKey != null) {
                    privateKeyMap.put(providerName, privateKey);
                    LOG.info("Loaded private key from PKCS11 provider: {}, alias: {}", providerName, alias);
                } else {
                    LOG.error("Failed to load private key from provider: {}, alias: {}", providerName, alias);
                }
            } catch (CertificateException e) {
                LOG.error("Unexpected certificate exception", e);
                throw new SecurityException(e);
            } catch (Exception e) {
                LOG.error("Error loading PKCS11 private key from device {} - {}", alias, e.getMessage());
                LOG.debug("", e);
                throw e;
            }

        }
        if (privateKeyMap.isEmpty()) {
            throw new UnrecoverableKeyException("No private key for alias: " + alias + ", was available from any specified provider");
        } else {
            setPrivateKey(privateKeyMap.get(getRandomProviderFromPool()));
        }
    }

    protected String getRandomProviderFromPool() {
        List<String> providersWithKey = privateKeyMap.keySet().stream().collect(Collectors.toList());
        currentKeyProvider = providersWithKey.get(RNG.nextInt(providersWithKey.size()));
        return currentKeyProvider;
    }

    /**
     * Overrides the default method to get the private key and adds a key test before the private key is extracted and
     * returned. This allows an attempt to reload the key in case the connection to the key was lost.
     *
     * @return The tested (and possibly reloaded) private key
     */
    @Override
    public synchronized PrivateKey getPrivateKey() {
        PrivateKey privateKey = this.testPrivateKey(getRandomProviderFromPool());
        setPrivateKey(privateKey);
        return privateKey;
    }

    /**
     * Tests if the private key is OK to use or else reloads the key.
     * <p>
     * The method is synchronized to avoid having several threads re-loading the same key.
     * </p>
     *
     * @param providerName the current provider with the key to test
     * @return the private key (possibly re-loaded)
     */
    private synchronized PrivateKey testPrivateKey(String providerName) {
        PrivateKey currentPrivateKey = privateKeyMap.get(providerName);
        try {
            Provider provider = Security.getProvider(providerName);
            String pkAlgo = currentPrivateKey.getAlgorithm();
            if ("RSA".equals(pkAlgo)) {
                Signature algo = Signature.getInstance("SHA256withRSA", provider);
                algo.initSign(currentPrivateKey);
            }
        } catch (Exception ex) {
            // This exception means that the private key no longer is attached and need to be reloaded.
            LOG.error("Private key is detached. Trying to reload the key");
            try {
                this.loadPrivateKey();
            } catch (Exception e) {
                LOG.error("Private key reload failed - {}", e.getMessage(), e);
            }
            return super.getPrivateKey();
        }
        return currentPrivateKey;
    }

    /**
     * Get the provider of the most recently selected private key.
     *
     * <p>Note: This method is mainly intended for logging purposes. It may not be thread safe to rely on this method
     * unless it is called from within a synchronized method after loading the private key.</p>
     *
     * @return the name of the provider of the most recently loaded private key
     */
    public String getCurrentKeyProvider() {
        return currentKeyProvider;
    }
}
