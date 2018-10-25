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
package se.swedenconnect.opensaml.pkcs11.providerimpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.opensaml.pkcs11.PKCS11Provider;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11SoftHsmProviderConfiguration;
import sun.security.pkcs11.SunPKCS11;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Utility class for loading keys from a key directory into a PKCS11 Soft HSM slot.
 * This utility class assumes the following conditions on the host:
 * <ul>
 * <li>Soft HSM version 2 is installed</li>
 * <li>The command line tool tool pkcs11-tool is installed</li>
 * <li>All keys and certificates are stored in a dedicated folder with the name convention:
 * Key="alias.key" and Certificate="alias.crt". The key and the certificate will then be imported
 * to the soft hsm so it can be imported to a key store under the specified alias.</li>
 * </ul>
 * <p>
 * In order to make its keys available to the Java keystore under a specified alias, the soft HSM must 
 * import both the private key and the certificate under the same ID and label.
 * </p>
 * <p>
 * This class utilises pkcs11-tool to initialize the HSM slot and to load keys and certificates into the soft HSM.
 * </p>
 * <p>
 * After import of keys in the folder. This class makes available the following information to support key import into
 * key stores:
 * <ul>
 * <li>Name of the Provider holding the keys (A SunPKCS11 provider). The name will be "SunPKCS11-{slotName}</></li>
 * <li>Lists of aliases of successfully imported keys and certificates</li>
 * <li>A Map of certificates imported</li>
 * </ul>
 * 
 * @author Stefan Santesson (stefan@aaa-sec.com)
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
@SuppressWarnings("restriction")
public class PKCS11SoftHsmProvider implements PKCS11Provider {

    /** Class logger. */
    private final Logger LOG = LoggerFactory.getLogger(PKCS11SoftHsmProvider.class);
    
    /** Random number generator. */
    private static final Random rnd = new SecureRandom(String.valueOf(System.currentTimeMillis()).getBytes());
    
    /** The PKCS#11 library location. */
    String lib;
    
    /** Security officer PIN. */
    String soPin;
    
    /** The PIN to unlock the private key. */
    String pin;
    
    /** PKCS#11 provider instance name. Is the name set as name parameter in the SunPKCS11 provider configuration. */
    String name;
    
    /** Location of keys and certificates. */
    String keyLocation;
    
    /** All aliases. */
    List<String> aliasList;
    
    File slotDir;
    
    /** The configuration provider name - SunPKCS11-<slot-name>. */
    String providerName;
    
    /** A mapping between aliases and certificates. */
    Map<String, X509Certificate> certificateMap;

    /**
     * The constructor checks the specified key folder and forms a list of aliases of keys that can be imported.
     *
     * @param keyLocation The location of the keys and certificates
     * @param name    The name of this provider instance that will be used also as label of the slot
     * @param lib         The PKCS11 library location on the host
     * @param pin         The soft HSM PIN
     */
    public PKCS11SoftHsmProvider(String keyLocation, String name, String lib, String pin) {
        this.keyLocation = keyLocation;
        this.name = name.trim().replaceAll("\\s", "");
        this.lib = lib;
        this.pin = pin;
        this.soPin = new BigInteger(24, rnd).toString();
        this.aliasList = new ArrayList<>();
        this.providerName = SUN_PROVIDER_PREFIX + this.name;
        this.certificateMap = new HashMap<>();

        if (keyLocation != null) {
            this.slotDir = new File(keyLocation);
        }
        if (this.slotDir == null || !this.slotDir.canRead()) {
            return;
        }

        // Extract the list of key files
        File[] keyFiles = slotDir.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return name.endsWith(".key");
            }
        });

        // Extract the alias name from the key file and check that there is a corresponding certificate file to form
        // The list of available aliases.
        aliasList = Arrays.stream(keyFiles)
                .map(file -> {
                    String fileNamename = file.getName();
                    String alias = fileNamename.substring(0, fileNamename.lastIndexOf("."));
                    File certFile = new File(slotDir, alias + ".crt");
                    if (certFile.canRead()) {
                        try {
                            X509Certificate cert = getCert(certFile);
                            certificateMap.put(alias, cert);
                            return alias;
                        } catch (Exception ex) {
                            LOG.error("Specified certificate file could not be parsed for alias: {}", alias);
                        }
                    }
                    return null;
                })
                .filter(alias -> alias != null)
                .collect(Collectors.toList());

        if (isSoftHsmNotInitialized()) {
            LOG.info("SoftHSM is not initialized - Loading keys into soft HSM");
            loadKeys();
        } 
        else {
            // Keys are already loaded into the SoftHsm.
            // Probable cause is a restart of the application on host with loaded keys
            // Just load Provider and exit
            LOG.info("SoftHSM already loaded. Just loading Provider - Skipping key import");
        }
        loadProvider();
    }
    
    public PKCS11SoftHsmProvider(PKCS11SoftHsmProviderConfiguration configuration) {
      this(configuration.getKeyLocation(), configuration.getName(), configuration.getLibrary(), configuration.getPin());
    }

    /**
     * Loads the keys into the Soft hsm and installs the security provider
     */
    private void loadKeys() {
        initKeySlot(0, name);
        for (int keyIndex = 0; keyIndex < aliasList.size(); keyIndex++) {
            String alias = aliasList.get(keyIndex);
            File keyFile = new File(slotDir, alias + ".key");
            File certFile = new File(slotDir, alias + ".crt");
            String id = new BigInteger("aaaa", 16).add(new BigInteger(String.valueOf(keyIndex))).toString(16);
            initKey(keyFile.getAbsolutePath(), certFile.getAbsolutePath(), alias, id);
        }
    }

    private void loadProvider() {
        // Load provider
        Provider pkcs11Provider = new SunPKCS11(getPkcs11ConfigStream());
        Security.addProvider(pkcs11Provider);
        LOG.info("Added provider {}", pkcs11Provider.getName());
    }

    private boolean isSoftHsmNotInitialized() {
        /*
           Test command: pkcs11-tool --module {lib} -T

           Response for not initialized:
             Slot 0 (0x0): SoftHSM slot ID 0x0
               token state:   uninitialized

           Response for initialized:
             Available slots:
             Slot 0 (0x5e498485): SoftHSM slot ID 0x5e498485
               token label        : softhsm
         */
        StringBuilder b = new StringBuilder();
        b.append("pkcs11-tool --module ").append(lib).append(" -T");
        LOG.debug("Executing shell command {}", b.toString());
        String console = executeCommand(b.toString());
        LOG.debug(console);
        boolean uninitialized = console.indexOf("Slot 0 (0x0)") > -1 && console.indexOf("token state:   uninitialized") > -1;
        LOG.info("Initialized state of PKCS11 SoftHsm: {}", uninitialized ? "uninitialized" : "initialized");
        return uninitialized;
    }

    /**
     * Performs the command line instructions to initialize a slot on the soft hsm
     *
     * @param slot  the number of the slot to initialize
     * @param label The label name of the slot after initialization.
     */
    private void initKeySlot(int slot, String label) {
        // pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --init-token --slot 0 --so-pin 0000 --init-pin --pin 1234 --label slot0
        StringBuilder b = new StringBuilder();
        b.append("pkcs11-tool --module ").append(lib)
                .append(" --init-token --slot ").append(slot)
                .append(" --so-pin ").append(soPin)
                .append(" --init-pin --pin ").append(pin)
                .append(" --label ").append(label);
        LOG.info("Initialized PKCS11 SoftHsm key slot {}", label);
        LOG.debug("Executing shell command {}", b.toString());
        String console = executeCommand(b.toString());
        LOG.debug(console);
    }

    /**
     * Performs the comman line instructions to load the key and certificate into the soft hsm slot.
     *
     * @param keyLocation  The path to the key file
     * @param certLocation The path to the certificate file
     * @param alias        The alias of the key and certificate
     * @param id           The id of the key and certificate
     */
    private void initKey(String keyLocation, String certLocation, String alias, String id) {
        // pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -p 1234 -l -w /root/key.pem -y privkey -a key1 -d aaaa --usage-sign --usage-decrypt
        // pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -p 1234 -l -w /opt/cert.crt -y cert -a key1 -d aaaa
        StringBuilder b = new StringBuilder();
        b.append("pkcs11-tool --module ").append(lib)
                .append(" -p ").append(pin)
                .append(" -l -w ").append(keyLocation)
                .append(" -y privkey -a ").append(alias)
                .append(" -d ").append(id)
                .append(" --usage-sign --usage-decrypt");
        LOG.debug("Executing shell command {}", b.toString());
        String console = executeCommand(b.toString());
        LOG.debug(console);

        b = new StringBuilder();
        b.append("pkcs11-tool --module ").append(lib)
                .append(" -p ").append(pin)
                .append(" -l -w ").append(certLocation)
                .append(" -y cert -a ").append(alias)
                .append(" -d ").append(id);
        LOG.debug("Executing shell command {}", b.toString());
        console = executeCommand(b.toString());
        LOG.debug(console);
        LOG.info("PKCS11 SoftHsm loaded with key and certificate for alias: {}", alias);
    }

    /**
     * Generates the PKCS11 configuration stream to load the security provider
     *
     * @return Configuration input stream
     */
    private InputStream getPkcs11ConfigStream() {
        /*
          library = /usr/lib/softhsm/libsofthsm2.so
          name = SoftHsm
          slotListIndex = 0
         */

        StringBuilder b = new StringBuilder();
        b.append("library = ").append(lib).append("\n")
                .append("name = ").append(name).append("\n");

        LOG.debug("Generated PKCS11 configuration: \n{}", b.toString());

        return new ByteArrayInputStream(b.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Execute a command line command on the host
     *
     * @param command The command to execute
     * @return The response from the host
     */
    private String executeCommand(String command) {

        StringBuffer output = new StringBuffer();

        Process p;
        try {
            p = Runtime.getRuntime().exec(command);
            p.waitFor();
            BufferedReader reader =
                    new BufferedReader(new InputStreamReader(p.getInputStream()));

            String line = "";
            while ((line = reader.readLine()) != null) {
                output.append(line + "\n");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return output.toString();
    }

    public static X509Certificate getCert(File certFile) throws CertificateException, IOException {
        try (InputStream inStream = new FileInputStream(certFile)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            return cert;
        }
    }

    /***
     * @return The list of key aliases
     */
    public List<String> getAliasList() {
        return aliasList;
    }

    /**
     * @return The name of the security provider
     */
    @Override
    public List<String> getProviderNameList() {
        return Arrays.asList(providerName);
    }

    /**
     * @return The map of loaded certificates having its alias as key
     */
    public Map<String, X509Certificate> getCertificateMap() {
        return certificateMap;
    }
}
