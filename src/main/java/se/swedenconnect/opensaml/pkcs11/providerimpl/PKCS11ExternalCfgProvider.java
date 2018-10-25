/*
 * Copyright 2017-2018 Swedish Agency for Digital Government
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
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11ProvidedCfgConfiguration;
import se.swedenconnect.opensaml.pkcs11.PKCS11Provider;
import sun.security.pkcs11.SunPKCS11;

import java.io.File;
import java.io.FileInputStream;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * PKCS#11 provider for the case when provider configuration is provided as external files.
 *
 * @author Stefan Santesson (stefan@aaa-sec.com)
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
@SuppressWarnings("restriction")
public class PKCS11ExternalCfgProvider implements PKCS11Provider {

    /**
     * Class logger.
     */
    private final Logger LOG = LoggerFactory.getLogger(PKCS11ExternalCfgProvider.class);

    /**
     * The pkcs11 library on the host to use.
     */
    private final List<String> externalCfgPathList;


    /**
     * The provider name. See {@link #getProviderNameList()}.
     */
    private List<String> providerNameList;

    /**
     * Constructor for setting up the provider
     *
     * @param configuration Configuration data object.
     */
    public PKCS11ExternalCfgProvider(PKCS11ProvidedCfgConfiguration configuration) {
        this(configuration.getConfigLocationList());
    }

    /**
     * Constructor setting up the provider.
     *
     * @param externalCfgPathList The list of configuration files to be used to load PKCS#11 providers.
     */
    public PKCS11ExternalCfgProvider(List<String> externalCfgPathList) {
        if (externalCfgPathList == null && externalCfgPathList.isEmpty()) {
            throw new IllegalArgumentException("List of PKCS#11 provider cfg files must not be empty");
        }
        this.externalCfgPathList = externalCfgPathList;
        this.providerNameList = new ArrayList<>();

        for (String cfgPath:externalCfgPathList) {
            // Load provider
            try {
                Provider pkcs11Provider = new SunPKCS11(new FileInputStream(new File(cfgPath)));
                Security.addProvider(pkcs11Provider);
                providerNameList.add(pkcs11Provider.getName());
                LOG.info("Added provider {}", pkcs11Provider.getName());
            } catch (Exception ex) {
                LOG.error("Exception {} caught while loading provider with cfg file {} - Msg: {}", ex.getClass().getName(), cfgPath, ex.getMessage(), ex);
                throw new IllegalArgumentException("Unable to load provider configuration");
            }
        }
    }

    /**
     * Returns the provider name which is "SunPKCS11-<name>".
     */
    @Override
    public List<String> getProviderNameList() {
        return this.providerNameList;
    }
}
