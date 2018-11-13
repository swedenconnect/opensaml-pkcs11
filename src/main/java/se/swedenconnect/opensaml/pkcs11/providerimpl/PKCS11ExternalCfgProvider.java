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
package se.swedenconnect.opensaml.pkcs11.providerimpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11ProvidedCfgConfiguration;
import se.swedenconnect.opensaml.pkcs11.PKCS11Provider;
import sun.security.pkcs11.SunPKCS11;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * PKCS#11 provider for the case when provider configuration is provided as external files.
 *
 * @author Stefan Santesson (stefan@idsec.se)
 * @author Martin Lindström (martin@idsec.se)
 */
@SuppressWarnings("restriction")
public class PKCS11ExternalCfgProvider implements PKCS11Provider {

  /** Class logger. */
  private final Logger LOG = LoggerFactory.getLogger(PKCS11ExternalCfgProvider.class);

  /** The provider names. See {@link #getProviderNameList()}. */
  private List<String> providerNameList;

  /**
   * Constructor for setting up the provider.
   *
   * @param configuration
   *          configuration data object
   */
  public PKCS11ExternalCfgProvider(PKCS11ProvidedCfgConfiguration configuration, PKCS11ProviderInstance providerInstance) {
    this(configuration.getConfigLocationList(), providerInstance);
  }

  /**
   * Constructor setting up the provider.
   *
   * @param externalCfgPathList
   *          The list of configuration files to be used to load PKCS#11 providers.
   */
  public PKCS11ExternalCfgProvider(List<String> externalCfgPathList, PKCS11ProviderInstance providerInstance) {
    if (externalCfgPathList == null) {
      throw new IllegalArgumentException("List of PKCS#11 provider cfg files must not be null");
    }
    this.providerNameList = new ArrayList<>();

    for (String cfgPath : externalCfgPathList) {
      try {
        String configStr = new String(Files.readAllBytes(Paths.get(cfgPath)), StandardCharsets.UTF_8);
        Provider pkcs11Provider = providerInstance.getProviderInstance(configStr);
        Security.addProvider(pkcs11Provider);
        this.providerNameList.add(pkcs11Provider.getName());
        LOG.info("Added provider {}", pkcs11Provider.getName());
      }
      catch (Exception ex) {
        LOG.error("Exception {} caught while loading provider with cfg file {} - Msg: {}", ex.getClass().getName(), cfgPath, 
          ex.getMessage(), ex);
        throw new IllegalArgumentException("Unable to load provider configuration");
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getProviderNameList() {
    return this.providerNameList;
  }
}
