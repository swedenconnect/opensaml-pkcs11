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
package se.swedenconnect.opensaml.pkcs11;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11ProvidedCfgConfiguration;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11ProviderConfiguration;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11SoftHsmProviderConfiguration;
import se.swedenconnect.opensaml.pkcs11.providerimpl.GenericPKCS11Provider;
import se.swedenconnect.opensaml.pkcs11.providerimpl.PKCS11NullProvider;
import se.swedenconnect.opensaml.pkcs11.providerimpl.PKCS11SoftHsmProvider;
import se.swedenconnect.opensaml.pkcs11.providerimpl.PKCS11ExternalCfgProvider;

/**
 * Factory class for creating an instance of a PKCS11 provider based on provided configuration data.
 *
 * @author Stefan Santesson (stefan@idsec.se)
 * @author Martin Lindström (martin@idsec.se)
 */
public class PKCS11ProviderFactory {

  /** Class logger. */
  private final Logger log = LoggerFactory.getLogger(PKCS11ProviderFactory.class);

  /** The configuration. */
  private PKCS11ProviderConfiguration configuration;

  /**
   * Constructor.
   * 
   * @param configuration
   *          the provider configuration
   */
  public PKCS11ProviderFactory(PKCS11ProviderConfiguration configuration) {
    this.configuration = configuration;
  }

  /**
   * Creates a {@code PKCS11Provider} instance given the factory's configuration.
   * 
   * @return a {@code PKCS11Provider}
   * @throws Exception
   *           for errors creating the instance
   */
  public PKCS11Provider createInstance() throws Exception {

    if (PKCS11ProvidedCfgConfiguration.class.isInstance(this.configuration)) {
      PKCS11ProvidedCfgConfiguration providedCfgConfig = PKCS11ProvidedCfgConfiguration.class.cast(this.configuration);
      if (providedCfgConfig.getConfigLocationList() != null) {
        log.info("Found PKCS11 configuration for externally provided cfg files for PKCS11 token/HSM");
        return new PKCS11ExternalCfgProvider(providedCfgConfig);
      }
    }

    if (this.configuration.getLibrary() == null || this.configuration.getName() == null) {
      // This is not a failure. It is perfectly OK to not configure any PKCS11 provider at all.
      log.info("No valid PKCS11 configuration found");
      return new PKCS11NullProvider();
    }

    if (PKCS11SoftHsmProviderConfiguration.class.isInstance(this.configuration)) {
      PKCS11SoftHsmProviderConfiguration softHsmConfig = PKCS11SoftHsmProviderConfiguration.class.cast(this.configuration);
      if (softHsmConfig.getCredentialConfigurationList() != null && softHsmConfig.getPin() != null) {
        log.info("Found PKCS11 configuration for SoftHSM");
        return new PKCS11SoftHsmProvider(softHsmConfig);
      }
    }
    log.info("Found PKCS11 configuration for PKCS11 token/HSM");
    return new GenericPKCS11Provider(this.configuration);
  }

}
