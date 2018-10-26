/*
 * Copyright 2018 Swedish Agency for Digital Government
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
package se.swedenconnect.opensaml.pkcs11.configuration;

import java.util.List;

/**
 * Configuration object for setting up PKCS#11 providers based on external cfg file.
 *
 * @author Stefan Santesson (stefan@idsec.se)
 * @author Martin Lindström (martin@idsec.se)*
 */
public class PKCS11ProvidedCfgConfiguration extends PKCS11ProviderConfiguration {

  /** A list of absolute paths to provided PKCS#11 provider configuration files. */
  private List<String> configLocationList;

  /**
   * Constructor.
   * 
   * @param configLocationList
   *          a list of configuration locations
   */
  public PKCS11ProvidedCfgConfiguration(List<String> configLocationList) {
    super();
    this.configLocationList = configLocationList;
  }

  /**
   * Getter for the list of PKCS#11 provider configuration files.
   * 
   * @return List of PKCS#11 provider configuration files.
   */
  public List<String> getConfigLocationList() {
    return this.configLocationList;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("External cfg configuration ('%s')", String.join(",", this.configLocationList));
  }

}
