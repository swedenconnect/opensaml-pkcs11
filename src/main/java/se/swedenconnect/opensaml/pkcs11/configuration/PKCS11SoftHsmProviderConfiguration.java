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

import se.swedenconnect.opensaml.pkcs11.utils.StringUtils;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Configuration class for setting up SoftHSM.
 *
 * @author Stefan Santesson (stefan@idsec.se)
 * @author Martin Lindström (martin@idsec.se)
 */
public class PKCS11SoftHsmProviderConfiguration extends PKCS11ProviderConfiguration {

  /** The location of the keys and certificates that the provider should load. */
  private List<SoftHsmCredentialConfiguration> credentialConfigurationList;

  /** The PIN to unlock the private key. */
  private String pin;

  /**
   * Returns the cofniguration data for keys and certificates that should be loaded by the SoftHSM provider.
   * 
   * @return list of soft HSM credential configurations
   */
  public List<SoftHsmCredentialConfiguration> getCredentialConfigurationList() {
    return credentialConfigurationList;
  }

  /**
   * Assigns the directory containing the keys and certificates that should be loaded by the SoftHSM provider.
   * 
   * @param credentialConfigurationList
   *          list of soft HSM credential configurations
   */
  public void setCredentialConfigurationList(List<SoftHsmCredentialConfiguration> credentialConfigurationList) {
    this.credentialConfigurationList = credentialConfigurationList;
  }

  /**
   * Returns the PIN needed to write the key.
   * 
   * @return PIN for writing key
   */
  public String getPin() {
    return this.pin;
  }

  /**
   * Assigns the PIN needed to write the key.
   * 
   * @param pin
   *          PIN for writing key
   */
  public void setPin(String pin) {
    this.pin = StringUtils.getTrimmedIfNotNull(pin);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("%s, keyLocation='%s', pin='*****'", super.toString(), String.join(", ", credentialConfigurationList.stream()
      .map(sc -> sc.toString())
      .collect(Collectors.toList())));
  }

}
