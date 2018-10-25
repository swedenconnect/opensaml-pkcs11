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
package se.swedenconnect.opensaml.pkcs11;

import se.swedenconnect.opensaml.pkcs11.utils.StringUtils;

/**
 * Configuration class for setting up SoftHSM.
 * 
 * @author Stefan Santesson (stefan@aaa-sec.com)
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class PKCS11SoftHsmProviderConfiguration extends PKCS11ProviderConfiguration {

  /** The location of the keys and certificates that the provider should load. */
  private String keyLocation;

  /** The PIN to unlock the private key. */
  private String pin;

  /**
   * Returns the directory containing the keys and certificates that should be loaded by the SoftHSM provider.
   * 
   * @return directory
   */
  public String getKeyLocation() {
    return this.keyLocation;
  }

  /**
   * Assigns the directory containing the keys and certificates that should be loaded by the SoftHSM provider.
   * 
   * @param keyLocation
   *          directory
   */
  public void setKeyLocation(String keyLocation) {
    this.keyLocation = StringUtils.getTrimmedIfNotNull(keyLocation);
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
    return String.format("%s, keyLocation='%s', pin='*****'", super.toString(), this.keyLocation);
  }

}
