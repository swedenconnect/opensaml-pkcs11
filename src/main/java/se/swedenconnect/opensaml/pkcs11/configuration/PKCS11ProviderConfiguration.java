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
package se.swedenconnect.opensaml.pkcs11.configuration;

import se.swedenconnect.opensaml.pkcs11.utils.StringUtils;

/**
 * Configuration class for setting up a PKCS#11 provider.
 * <p>
 * It is recommended to supply either slot (number) or slotListIndex, but not both, since if the index and slot supplied
 * does not match the device's view an error will occur.
 * </p>
 *
 * @author Stefan Santesson (stefan@idsec.se)
 * @author Martin Lindström (martin@idsec.se)
 */
public class PKCS11ProviderConfiguration {

  /** The pkcs11 library on the host to use. */
  protected String library;

  /** The name of the HSM slot. */
  protected String name;

  /** The slot number to use. */
  protected String slot;

  /** The slot index to use. */
  protected Integer slotListIndex;

  /** The maximum number och slots to use starting from the slotListIndex */
  protected Integer slotListIndexMaxRange;

  /**
   * Returns the path to the pkcs11 library on the host to use for the provider.
   * 
   * @return path to pkcs11 library
   */
  public String getLibrary() {
    return this.library;
  }

  /**
   * Assigns the path to the pkcs11 library on the host to use for the provider.
   * 
   * @param library
   *          path to pkcs11 library
   */
  public void setLibrary(String library) {
    this.library = StringUtils.getTrimmedIfNotNull(library);
  }

  /**
   * Returns the name of the HSM slot.
   * 
   * @return the name of the HSM slot
   */
  public String getName() {
    return this.name;
  }

  /**
   * Assigns the name of the HSM slot.
   * 
   * @param name
   *          the name of the HSM slot
   */
  public void setName(String name) {
    this.name = StringUtils.getTrimmedIfNotNull(name);
  }

  /**
   * Returns the slot number to use.
   * <p>
   * If {@code null} is returned, the device will use the slot entry identified by the active {@code slotListIndex}.
   * </p>
   * 
   * @return slot number, or {@code null}
   */
  public String getSlot() {
    return this.slot;
  }

  /**
   * Assigns the slot number to use.
   *
   * @param slot
   *          slot number
   */
  public void setSlot(String slot) {
    this.slot = StringUtils.getTrimmedIfNotNull(slot);
  }

  /**
   * Returns the slot list index to use.
   * <p>
   * If no slot list index is assigned ({@code null} is returned), the following logic applies:
   * </p>
   * <ul>
   * <li>If {@code slot} ({@link #getSlot()}) is {@code null}, the default slot list index 0 will be used.</li>
   * <li>If {@code slot} ({@link #getSlot()}) is non-null, the slot identified by this slot number will be used.</li>
   * </ul>
   * 
   * @return the slot list index
   */
  public Integer getSlotListIndex() {
    return this.slotListIndex;
  }

  /**
   * Assigns the slot list index to use.
   * 
   * @param slotListIndex
   *          slot list index
   */
  public void setSlotListIndex(Integer slotListIndex) {
    this.slotListIndex = slotListIndex != null ? (slotListIndex >= 0 ? slotListIndex : null) : null;
  }

  /**
   * Returns the maximum range of slot list indexes to traverse, starting from the active {@code slotListIndex}.
   * 
   * @return the maximum slot list index range
   */
  public Integer getSlotListIndexMaxRange() {
    return this.slotListIndexMaxRange;
  }

  /**
   * Assigns the slot list index max range
   *
   * @param slotListIndexMaxRange
   *          slot list index max range
   */
  public void setSlotListIndexMaxRange(Integer slotListIndexMaxRange) {
    this.slotListIndexMaxRange = slotListIndexMaxRange != null ? (slotListIndexMaxRange >= 0 ? slotListIndexMaxRange : null) : null;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("library='%s', name='%s', slot='%s', slotListIndex='%s'",
      this.library, this.name, this.slot, this.slotListIndex);
  }

}
