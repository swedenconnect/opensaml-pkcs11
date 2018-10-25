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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.opensaml.pkcs11.PKCS11Provider;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11ProviderConfiguration;
import se.swedenconnect.opensaml.pkcs11.utils.StringUtils;
import sun.security.pkcs11.SunPKCS11;

/**
 * PKCS#11 provider for the general case.
 *
 * @author Stefan Santesson (stefan@aaa-sec.com)
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
@SuppressWarnings("restriction")
public class GenericPKCS11Provider implements PKCS11Provider {

    /**
     * Class logger.
     */
    private final Logger LOG = LoggerFactory.getLogger(GenericPKCS11Provider.class);

    /**
     * The pkcs11 library on the host to use.
     */
    private final String library;

    /**
     * The name of the HSM slot.
     */
    private final String name;

    /**
     * The slot number to use.
     */
    private final String slot;

    /**
     * The slot index to use.
     */
    private final Integer slotListIndex;

    /**
     * The maximum number och slots to use starting from the slotListIndex
     */
    private final Integer slotListIndexMaxRange;

    /**
     * The provider name. See {@link #getProviderNameList()}.
     */
    private List<String> providerNameList;

    /**
     * Constructor setting up the provider.
     * <p>
     * It is recommended to supply either slot or slotListIndex, but not both, since if the index and slot
     * supplied does not match the device's view an error will occur.
     * </p>
     *
     * @param name          Name of the HSM slot. The Provider name will be "SunPKCS11-{slotName}".
     * @param library       The PKCS11 library on the host to use
     * @param slot          The slot number, or null for default (slotListIndex of 0)
     * @param slotListIndex The slotListIndex, or null for default (slotListIndex of 0)
     */
    public GenericPKCS11Provider(String name, String library, String slot, Integer slotListIndex, Integer slotListIndexMaxRange) {
        if (!StringUtils.hasText(name)) {
            throw new IllegalArgumentException("'name' must not be empty");
        }
        this.name = name.trim().replaceAll("\\s", "");
        this.library = library;
        this.providerNameList = new ArrayList<>();
        this.slot = slot;
        this.slotListIndex = slotListIndex;
        this.slotListIndexMaxRange = slotListIndexMaxRange;

        loadProviders();
    }

    public GenericPKCS11Provider(PKCS11ProviderConfiguration configuration) {
        this(configuration.getName(), configuration.getLibrary(), configuration.getSlot(), configuration.getSlotListIndex(), configuration.getSlotListIndexMaxRange());
    }

    /**
     * Loads the configured provider, or range of providers.
     * If a specific provider was requested, this method throws an Illegal argument Exception if the provider could not be loaded
     * If a range of providers was reqeusted, then the available providers will be loaded. No exception will be thrown in this case.
     */
    private void loadProviders() throws IllegalArgumentException {
        try {
            if (slotListIndexMaxRange == null && slotListIndex == null) {
                loadProvider(null);
                return;
            }
            if (slotListIndexMaxRange == null) {
                loadProvider(slotListIndex);
                return;
            }
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Failed to load the specified PKCS11 Provider");
        }

        for (int index = slotListIndex; index < slotListIndex + slotListIndexMaxRange; index++) {
            try {
                loadProvider(index);
            } catch (IllegalArgumentException ex) {
                LOG.info("Loaded {} out of a maximum of {} PKCS11 slots", index - slotListIndex, slotListIndexMaxRange);
                break;
            }
        }
    }

    /**
     * Loads the provider for a particular slot list index
     *
     * @param index The slot list index to load and the value {@code null} if default index is used.
     * @throws IllegalArgumentException This exception is thrown if the provider could not be loaded.
     */
    private void loadProvider(Integer index) throws IllegalArgumentException {
        // Load provider
        try {
            Provider pkcs11Provider = new SunPKCS11(getPkcs11ConfigStream(index));
            Security.addProvider(pkcs11Provider);
            providerNameList.add(pkcs11Provider.getName());
            LOG.info("Added provider {}", pkcs11Provider.getName());
        } catch (Exception ex) {
            LOG.error("Exception {} caught while loading provider with index {} - Msg: {}", ex.getClass().getName(), index, ex.getMessage(), ex);
            throw new IllegalArgumentException("PKCS11 slot index reached upper bound.");
        }
    }

    /**
     * Generates the PKCS11 configuration stream to load the security provider
     *
     * @return Configuration data input Stream
     */
    private InputStream getPkcs11ConfigStream(Integer index) {
        /*
         * library = /usr/lib/softhsm/libsofthsm2.so
         * name = SoftHsm
         * slot = 0
         * slotListIndex = 0
         */

        StringBuilder b = new StringBuilder();
        b.append("library = ")
                .append(library)
                .append("\n")
                .append("name = ")
                .append(getProviderNamePart(index))
                .append("\n");

        if (slot != null) {
            b.append("slot = ").append(slot).append("\n");
        }

        if (index != null) {
            b.append("slotListIndex = ").append(index).append("\n");
        }

        LOG.debug("Generated PKCS11 configuration: \n{}", b.toString());

        return new ByteArrayInputStream(b.toString().getBytes(StandardCharsets.UTF_8));
    }

    private String getProviderNamePart(Integer index) {
        if (index == null) {
            return name;
        }
        return name + "-" + String.valueOf(index);
    }

    /**
     * Returns the provider name which is "SunPKCS11-<slot-name>[-index]".
     */
    @Override
    public List<String> getProviderNameList() {
        return this.providerNameList;
    }
}
