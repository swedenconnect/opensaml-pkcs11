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

import org.junit.Test;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11ProvidedCfgConfiguration;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11SoftHsmProviderConfiguration;
import se.swedenconnect.opensaml.pkcs11.configuration.SoftHsmCredentialConfiguration;
import se.swedenconnect.opensaml.pkcs11.providerimpl.GenericPKCS11Provider;
import se.swedenconnect.opensaml.pkcs11.providerimpl.PKCS11ExternalCfgProvider;
import se.swedenconnect.opensaml.pkcs11.providerimpl.PKCS11NullProvider;
import se.swedenconnect.opensaml.pkcs11.providerimpl.PKCS11SoftHsmProvider;

import java.util.Arrays;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PKCS11Test {

    @Test
    public void testPKCS11ProviderFactory() throws Exception {

        PKCS11SoftHsmProviderConfiguration mockConfig = mock(PKCS11SoftHsmProviderConfiguration.class);

        //Test null configuration creates null providerimpl
        assertTrue(new PKCS11ProviderFactory(mockConfig).createInstance() instanceof PKCS11NullProvider);

        //Test that lib is required
        when(mockConfig.getName()).thenReturn("Name");
        assertTrue(new PKCS11ProviderFactory(mockConfig).createInstance() instanceof PKCS11NullProvider);
        //Test that name is required
        when(mockConfig.getName()).thenReturn(null);
        when(mockConfig.getLibrary()).thenReturn("/some-place-Er8/i879okLikjUy73/lib.so");
        assertTrue(new PKCS11ProviderFactory(mockConfig).createInstance() instanceof PKCS11NullProvider);

        when(mockConfig.getName()).thenReturn("Name");
        assertTrue(new PKCS11ProviderFactory(mockConfig).createInstance() instanceof GenericPKCS11Provider);

        when(mockConfig.getCredentialConfigurationList()).thenReturn(Arrays.asList(new SoftHsmCredentialConfiguration[]{}));
        when(mockConfig.getPin()).thenReturn("1234");
        assertTrue(new PKCS11ProviderFactory(mockConfig).createInstance() instanceof PKCS11SoftHsmProvider);

        //Test external configuration
        PKCS11ProvidedCfgConfiguration extCfgMockConfig = mock(PKCS11ProvidedCfgConfiguration.class);
        when(extCfgMockConfig.getConfigLocationList()).thenReturn(Arrays.asList(new String[]{}));
        assertTrue(new PKCS11ProviderFactory(extCfgMockConfig).createInstance() instanceof PKCS11ExternalCfgProvider);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPKCS11ProviderFactoryException() throws Exception {
        PKCS11SoftHsmProviderConfiguration mockConfig = mock(PKCS11SoftHsmProviderConfiguration.class);

        //Test that non-existing lib causes an exception.
        when(mockConfig.getName()).thenReturn("Name");
        when(mockConfig.getLibrary()).thenReturn("/some-place-Er8/i879okLikjUy73/lib.so");
        when(mockConfig.getCredentialConfigurationList()).thenReturn(Arrays.asList(new SoftHsmCredentialConfiguration("test","test","test")));
        when(mockConfig.getSlotListIndex()).thenReturn(null);
        when(mockConfig.getSlotListIndexMaxRange()).thenReturn(null);
        new PKCS11ProviderFactory(mockConfig).createInstance();
    }

}
