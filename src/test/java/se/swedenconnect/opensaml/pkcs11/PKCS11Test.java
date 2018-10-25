package se.swedenconnect.opensaml.pkcs11;

import org.junit.Test;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11SoftHsmProviderConfiguration;
import se.swedenconnect.opensaml.pkcs11.providerimpl.GenericPKCS11Provider;
import se.swedenconnect.opensaml.pkcs11.providerimpl.PKCS11NullProvider;
import se.swedenconnect.opensaml.pkcs11.providerimpl.PKCS11SoftHsmProvider;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PKCS11Test {

    @Test
    public void testPKCS11ProviderBeanFactory() throws Exception {

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

        when(mockConfig.getKeyLocation()).thenReturn("/some-place-Er8/i879okLikjUy73/keyFiles");
        when(mockConfig.getPin()).thenReturn("1234");
        assertTrue(new PKCS11ProviderFactory(mockConfig).createInstance() instanceof PKCS11SoftHsmProvider);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPKCS11ProviderBeanFactoryException() throws Exception {
        PKCS11SoftHsmProviderConfiguration mockConfig = mock(PKCS11SoftHsmProviderConfiguration.class);

        //Test that non-existing lib causes an exception.
        when(mockConfig.getName()).thenReturn("Name");
        when(mockConfig.getLibrary()).thenReturn("/some-place-Er8/i879okLikjUy73/lib.so");
        when(mockConfig.getSlotListIndex()).thenReturn(null);
        when(mockConfig.getSlotListIndexMaxRange()).thenReturn(null);
        new PKCS11ProviderFactory(mockConfig).createInstance();
    }

}
