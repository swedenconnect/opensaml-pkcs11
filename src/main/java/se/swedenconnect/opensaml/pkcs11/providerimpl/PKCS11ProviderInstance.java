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


import java.security.Provider;

/**
 * This inteface covers for the fact that instantiation of SunPKCS11 is performed differently in Java 8 and Java 9+.
 * In order to make this code compatible with both Java 8 and Java 9+ the code snippet used to create an instance of
 * a SunPKCS11 provider must be provided as an implementation of this interface.
 * <pre>{@code
 *  // Typical Java 8 implementation.
 *  Provider p11provider = new SunPKCS11(configInputStream);
 *
 *  // Typical java 9+ implementation
 *  // configData is either a file name or "--" + configDataString
 *  Provider p = Security.getProvider("SunPKCS11");
 *    p = p.configure(configData);}</pre>
 *
 */
public interface PKCS11ProviderInstance {

    /**
     * Create an instance of a SunPKCS11 provider
     * @param configData SunPKCS11 config data as a UTF-8 encoded String
     * @return A SunPKCS11 provider with loaded configuration.
     */
    Provider getProviderInstance(String configData);

}
