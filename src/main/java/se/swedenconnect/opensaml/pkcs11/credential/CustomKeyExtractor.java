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
package se.swedenconnect.opensaml.pkcs11.credential;

import java.security.PrivateKey;

/**
 * Interface for extracting the private key object under a specified alias from a registered provider under a specified name.
 */
public interface CustomKeyExtractor {

    /**
     * Interface for providing a custom method for extracting a private key handler object from a registered provider.
     *
     * @param providerName the name of the specified provider
     * @param alias the alias under which the key is stored
     * @return a PrivateKey handler object
     * @throws Exception general errors
     */
    PrivateKey getPrivateKey(String providerName, String alias) throws Exception;
}
