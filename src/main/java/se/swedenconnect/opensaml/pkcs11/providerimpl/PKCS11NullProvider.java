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
package se.swedenconnect.opensaml.pkcs11.providerimpl;

import se.swedenconnect.opensaml.pkcs11.PKCS11Provider;

import java.util.ArrayList;
import java.util.List;

/**
 * Null PKCS#11 provider.
 *
 * @author Stefan Santesson (stefan@idsec.se)
 * @author Martin Lindström (martin@idsec.se)
 */
public class PKCS11NullProvider implements PKCS11Provider {

  /** {@inheritDoc} */
  @Override
  public List<String> getProviderNameList() {
    return new ArrayList<>();
  }
}
