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
package se.swedenconnect.opensaml.pkcs11.utils;

/**
 * This class performs some simple String functions normally provided by the Spring framework.
 */
public class StringUtils {

  /**
   * Test if a String has a value and is not {@code null}.
   *
   * @param text
   *          string to be tested
   * @return {@code true} if the string is not {@code null} and not empty or just contains white space
   */
  public static boolean hasText(String text) {
    return text != null && !text.trim().isEmpty();
  }

  /**
   * Returns the trimmed string if present.
   *
   * @param text
   *          text to trim
   * @return the trimmed string or {@code null} if empty
   */
  public static String getTrimmedIfNotNull(String text) {
    return hasText(text) ? text.trim() : null;
  }

}
