/*
 *  Copyright 2018 The shiro-root contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.apache.shiro.util;

import java.util.Arrays;

public final class ByteUtils {

  private ByteUtils() {
    // private utility class
  }

  /**
   * For security, sensitive information in array should be zeroed-out at end of use (SHIRO-349).
   * @param value An array holding sensitive data
   */
  public static void wipe(Object value) {
    if (value instanceof byte[]) {
      byte[] array = (byte[]) value;
      Arrays.fill(array, (byte) 0);
    } else if (value instanceof char[]) {
      char[] array = (char[]) value;
      Arrays.fill(array, '\u0000');
    }
  }

}
