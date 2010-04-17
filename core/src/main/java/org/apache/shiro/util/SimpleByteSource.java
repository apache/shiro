/*
 * Copyright 2008 Les Hazlewood
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
package org.apache.shiro.util;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.Hex;

import java.util.Arrays;

/**
 * TODO - Class JavaDoc
 *
 * @author Les Hazlewood
 * @since Apr 12, 2010 2:35:19 PM
 */
public class SimpleByteSource implements ByteSource {

    private final byte[] bytes;

    public SimpleByteSource(byte[] bytes) {
        this.bytes = bytes;
    }

    public byte[] getBytes() {
        return this.bytes;
    }

    public String toHex() {
        return Hex.encodeToString(getBytes());
    }

    public String toBase64() {
        return Base64.encodeToString(getBytes());
    }

    public String toString() {
        return toBase64();
    }

    public int hashCode() {
        return toBase64().hashCode();
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof SimpleByteSource) {
            SimpleByteSource bs = (SimpleByteSource) o;
            return Arrays.equals(getBytes(), bs.getBytes());
        }
        return false;
    }
}
