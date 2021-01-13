/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.crypto.hash;

import org.apache.shiro.lang.codec.Base64;
import org.apache.shiro.lang.codec.Hex;

/**
 * Generates an MD5 Hash (RFC 1321) from a given input <tt>source</tt> with an optional <tt>salt</tt> and
 * hash iterations.
 * <p/>
 * See the {@link SimpleHash SimpleHash} parent class JavaDoc for a detailed explanation of Hashing
 * techniques and how the overloaded constructors function.
 *
 * @since 0.9
 * @deprecated since 2.0.0, will throw exceptions in 2.1.0 and to be removed in 2.2.0.
 */
@Deprecated
public class Md5Hash extends SimpleHash {

    //TODO - complete JavaDoc

    public static final String ALGORITHM_NAME = "MD5";
    private static final long serialVersionUID = -1297357676456275955L;

    public Md5Hash() {
        super(ALGORITHM_NAME);
    }

    public Md5Hash(Object source) {
        super(ALGORITHM_NAME, source);
    }

    public Md5Hash(Object source, Object salt) {
        super(ALGORITHM_NAME, source, salt);
    }

    public Md5Hash(Object source, Object salt, int hashIterations) {
        super(ALGORITHM_NAME, source, salt, hashIterations);
    }

    public static Md5Hash fromHexString(String hex) {
        Md5Hash hash = new Md5Hash();
        hash.setBytes(Hex.decode(hex));
        return hash;
    }

    public static Md5Hash fromBase64String(String base64) {
        Md5Hash hash = new Md5Hash();
        hash.setBytes(Base64.decode(base64));
        return hash;
    }
}
