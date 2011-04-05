/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.authc.credential;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SaltedAuthenticationInfo;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.crypto.hash.*;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.util.SimpleByteSource;

import java.util.Arrays;

/**
 * Default implementation of the {@link PasswordService} interface.  Delegates to an internal (configurable)
 * {@link Hasher} instance.
 *
 * @since 1.2
 */
public class DefaultPasswordService implements PasswordService {

    private ConfigurableHasher hasher;

    private String storedCredentialsEncoding = "base64";

    public DefaultPasswordService() {
        this.hasher = new DefaultHasher();
        this.hasher.setHashAlgorithmName(Sha512Hash.ALGORITHM_NAME);
        //see http://www.katasoft.com/blog/2011/04/04/strong-password-hashing-apache-shiro:
        this.hasher.setHashIterations(200000);
    }

    public HashResponse hashPassword(ByteSource plaintextPassword) {
        byte[] plaintextBytes = plaintextPassword != null ? plaintextPassword.getBytes() : null;
        if (plaintextBytes == null || plaintextBytes.length == 0) {
            return null;
        }

        return this.hasher.computeHash(new SimpleHashRequest(plaintextPassword));
    }

    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {

        ByteSource publicSalt = null;
        if (info instanceof SaltedAuthenticationInfo) {
            publicSalt = ((SaltedAuthenticationInfo) info).getCredentialsSalt();
        }

        Hash tokenCredentialsHash = hashProvidedCredentials(token, publicSalt);
        byte[] storedCredentialsBytes = getCredentialsBytes(info);

        return Arrays.equals(tokenCredentialsHash.getBytes(), storedCredentialsBytes);
    }

    protected byte[] getCredentialsBytes(AuthenticationInfo info) {
        Object credentials = info.getCredentials();

        byte[] bytes = new BytesHelper().getBytes(credentials);

        if (this.storedCredentialsEncoding != null &&
                (credentials instanceof String || credentials instanceof char[])) {
            assertEncodingSupported(this.storedCredentialsEncoding);
            bytes = decode(bytes, this.storedCredentialsEncoding);
        }

        return bytes;
    }

    protected byte[] decode(byte[] storedCredentials, String encodingName) {
        if ("hex".equalsIgnoreCase(encodingName)) {
            return Hex.decode(storedCredentials);
        } else if ("base64".equalsIgnoreCase(encodingName) ||
                "base-64".equalsIgnoreCase(encodingName)) {
            return Base64.decode(storedCredentials);
        }
        throw new IllegalStateException("Unsupported encoding '" + encodingName + "'.");
    }

    protected Hash hashProvidedCredentials(AuthenticationToken token, ByteSource salt) {
        Object credentials = token.getCredentials();
        byte[] credentialsBytes = new BytesHelper().getBytes(credentials);
        ByteSource credentialsByteSource = new SimpleByteSource(credentialsBytes);

        HashRequest request = new SimpleHashRequest(credentialsByteSource, salt);

        HashResponse response = this.hasher.computeHash(request);

        return response.getHash();
    }

    /**
     * Returns {@code true} if the argument equals (ignoring case):
     * <ul>
     * <li>{@code hex}</li>
     * <li>{@code base64}</li>
     * <li>{@code base-64}</li>
     * </ul>
     * {@code false} otherwise.
     * <p/>
     * Subclasses should override this method as well as the {@link #decode(byte[], String)} method if other
     * encodings should be supported.
     *
     * @param encodingName the name of the encoding to check.
     * @return {@code }
     */
    protected boolean isEncodingSupported(String encodingName) {
        return "hex".equalsIgnoreCase(encodingName) ||
                "base64".equalsIgnoreCase(encodingName) ||
                "base-64".equalsIgnoreCase(encodingName);
    }


    protected void assertEncodingSupported(String encodingName) throws IllegalArgumentException {
        if (!isEncodingSupported(encodingName)) {
            String msg = "Unsupported encoding '" + encodingName + "'.  Please check for typos.";
            throw new IllegalArgumentException(msg);
        }
    }

    public ConfigurableHasher getHasher() {
        return hasher;
    }

    public void setHasher(ConfigurableHasher hasher) {
        this.hasher = hasher;
    }

    public void setStoredCredentialsEncoding(String storedCredentialsEncoding) {
        if (storedCredentialsEncoding != null) {
            assertEncodingSupported(storedCredentialsEncoding);
        }
        this.storedCredentialsEncoding = storedCredentialsEncoding;
    }

    //will probably be removed in Shiro 2.0.  See SHIRO-203:
    //https://issues.apache.org/jira/browse/SHIRO-203
    private static final class BytesHelper extends CodecSupport {
        public byte[] getBytes(Object o) {
            return toBytes(o);
        }
    }
}
