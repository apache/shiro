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
package org.jsecurity.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.codec.Base64;
import org.jsecurity.codec.CodecSupport;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Utility class for composing and decomposing hashed {@link javax.servlet.http.Cookie} content
 * using a {@link MessageDigest}.
 *
 * @see MessageDigest
 *
 * @author Zach Bailey
 * @since  0.9
 */
public class HashedCookieComposer {

    public static final String PIECE_DELIMETER = ":";

    protected final transient Log log = LogFactory.getLog(getClass());

    private final MessageDigest md;

    /**
     * Construct a new {@link HashedCookieComposer} instance which uses the given <code>digestAlgorithm</code> (such as
     * "SHA-1" or "MD5") and salts the digester with the specified <code>salt</code> bytes.
     *
     * @param digestAlgorithm algorithm to use when hashing.
     */
    public HashedCookieComposer(String digestAlgorithm) {
        try {
            md = MessageDigest.getInstance(digestAlgorithm);
        } catch (NoSuchAlgorithmException nsae) {
            throw new RuntimeException("Unable to instantiate CookieCrypter with the given digest algorithm: " + digestAlgorithm, nsae);
        }
    }

    /**
     * Determines if the given content is valid for this {@link HashedCookieComposer} by comparing the value of the hash
     * pulled from the given content to the value of the hash calculated by this {@link HashedCookieComposer} instance.
     *
     * @param content the delimited content of the cookie with the hash as the last token.
     * @param salt the salt to use when hashing the cookie.
     * @return false if the content is empty or if the hash in the content does not match the
     *      calculated hash.
     */
    public boolean isValidHashedContent(String content, byte[] salt) {
        //no content is invalid
        if (content == null || content.length() == 0 || content.trim().length() == 0)
            return false;

        //decompose the content into its parts, including the hash as the last value
        List<String> parts = decompose(content, true);

        //no content, same as above
        if (parts.isEmpty()) {
            return false;
        }

        //the hash specified in the content, possibly invalid
        String actualHash = parts.remove(parts.size()-1);

        //hash the first n-1 parts
        String expectedHash = hash(salt, parts.toArray(new String[parts.size()]) );

        //the hashes must be equal
        return expectedHash.equals(actualHash);
    }

    /**
     * Decomposes this cookie content string into its component tokens. Should only
     * be used after verifying the content of the cookie as valid by calling
     * {@link HashedCookieComposer#isValidHashedContent(String, byte[])}
     *
     * @param content the content of a cookie which was build using a similar instance of CookieCrypter
     * @return the decomposed cookie values not including the hash
     */
    public List<String> decompose(String content) {
        return decompose(content, false);
    }

    /**
     * Decomposes this cookie content string into its component tokens, optionally including
     * the hash as the last token. It is assumed the content was composed by a similar instance
     * of {@link HashedCookieComposer}
     *
     * @param content the content to be decomposed.
     * @param includeHash whether or not to include the hash
     * @return the decomposed cookie values, possibly including the hash as the last token
     */
    private List<String> decompose(String content, boolean includeHash) {
        if (content == null) {
            return Collections.emptyList();
        }

        String[] pieces = content.split(PIECE_DELIMETER);
        if (pieces.length == 0) {
            return Collections.emptyList();
        }

        List<String> toRet = Arrays.asList(pieces);
        if (!includeHash) {
            toRet.remove(toRet.size()-1);
        }
        return toRet;
    }

    /**
     * Composes hashed cookie content from the given pieces by concatenating each piece
     * together with the {@link HashedCookieComposer#PIECE_DELIMETER} and then calculating the
     * hash of the content with the digest algorithm this {@link HashedCookieComposer} was
     * constructed to use, placing that as the last token. The hash bytes are base64 encoded,
     * but the pieces are left as plain-text.
     *
     * @param pieces the pieces that should be combined into a single cookie
     * @param salt the salt to be used
     * @return
     */
    public String compose(List<String> pieces, byte[] salt) {
        StringBuilder sb = new StringBuilder();
        for (String piece : pieces) {
            sb.append(piece);
            sb.append(PIECE_DELIMETER);
        }

        sb.append(hash(salt, pieces.toArray(new String[pieces.size()])));
        return sb.toString();
    }

    /**
     * Hashes the given tokens through this {@link HashedCookieComposer}'s {@link MessageDigest}
     * after resetting and salting the digest and then Base64 encodes the resulting hash.
     *
     * @param salt the salt for hashing.
     * @param pieces the pieces to be encoded.
     * @return the resulting hash bytes that were encoded.
     */
    private String hash(byte[] salt, String... pieces) {
        md.reset();

        //salt it
        md.update(salt);

        //hash the pieces
        for (String piece : pieces) {
            md.update(CodecSupport.toBytes(piece));
        }

        //finalize the digest
        byte[] digestBytes = md.digest();

        //base64 encode the bytes
        return Base64.encodeToString(digestBytes);
    }

}
