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
package org.apache.shiro.crypto.hash.format;

import org.apache.shiro.util.ClassUtils;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.util.UnknownClassException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * This default {@code HashFormatFactory} implementation heuristically determines a {@code HashFormat} class to
 * instantiate based on the input argument and returns a new instance of the discovered class.  The heuristics are
 * detailed in the {@link #getInstance(String) getInstance} method documentation.j
 *
 * @since 1.2
 */
public class DefaultHashFormatFactory implements HashFormatFactory {

    private static final Logger log = LoggerFactory.getLogger(DefaultHashFormatFactory.class);

    private static final String DEFAULT_HASH_FORMAT_PACKAGE_NAME = HashFormat.class.getPackage().getName();

    private Map<String, String> formatClassNames; //id - to - fully qualified class name

    private Set<String> searchPackages;

    public DefaultHashFormatFactory() {
        this.searchPackages = new HashSet<String>();
        formatClassNames = new HashMap<String, String>();
        formatClassNames.put(Shiro1CryptFormat.ID, Shiro1CryptFormat.class.getName());
    }

    public Map<String, String> getFormatClassNames() {
        return formatClassNames;
    }

    public void setFormatClassNames(Map<String, String> formatClassNames) {
        this.formatClassNames = formatClassNames;
    }

    public Set<String> getSearchPackages() {
        return searchPackages;
    }

    public void setSearchPackages(Set<String> searchPackages) {
        this.searchPackages = searchPackages;
    }

    public HashFormat getInstance(String in) {
        if (in == null) {
            return null;
        }

        HashFormat hashFormat = null;

        Class clazz = getHashFormatClass(in);

        //The 'in' argument didn't result in a corresponding HashFormat class using our heuristics.
        //As a fallback, check to see if the argument is an MCF-formatted string.  If it is, odds are very high
        //that the MCF ID id is the lookup token we can use to find a corresponding HashFormat class:
        if (clazz == null && in.startsWith(ModularCryptFormat.TOKEN_DELIMITER)) {
            String test = in.substring(ModularCryptFormat.TOKEN_DELIMITER.length());
            String[] tokens = test.split("\\" + ModularCryptFormat.TOKEN_DELIMITER);
            //the MCF ID is always the first token in the delimited string:
            String possibleMcfId = (tokens != null && tokens.length > 0) ? tokens[0] : null;
            if (possibleMcfId != null) {
                //found a possible MCF ID - test it using our heuristics to see if we can find a corresponding class:
                clazz = getHashFormatClass(possibleMcfId);
            }
        }

        if (clazz != null) {
            //we found a HashFormat class - instantiate it:
            hashFormat = newHashFormatInstance(clazz);

            //do further compatibility testing if we can:
            if (hashFormat instanceof ParsableHashFormat) {
                //This is not really an efficient way to test for format compatibility, but
                //there is no other way that guarantees compatibility that I can think of at the moment.
                //perhaps an isCompatible method can be introduced?  The struggle I have with this is how do you
                //determine compatibility without parsing it fully?  If not fully parsed, then it truly can't be
                //guaranteed compatible - at which point, you might as well just parse the thing - L.H. 22 Nov 2011
                try {
                    ParsableHashFormat phf = (ParsableHashFormat)hashFormat;
                    phf.parse(in);
                    // no exception - must be a match:
                    return phf;
                } catch (RuntimeException re) {
                    log.debug("Candidate format instance of type [{}] is unable to " +
                            "parse formatted String [{}].  Ignoring.", clazz, in);
                    log.trace("HashFormat parsing caused exception: ", re);
                }
            }
        }

        return hashFormat;
    }

    /**
     * Heuristically determine the fully qualified HashFormat implementation class name based on the specified
     * token.
     * <p/>
     * This implementation functions as follows:
     * <p/>
     * All configured {@link #getSearchPackages() searchPackages} will be searched using heuristics defined in the
     * {@link #getHashFormatClass(String, String) getHashFormatClass(packageName, token)} method documentation (relaying
     * the {@code token} argument to that method for each configured package).
     * <p/>
     * If the class was not found in any configured {@code searchPackages}, the default
     * {@code org.apache.shiro.crypto.hash.format} package will be attempted as a final fallback.
     * </p>
     * If the class was not discovered in any of the {@code searchPackages} or in Shiro's default fallback package,
     * {@code null} is returned to indicate the class could not be found.
     *
     * @param token the string token from which a class name will be heuristically determined.
     * @return the discovered HashFormat class implementation or {@code null} if no class could be heuristically determined.
     */
    protected Class getHashFormatClass(String token) {

        //check to see if the token is a fully qualified class name:
        Class clazz = lookupHashFormatClass(token);

        if (clazz == null) {
            //check to see if the token is a FQCN alias:
            if (!CollectionUtils.isEmpty(this.formatClassNames)) {
                String value = this.formatClassNames.get(token);
                if (value != null) {
                    //found an alias - see if the value is a class:
                    clazz = lookupHashFormatClass(token);
                }
            }
        }

        if (clazz == null) {
            //token wasn't a FQCN or a FQCN alias - try searching in configured packages:
            if (!CollectionUtils.isEmpty(this.searchPackages)) {
                for (String packageName : this.searchPackages) {
                    clazz = getHashFormatClass(packageName, token);
                    if (clazz != null) {
                        //found it:
                        break;
                    }
                }
            }
        }

        if (clazz == null) {
            //couldn't find it in any configured search packages.  Try Shiro's default search package:
            clazz = getHashFormatClass(DEFAULT_HASH_FORMAT_PACKAGE_NAME, token);
        }

        if (clazz != null) {
            assertHashFormatImpl(clazz);
        }

        return clazz;
    }

    /**
     * Heuristically determine the fully qualified {@code HashFormat} implementation class name in the specified
     * package based on the provided token.
     * <p/>
     * The token is expected to be a relevant fragment of an unqualified class name in the specified package.
     * A 'relevant fragment' can be one of the following:
     * <ul>
     * <li>The {@code HashFormat} implementation unqualified class name</li>
     * <li>The prefix of an unqualified class name ending with the text {@code Format}.  The first character of
     * this prefix can be upper or lower case and both options will be tried.</li>
     * <li>The prefix of an unqualified class name ending with the text {@code HashFormat}.  The first character of
     * this prefix can be upper or lower case and both options will be tried.</li>
     * <li>The prefix of an unqualified class name ending with the text {@code CryptoFormat}.  The first character
     * of this prefix can be upper or lower case and both options will be tried.</li>
     * </ul>
     * <p/>
     * Some examples:
     * <table>
     * <tr>
     * <th>Package Name</th>
     * <th>Token</th>
     * <th>Expected Output Class</th>
     * <th>Notes</th>
     * </tr>
     * <tr>
     * <td>{@code com.foo.whatever}</td>
     * <td>{@code MyBarFormat}</td>
     * <td>{@code com.foo.whatever.MyBarFormat}</td>
     * <td>Token is a complete unqualified class name</td>
     * </tr>
     * <tr>
     * <td>{@code com.foo.whatever}</td>
     * <td>{@code Bar}</td>
     * <td>{@code com.foo.whatever.BarFormat} <em>or</em> {@code com.foo.whatever.BarHashFormat} <em>or</em>
     * {@code com.foo.whatever.BarCryptFormat}</td>
     * <td>The token is only part of the unqualified class name - i.e. all characters in front of the {@code *Format}
     * {@code *HashFormat} or {@code *CryptFormat} suffix.  Note that the {@code *Format} variant will be tried before
     * {@code *HashFormat} and then finally {@code *CryptFormat}</td>
     * </tr>
     * <tr>
     * <td>{@code com.foo.whatever}</td>
     * <td>{@code bar}</td>
     * <td>{@code com.foo.whatever.BarFormat} <em>or</em> {@code com.foo.whatever.BarHashFormat} <em>or</em>
     * {@code com.foo.whatever.BarCryptFormat}</td>
     * <td>Exact same output as the above {@code Bar} input example. (The token differs only by the first character)</td>
     * </tr>
     * </table>
     *
     * @param packageName the package to search for matching {@code HashFormat} implementations.
     * @param token       the string token from which a class name will be heuristically determined.
     * @return the discovered HashFormat class implementation or {@code null} if no class could be heuristically determined.
     */
    protected Class getHashFormatClass(String packageName, String token) {
        String test = token;
        Class clazz = null;
        String pkg = packageName == null ? "" : packageName;

        //1. Assume the arg is a fully qualified class name in the classpath:
        clazz = lookupHashFormatClass(test);

        if (clazz == null) {
            test = pkg + "." + token;
            clazz = lookupHashFormatClass(test);
        }

        if (clazz == null) {
            test = pkg + "." + StringUtils.uppercaseFirstChar(token) + "Format";
            clazz = lookupHashFormatClass(test);
        }

        if (clazz == null) {
            test = pkg + "." + token + "Format";
            clazz = lookupHashFormatClass(test);
        }

        if (clazz == null) {
            test = pkg + "." + StringUtils.uppercaseFirstChar(token) + "HashFormat";
            clazz = lookupHashFormatClass(test);
        }

        if (clazz == null) {
            test = pkg + "." + token + "HashFormat";
            clazz = lookupHashFormatClass(test);
        }

        if (clazz == null) {
            test = pkg + "." + StringUtils.uppercaseFirstChar(token) + "CryptFormat";
            clazz = lookupHashFormatClass(test);
        }

        if (clazz == null) {
            test = pkg + "." + token + "CryptFormat";
            clazz = lookupHashFormatClass(test);
        }

        if (clazz == null) {
            return null; //ran out of options
        }

        assertHashFormatImpl(clazz);

        return clazz;
    }

    protected Class lookupHashFormatClass(String name) {
        try {
            return ClassUtils.forName(name);
        } catch (UnknownClassException ignored) {
        }

        return null;
    }

    protected final void assertHashFormatImpl(Class clazz) {
        if (!HashFormat.class.isAssignableFrom(clazz) || clazz.isInterface()) {
            throw new IllegalArgumentException("Discovered class [" + clazz.getName() + "] is not a " +
                    HashFormat.class.getName() + " implementation.");
        }

    }

    protected final HashFormat newHashFormatInstance(Class clazz) {
        assertHashFormatImpl(clazz);
        return (HashFormat)ClassUtils.newInstance(clazz);
    }
}
