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

import org.apache.shiro.lang.util.ClassUtils;
import org.apache.shiro.lang.util.StringUtils;
import org.apache.shiro.lang.util.UnknownClassException;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * This default {@code HashFormatFactory} implementation heuristically determines a {@code HashFormat} class to
 * instantiate based on the input argument and returns a new instance of the discovered class.  The heuristics are
 * detailed in the {@link #getInstance(String) getInstance} method documentation.
 *
 * @since 1.2
 */
public class DefaultHashFormatFactory implements HashFormatFactory {

    private Map<String, String> formatClassNames; //id - to - fully qualified class name

    private Set<String> searchPackages; //packages to search for HashFormat implementations

    public DefaultHashFormatFactory() {
        this.searchPackages = new HashSet<String>();
        this.formatClassNames = new HashMap<String, String>();
    }

    /**
     * Returns a {@code hashFormatAlias}-to-<code>fullyQualifiedHashFormatClassNameImplementation</code> map.
     * <p/>
     * This map will be used by the {@link #getInstance(String) getInstance} implementation:  that method's argument
     * will be used as a lookup key to this map.  If the map returns a value, that value will be used to instantiate
     * and return a new {@code HashFormat} instance.
     * <h3>Defaults</h3>
     * Shiro's default HashFormat implementations (as listed by the {@link ProvidedHashFormat} enum) will
     * be searched automatically independently of this map.  You only need to populate this map with custom
     * {@code HashFormat} implementations that are <em>not</em> already represented by a {@code ProvidedHashFormat}.
     * <h3>Efficiency</h3>
     * Populating this map will be more efficient than configuring {@link #getSearchPackages() searchPackages},
     * but search packages may be more convenient depending on the number of {@code HashFormat} implementations that
     * need to be supported by this factory.
     *
     * @return a {@code hashFormatAlias}-to-<code>fullyQualifiedHashFormatClassNameImplementation</code> map.
     */
    public Map<String, String> getFormatClassNames() {
        return formatClassNames;
    }

    /**
     * Sets the {@code hash-format-alias}-to-{@code fullyQualifiedHashFormatClassNameImplementation} map to be used in
     * the {@link #getInstance(String)} implementation.  See the {@link #getFormatClassNames()} JavaDoc for more
     * information.
     * <h3>Efficiency</h3>
     * Populating this map will be more efficient than configuring {@link #getSearchPackages() searchPackages},
     * but search packages may be more convenient depending on the number of {@code HashFormat} implementations that
     * need to be supported by this factory.
     *
     * @param formatClassNames the {@code hash-format-alias}-to-{@code fullyQualifiedHashFormatClassNameImplementation}
     *                         map to be used in the {@link #getInstance(String)} implementation.
     */
    public void setFormatClassNames(Map<String, String> formatClassNames) {
        this.formatClassNames = formatClassNames;
    }

    /**
     * Returns a set of package names that can be searched for {@link HashFormat} implementations according to
     * heuristics defined in the {@link #getHashFormatClass(String, String) getHashFormat(packageName, token)} JavaDoc.
     * <h3>Efficiency</h3>
     * Configuring this property is not as efficient as configuring a {@link #getFormatClassNames() formatClassNames}
     * map, but it may be more convenient depending on the number of {@code HashFormat} implementations that
     * need to be supported by this factory.
     *
     * @return a set of package names that can be searched for {@link HashFormat} implementations
     * @see #getHashFormatClass(String, String)
     */
    public Set<String> getSearchPackages() {
        return searchPackages;
    }

    /**
     * Sets a set of package names that can be searched for {@link HashFormat} implementations according to
     * heuristics defined in the {@link #getHashFormatClass(String, String) getHashFormat(packageName, token)} JavaDoc.
     * <h3>Efficiency</h3>
     * Configuring this property is not as efficient as configuring a {@link #getFormatClassNames() formatClassNames}
     * map, but it may be more convenient depending on the number of {@code HashFormat} implementations that
     * need to be supported by this factory.
     *
     * @param searchPackages a set of package names that can be searched for {@link HashFormat} implementations
     */
    public void setSearchPackages(Set<String> searchPackages) {
        this.searchPackages = searchPackages;
    }

    public HashFormat getInstance(String in) {
        if (in == null) {
            return null;
        }

        HashFormat hashFormat = null;
        Class clazz = null;

        //NOTE: this code block occurs BEFORE calling getHashFormatClass(in) on purpose as a performance
        //optimization.  If the input arg is an MCF-formatted string, there will be many unnecessary ClassLoader
        //misses which can be slow.  By checking the MCF-formatted option, we can significantly improve performance
        if (in.startsWith(ModularCryptFormat.TOKEN_DELIMITER)) {
            //odds are high that the input argument is not a fully qualified class name or a format key (e.g. 'hex',
            //base64' or 'shiro1').  Try to find the key and lookup via that:
            String test = in.substring(ModularCryptFormat.TOKEN_DELIMITER.length());
            String[] tokens = test.split("\\" + ModularCryptFormat.TOKEN_DELIMITER);
            //the MCF ID is always the first token in the delimited string:
            String possibleMcfId = (tokens != null && tokens.length > 0) ? tokens[0] : null;
            if (possibleMcfId != null) {
                //found a possible MCF ID - test it using our heuristics to see if we can find a corresponding class:
                clazz = getHashFormatClass(possibleMcfId);
            }
        }

        if (clazz == null) {
            //not an MCF-formatted string - use the unaltered input arg and go through our heuristics:
            clazz = getHashFormatClass(in);
        }

        if (clazz != null) {
            //we found a HashFormat class - instantiate it:
            hashFormat = newHashFormatInstance(clazz);
        }

        return hashFormat;
    }

    /**
     * Heuristically determine the fully qualified HashFormat implementation class name based on the specified
     * token.
     * <p/>
     * This implementation functions as follows (in order):
     * <ol>
     * <li>See if the argument can be used as a lookup key in the {@link #getFormatClassNames() formatClassNames}
     * map.  If a value (a fully qualified class name {@link HashFormat HashFormat} implementation) is found,
     * {@link ClassUtils#forName(String) lookup} the class and return it.</li>
     * <li>
     * Check to see if the token argument is a
     * {@link ProvidedHashFormat} enum value.  If so, acquire the corresponding {@code HashFormat} class and
     * return it.
     * </li>
     * <li>
     * Check to see if the token argument is itself a fully qualified class name.  If so, try to load the class
     * and return it.
     * </li>
     * <li>If the above options do not result in a discovered class, search all all configured
     * {@link #getSearchPackages() searchPackages} using heuristics defined in the
     * {@link #getHashFormatClass(String, String) getHashFormatClass(packageName, token)} method documentation
     * (relaying the {@code token} argument to that method for each configured package).
     * </li>
     * </ol>
     * <p/>
     * If a class is not discovered via any of the above means, {@code null} is returned to indicate the class
     * could not be found.
     *
     * @param token the string token from which a class name will be heuristically determined.
     * @return the discovered HashFormat class implementation or {@code null} if no class could be heuristically determined.
     */
    protected Class getHashFormatClass(String token) {

        Class clazz = null;

        //check to see if the token is a configured FQCN alias.  This is faster than searching packages,
        //so we try this first:
        if (this.formatClassNames != null) {
            String value = this.formatClassNames.get(token);
            if (value != null) {
                //found an alias - see if the value is a class:
                clazz = lookupHashFormatClass(value);
            }
        }

        //check to see if the token is one of Shiro's provided FQCN aliases (again, faster than searching):
        if (clazz == null) {
            ProvidedHashFormat provided = ProvidedHashFormat.byId(token);
            if (provided != null) {
                clazz = provided.getHashFormatClass();
            }
        }

        if (clazz == null) {
            //check to see if 'token' was a FQCN itself:
            clazz = lookupHashFormatClass(token);
        }

        if (clazz == null) {
            //token wasn't a FQCN or a FQCN alias - try searching in configured packages:
            if (this.searchPackages != null) {
                for (String packageName : this.searchPackages) {
                    clazz = getHashFormatClass(packageName, token);
                    if (clazz != null) {
                        //found it:
                        break;
                    }
                }
            }
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
        return (HashFormat) ClassUtils.newInstance(clazz);
    }
}
