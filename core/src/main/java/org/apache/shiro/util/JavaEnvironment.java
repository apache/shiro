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
package org.apache.shiro.util;

/**
 * Internal helper class used to find the Java/JDK version
 * that Shiro is operating within, to allow for automatically
 * adapting to the present platform's capabilities.
 *
 * <p>Note that Shiro does not support 1.2 or earlier JVMs - only 1.3 and later.
 *
 * <p><em>This class was borrowed and heavily based upon a nearly identical version found in
 * the <a href="http://www.springframework.org/">Spring Framework</a>, with minor modifications.
 * The original author names and copyright (Apache 2.0) has been left in place.  A special
 * thanks to Rod Johnson, Juergen Hoeller, and Rick Evans for making this available.</em>
 *
 * @since 0.2
 */
public abstract class JavaEnvironment {

    /**
     * Constant identifying the 1.3.x JVM (JDK 1.3).
     */
    public static final int JAVA_13 = 0;

    /**
     * Constant identifying the 1.4.x JVM (J2SE 1.4).
     */
    public static final int JAVA_14 = 1;

    /**
     * Constant identifying the 1.5 JVM (Java 5).
     */
    public static final int JAVA_15 = 2;

    /**
     * Constant identifying the 1.6 JVM (Java 6).
     */
    public static final int JAVA_16 = 3;

    /**
     * Constant identifying the 1.7 JVM.
     */
    public static final int JAVA_17 = 4;

    /** The virtual machine version, i.e. <code>System.getProperty("java.version");</code>. */
    private static final String version;

    /**
     * The virtual machine <em>major</em> version.  For example, with a <code>version</code> of
     * <code>1.5.6_10</code>, this would be <code>1.5</code>
     */
    private static final int majorVersion;

    /**
     * Static code initialization block that sets the
     * <code>version</code> and <code>majorVersion</code> Class constants
     * upon initialization.
     */
    static {
        version = System.getProperty("java.version");
        // version String should look like "1.4.2_10"
        if (version.indexOf("1.7.") != -1) {
            majorVersion = JAVA_17;
        } else if (version.indexOf("1.6.") != -1) {
            majorVersion = JAVA_16;
        } else if (version.indexOf("1.5.") != -1) {
            majorVersion = JAVA_15;
        } else if (version.indexOf("1.4.") != -1) {
            majorVersion = JAVA_14;
        } else {
            // else leave 1.3 as default (it's either 1.3 or unknown)
            majorVersion = JAVA_13;
        }
    }


    /**
     * Return the full Java version string, as returned by
     * <code>System.getProperty("java.version")</code>.
     *
     * @return the full Java version string
     * @see System#getProperty(String)
     */
    public static String getVersion() {
        return version;
    }

    /**
     * Get the major version code. This means we can do things like
     * <code>if (getMajorVersion() < JAVA_14)</code>.
     *
     * @return a code comparable to the JAVA_XX codes in this class
     * @see #JAVA_13
     * @see #JAVA_14
     * @see #JAVA_15
     * @see #JAVA_16
     * @see #JAVA_17
     */
    public static int getMajorVersion() {
        return majorVersion;
    }

    /**
     * Convenience method to determine if the current JVM is at least Java 1.4.
     *
     * @return <code>true</code> if the current JVM is at least Java 1.4
     * @see #getMajorVersion()
     * @see #JAVA_14
     * @see #JAVA_15
     * @see #JAVA_16
     * @see #JAVA_17
     */
    public static boolean isAtLeastVersion14() {
        return getMajorVersion() >= JAVA_14;
    }

    /**
     * Convenience method to determine if the current JVM is at least
     * Java 1.5 (Java 5).
     *
     * @return <code>true</code> if the current JVM is at least Java 1.5
     * @see #getMajorVersion()
     * @see #JAVA_15
     * @see #JAVA_16
     * @see #JAVA_17
     */
    public static boolean isAtLeastVersion15() {
        return getMajorVersion() >= JAVA_15;
    }
}
