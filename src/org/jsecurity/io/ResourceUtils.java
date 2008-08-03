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
package org.jsecurity.io;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.util.ClassUtils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

/**
 * Static helper methods for loading resources.
 *
 * @author Jeremy Haile
 * @since 0.2
 */
public class ResourceUtils {

    /**
     * Resource path prefix that specifies to load from a classpath location, value is <b><code>classpath:</code></b>
     */
    public static final String CLASSPATH_PREFIX = "classpath:";
    /**
     * Resource path prefix that specifies to load from a url location, value is <b><code>url:</code></b>
     */
    public static final String URL_PREFIX = "url:";
    /**
     * Resource path prefix that specifies to load from a file location, value is <b><code>file:</code></b>
     */
    public static final String FILE_PREFIX = "file:";

    private static final Log log = LogFactory.getLog(ResourceUtils.class);


    /**
     * Prevent instantiation.
     */
    private ResourceUtils() {
    }

    /**
     * Returns <code>true</code> if the resource path is not null and starts with one of the recognized
     * resource prefixes ({@link #CLASSPATH_PREFIX CLASSPATH_PREFIX}, 
     * {@link #URL_PREFIX URL_PREFIX}, or {@link #FILE_PREFIX FILE_PREFIX}), <code>false</code> otherwise.
     *
     * @param resourcePath the resource path to check
     * @return <code>true</code> if the resource path is not null and starts with one of the recognized
     * resource prefixes, <code>false</code> otherwise.
     * @since 0.9
     */
    public static boolean hasResourcePrefix(String resourcePath) {
        return resourcePath != null &&
                (resourcePath.startsWith(CLASSPATH_PREFIX) ||
                        resourcePath.startsWith(URL_PREFIX) ||
                        resourcePath.startsWith(FILE_PREFIX));
    }

    /**
     * Returns <code>true</code> if the resource at the specified path exists, <code>false</code> otherwise.
     * @param resourcePath the path of the resource to check.
     * @return <code>true</code> if the resource at the specified path exists, <code>false</code> otherwise.
     * @since 0.9
     */
    public static boolean resourceExists(String resourcePath) {
        InputStream stream = null;
        boolean exists = false;

        try {
            stream = getInputStreamForPath(resourcePath);
            exists = true;
        } catch (IOException e) {
            stream = null;
        } finally {
            if (stream != null) {
                try {
                    stream.close();
                } catch (IOException ignored) {
                }
            }
        }

        return exists;
    }


    /**
     * Returns the InputStream for the resource represented by the specified path.
     *
     * <p>The supporting prefixes are defined as as *_PREFIX constants in this class.</p>
     *
     * @param resourcePath the String path representing the resource to obtain.
     * @return the InputStraem for the specified resource.
     * @throws IOException if there is a problem acquiring the resource at the specified path.
     */
    public static InputStream getInputStreamForPath(String resourcePath) throws IOException {

        InputStream is;
        if (resourcePath.startsWith(CLASSPATH_PREFIX)) {
            is = loadFromClassPath(stripPrefix(resourcePath));

        } else if (resourcePath.startsWith(URL_PREFIX)) {
            is = loadFromUrl(stripPrefix(resourcePath));

        } else if (resourcePath.startsWith(FILE_PREFIX)) {
            is = loadFromFile(stripPrefix(resourcePath));

        } else {
            is = loadFromFile(resourcePath);
        }

        if (is == null) {
            throw new IOException("Resource [" + resourcePath + "] could not be found.");
        }

        return is;
    }

    private static InputStream loadFromFile(String path) throws IOException {

        if (log.isDebugEnabled()) {
            log.debug("Opening file [" + path + "]...");
        }

        return new FileInputStream(path);
    }

    private static InputStream loadFromUrl(String urlPath) throws IOException {

        if (log.isDebugEnabled()) {
            log.debug("Opening url [" + urlPath + "]...");
        }

        URL url = new URL(urlPath);
        return url.openStream();
    }

    private static InputStream loadFromClassPath(String path) {
        if (log.isDebugEnabled()) {
            log.debug("Opening resource from class path [" + path + "]...");
        }

        return ClassUtils.getResourceAsStream(path);
    }

    private static String stripPrefix(String resourcePath) {
        return resourcePath.substring(resourcePath.indexOf(":") + 1);
    }

    public static void close(InputStream is) {
        if (is != null) {
            try {
                is.close();
            } catch (IOException e) {
                log.warn("Error closing input stream.", e);
            }
        }
    }
}
