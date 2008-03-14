/*
 * Copyright (C) 2005-2007 Jeremy Haile
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

/**
 * Static helper methods for loading resources.
 *
 * @since 0.2
 * @author Jeremy Haile
 */
public class ResourceUtils {

    public static final String CLASSPATH_PREFIX = "classpath:";
    public static final String URL_PREFIX = "url:";
    public static final String FILE_PREFIX = "file:";

    /**
     * Commons-logging logger
     */
    private final static transient Log logger = LogFactory.getLog( ResourceUtils.class );    


    /**
     * Prevent instantiation.
     */
    private ResourceUtils() { }


    public static InputStream getInputStreamForPath(String resourcePath) throws IOException {

        InputStream is;
        if( resourcePath.startsWith( CLASSPATH_PREFIX ) ) {
            is = loadFromClassPath( stripPrefix( resourcePath ) );

        } else if( resourcePath.startsWith( URL_PREFIX ) ) {
            is = loadFromUrl( stripPrefix( resourcePath ) );

        } else if( resourcePath.startsWith( FILE_PREFIX ) ) {
            is = loadFromFile( stripPrefix( resourcePath ) );

        } else {
            is = loadFromFile( resourcePath );
        }

        if( is == null ) {
            throw new IOException( "Resource [" + resourcePath + "] could not be found." );
        }

        return is;
    }

    private static InputStream loadFromFile(String path) throws IOException {

        if( logger.isDebugEnabled() ) {
            logger.debug( "Opening file [" + path + "]..." );
        }

        return new FileInputStream( path );
    }

    private static InputStream loadFromUrl(String urlPath) throws IOException {

        if( logger.isDebugEnabled() ) {
            logger.debug( "Opening url [" + urlPath + "]..." );
        }

        URL url = new URL(urlPath);
        return url.openStream();
    }

    private static InputStream loadFromClassPath(String path) {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();

        // Fall back to class loader for this class if no context class loader
        if( classLoader == null ) {
            classLoader = ResourceUtils.class.getClassLoader();
        }

        if( logger.isDebugEnabled() ) {
            logger.debug( "Opening resource from class path [" + path + "]..." );
        }

        return classLoader.getResourceAsStream( path );
    }

    private static String stripPrefix(String resourcePath) {
        return resourcePath.substring( resourcePath.indexOf( ":" ) + 1 );
    }

    public static void close(InputStream is) {
        if( is != null ) {
            try {
                is.close();
            } catch (IOException e) {
                logger.warn( "Error closing input stream.", e );
            }
        }
    }
}
