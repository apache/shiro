/*
* Copyright (C) 2005 Jeremy Haile
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

package org.jsecurity;

import org.jsecurity.cache.CacheProvider;

import java.util.Properties;

/**
 * Configuration interface for standard JSecurity configuration information.
 * The source of this configuration is specific to the implementation.
 *
 * @since 0.2
 * @author Jeremy Haile
 */
public interface Configuration {

    /**
     * Returns a set of configuration properties associated with this
     * configuration instance.
     * @return the properties associated with this configuration instance.
     */
    Properties getProperties();

    /**
     * Determines whether or not the security context accessor should be cached.
     * <tt>True</tt> by default.
     * @return true if the security context accessor should be cached, false otherwise.
     */
    boolean isSecurityContextAccessorCached();

    /**
     * Returns the class name of the security context accessor implementation that should
     * be used to retrieve the security context at runtime.  The default value of this
     * is implementation specific.
     * @return the class name of the security context accessor implementation that should
     * be used to retrieve the security context at runtime.
     */
    String getSecurityContextAccessorClassName();

    /**
     * Determines whether authorization information related to user principals should be
     * cached by default.
     * @return true if the authorization information should be cached, false otherwise.
     */
    boolean isCacheAuthorizationInfo();

    /**
     * Provides the default cache provider that should be used by components requiring caching
     * in this configuration. 
     * @return the default cache provider used in this configuration.
     */
    CacheProvider getDefaultCacheProvider();
}