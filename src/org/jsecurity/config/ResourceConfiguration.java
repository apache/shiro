/*
 * Copyright 2005-2008 Les Hazlewood
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
package org.jsecurity.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.mgt.SecurityManager;
import org.jsecurity.util.ResourceUtils;

import java.io.IOException;
import java.io.InputStream;

/**
 * @since 0.9
 */
public abstract class ResourceConfiguration implements Configuration {

    protected transient final Log log = LogFactory.getLog( getClass() );

    protected SecurityManager securityManager = null;

    public ResourceConfiguration(){}

    public ResourceConfiguration( String resourcePath ) {
        load(resourcePath);
    }

    protected void load( String resourcePath ) {
        if ( resourcePath == null ) {
            throw new IllegalArgumentException( "resourcePath argument cannot be null." );
        }
        InputStream is = getPathInputStream(resourcePath);
        loadFromStream(is);
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    protected void setSecurityManager(SecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    protected InputStream getPathInputStream( String path ) throws ConfigurationException {
        try {
            return ResourceUtils.getInputStreamForPath( path );
        } catch (IOException e) {
            String msg = "Unable to create input stream from resource path [" + path + "].";
            throw new ConfigurationException(msg, e);
        }
    }

    protected void loadFromStream( InputStream is ) throws ConfigurationException {
        try {
            doLoadFromStream( is );
        } catch (Exception e) {
            String msg = "Unable to load data from input stream [" + is + "].";
            throw new ConfigurationException( msg, e );
        }
    }

    protected abstract void doLoadFromStream( InputStream is ) throws Exception;
}
