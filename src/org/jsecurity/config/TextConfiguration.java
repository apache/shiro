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

import org.jsecurity.JSecurityException;
import org.jsecurity.mgt.SecurityManager;
import org.jsecurity.util.Initializable;

import java.io.Reader;
import java.util.Scanner;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class TextConfiguration extends ResourceConfiguration implements Initializable {

    private String config;

    public TextConfiguration() {
    }

    public String getConfig() {
        return config;
    }

    public void setConfig(String config) {
        this.config = config;
    }

    protected abstract void load(Reader r) throws ConfigurationException;

    protected abstract void load(Scanner s) throws ConfigurationException;

    public void init() throws JSecurityException {
        SecurityManager securityManager = getSecurityManager();
        if (securityManager == null) {
            String config = getConfig();
            if (config != null) {
                if (log.isInfoEnabled()) {
                    log.info("Attempting to load Configuration based on 'config' property.");
                }
                load(config);
            }
        }
    }
}
