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

import org.jsecurity.util.ResourceUtils;

import java.io.*;
import java.util.Scanner;

/**
 * @since 0.9
 * @author Les Hazlewood
 */
public abstract class TextConfiguration extends ResourceConfiguration {

    protected String charsetName = null;

    public TextConfiguration(){}

    public TextConfiguration(String configBodyOrResourcePath) {
        this(configBodyOrResourcePath, null);
    }

    public TextConfiguration(String configBodyOrResourcePath, String charsetName) {
        load( configBodyOrResourcePath, charsetName );
    }

    protected void load( String configBodyOrResourcePath, String charsetName ) {
        if ( configBodyOrResourcePath == null ) {
            throw new IllegalArgumentException( "'configBodyOrResourcePath' argument cannot be null." );
        }
        setCharsetName(charsetName);
        if (ResourceUtils.hasResourcePrefix(configBodyOrResourcePath)) {
            load(configBodyOrResourcePath);
        } else {
            StringReader sr = new StringReader(configBodyOrResourcePath);
            try {
                load(sr);
            } catch (Exception e) {
                String msg = "Unable to load configuration from configBody method argument.";
                throw new ConfigurationException(msg, e );
            }
        }
    }

    public String getCharsetName() {
        return charsetName;
    }

    public void setCharsetName(String charsetName) {
        this.charsetName = charsetName;
    }

    protected void doLoadFromStream(InputStream is) throws Exception {
        InputStreamReader isr;
        String charsetName = getCharsetName();
        if (charsetName != null) {
            isr = new InputStreamReader(is, charsetName);
        } else {
            isr = new InputStreamReader(is);
        }
        load(isr);
    }

    protected void load(Reader reader) throws Exception {
        BufferedReader br;
        if (reader instanceof BufferedReader) {
            br = (BufferedReader) reader;
        } else {
            br = new BufferedReader(reader);
        }
        try {
            doLoad(br);
        } finally {
            try {
                br.close();
            } catch (IOException e) {
                if (log.isWarnEnabled()) {
                    log.warn("Unable to cleanly close BufferedReader [" + br + "] after " +
                            "the doLoad(Reader) call.");
                }
            }
        }
    }

    protected void doLoad(Reader reader) throws Exception {
        Scanner s = new Scanner(reader);
        try {
            doLoad(s);
        } finally {
            s.close();
        }
    }

    protected void doLoad(Scanner scanner) throws Exception {
    }
}
