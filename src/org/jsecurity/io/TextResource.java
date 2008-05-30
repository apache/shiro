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
package org.jsecurity.io;

import java.io.*;
import java.util.Scanner;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class TextResource extends AbstractResource {

    protected String charsetName = null;

    public TextResource(){}

    public TextResource(String configBodyOrResourcePath) {
        load(configBodyOrResourcePath);
    }

    public TextResource(String configBodyOrResourcePath, String charsetName) {
        setCharsetName(charsetName);
        load( configBodyOrResourcePath );
    }

    public TextResource(InputStream is) {
        super(is);
    }

    public TextResource(Reader r ) {
        load(r);
    }

    public TextResource(Scanner s ) {
        load(s);
    }

    public String getCharsetName() {
        return charsetName;
    }

    public void setCharsetName(String charsetName) {
        this.charsetName = charsetName;
    }

    public void load( String configBodyOrResourcePath ) {
        if ( configBodyOrResourcePath == null ) {
            throw new IllegalArgumentException( "'configBodyOrResourcePath' argument cannot be null." );
        }
        try {
            super.load(configBodyOrResourcePath);
        } catch ( Exception e ) {
            if ( log.isDebugEnabled() ) {
                log.debug( "Unable to load text resource from the string argument.  Attempting to use the string " +
                        "argument as the text resource itself...", e );
            }
            StringReader sr = new StringReader(configBodyOrResourcePath);
            try {
                load(sr);
            } catch (Exception e2) {
                String msg = "Unable to load from configBody method argument.";
                throw new ResourceException(msg, e2 );
            }
        }
    }

    protected void doLoad(InputStream is) throws Exception {
        InputStreamReader isr;
        String charsetName = getCharsetName();
        if (charsetName != null) {
            isr = new InputStreamReader(is, charsetName);
        } else {
            isr = new InputStreamReader(is);
        }
        load(isr);
    }

    public void load(Reader reader) {
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

    protected void doLoad(Reader reader) {
        Scanner s = new Scanner(reader);
        try {
            load(s);
        } finally {
            s.close();
        }
    }

    public abstract void load(Scanner scanner);
}
