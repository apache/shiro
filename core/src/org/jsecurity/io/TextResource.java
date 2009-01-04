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

import java.io.*;
import java.util.Scanner;

/**
 * //TODO complete JavaDoc
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class TextResource extends AbstractResource {

    private static final Log log = LogFactory.getLog(TextResource.class);    

    protected String charsetName;

    public TextResource() {
    }

    public TextResource(String configBodyOrResourcePath) {
        load(configBodyOrResourcePath);
    }

    public TextResource(String configBodyOrResourcePath, String charsetName) {
        setCharsetName(charsetName);
        load(configBodyOrResourcePath);
    }

    public TextResource(InputStream is) {
        super(is);
    }

    public TextResource(Reader r) {
        load(r);
    }

    public TextResource(Scanner s) {
        load(s);
    }

    public String getCharsetName() {
        return charsetName;
    }

    public void setCharsetName(String charsetName) {
        this.charsetName = charsetName;
    }

    public void load(String resourcePath) {
        if (resourcePath == null) {
            throw new IllegalArgumentException("'resourcePath' argument cannot be null.");
        }
        try {
            super.load(resourcePath);
        } catch (Exception e) {
            String msg = "Unable to load text resource from the resource path [" + resourcePath +"]";
            throw new ResourceException(msg, e);
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

    protected void doLoad(BufferedReader reader) {
        Scanner s = new Scanner(reader);
        try {
            load(s);
        } finally {
            s.close();
        }
    }

    public abstract void load(Scanner scanner);
}
