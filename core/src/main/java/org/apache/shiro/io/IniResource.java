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
package org.apache.shiro.io;

import java.io.InputStream;
import java.io.Reader;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.shiro.util.StringUtils.clean;
import static org.apache.shiro.util.StringUtils.splitKeyValue;

/**
 * //TODO - complete JavaDoc
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public class IniResource extends TextResource {

    private static final Logger log = LoggerFactory.getLogger(IniResource.class);

    public static final String COMMENT_POUND = "#";
    public static final String COMMENT_SEMICOLON = ";";
    public static final String HEADER_PREFIX = "[";
    public static final String HEADER_SUFFIX = "]";

    protected Map<String, Map<String, String>> sections = new LinkedHashMap<String, Map<String, String>>();

    public IniResource() {
    }

    public IniResource(String configBodyOrResourcePath) {
        load(configBodyOrResourcePath);
    }

    public IniResource(String configBodyOrResourcePath, String charsetName) {
        setCharsetName(charsetName);
        load(configBodyOrResourcePath);
    }

    public IniResource(InputStream is) {
        load(is);
    }

    public IniResource(Reader r) {
        load(r);
    }

    public IniResource(Scanner s) {
        load(s);
    }

    public Map<String, Map<String, String>> getSections() {
        return sections;
    }

    public void setSections(Map<String, Map<String, String>> sections) {
        this.sections = sections;
    }

    public void load(Scanner scanner) {

        String currSectionName = null;

        Map<String, String> section = new LinkedHashMap<String, String>();

        while (scanner.hasNextLine()) {

            String line = clean(scanner.nextLine());

            if (line == null || line.startsWith(COMMENT_POUND) || line.startsWith(COMMENT_SEMICOLON)) {
                //skip empty lines and comments:
                continue;
            }

            String sectionName = getSectionName(line.toLowerCase());
            if (sectionName != null) {
                if (!section.isEmpty()) {
                    sections.put(currSectionName, section);
                }
                currSectionName = sectionName;
                section = new LinkedHashMap<String, String>();

                if (log.isDebugEnabled()) {
                    log.debug("Parsing " + HEADER_PREFIX + currSectionName + HEADER_SUFFIX);
                }
            } else {
                //normal line - split it into Key Value pairs and add it to the section:
                try {
                    String[] keyValue = splitKeyValue(line);
                    section.put(keyValue[0], keyValue[1]);
                } catch (ParseException e) {
                    String msg = "Unable to read key value pair for line [" + line + "].";
                    throw new ResourceException(msg, e);
                }
            }
        }

        if (!section.isEmpty()) {
            sections.put(currSectionName, section);
        }
    }

    protected static boolean isSectionHeader(String line) {
        String s = clean(line);
        return s != null && s.startsWith(HEADER_PREFIX) && s.endsWith(HEADER_SUFFIX);
    }

    protected static String getSectionName(String line) {
        String s = clean(line);
        if (isSectionHeader(s)) {
            return clean(s.substring(1, s.length() - 1));
        }
        return null;
    }
}
