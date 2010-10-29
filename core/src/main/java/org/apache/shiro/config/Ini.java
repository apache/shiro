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
package org.apache.shiro.config;

import org.apache.shiro.io.ResourceUtils;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.*;

/**
 * A class representing the <a href="http://en.wikipedia.org/wiki/INI_file">INI</a> text configuration format.
 * <p/>
 * An Ini instance is a map of {@link Ini.Section Section}s, keyed by section name.  Each
 * {@code Section} is itself a map of {@code String} name/value pairs.  Name/value pairs are guaranteed to be unique
 * within each {@code Section} only - not across the entire {@code Ini} instance.
 *
 * @since 1.0
 */
public class Ini implements Map<String, Ini.Section> {

    private static transient final Logger log = LoggerFactory.getLogger(Ini.class);

    public static final String DEFAULT_SECTION_NAME = ""; //empty string means the first unnamed section
    public static final String DEFAULT_CHARSET_NAME = "UTF-8";

    public static final String COMMENT_POUND = "#";
    public static final String COMMENT_SEMICOLON = ";";
    public static final String SECTION_PREFIX = "[";
    public static final String SECTION_SUFFIX = "]";

    protected static final char ESCAPE_TOKEN = '\\';

    private final Map<String, Section> sections;

    /**
     * Creates a new empty {@code Ini} instance.
     */
    public Ini() {
        this.sections = new LinkedHashMap<String, Section>();
    }

    /**
     * Creates a new {@code Ini} instance with the specified defaults.
     *
     * @param defaults the default sections and/or key-value pairs to copy into the new instance.
     */
    public Ini(Ini defaults) {
        this();
        if (defaults == null) {
            throw new NullPointerException("Defaults cannot be null.");
        }
        for (Section section : defaults.getSections()) {
            Section copy = new Section(section);
            this.sections.put(section.getName(), copy);
        }
    }

    /**
     * Returns {@code true} if no sections have been configured, or if there are sections, but the sections themselves
     * are all empty, {@code false} otherwise.
     *
     * @return {@code true} if no sections have been configured, or if there are sections, but the sections themselves
     *         are all empty, {@code false} otherwise.
     */
    public boolean isEmpty() {
        Collection<Section> sections = this.sections.values();
        if (!sections.isEmpty()) {
            for (Section section : sections) {
                if (!section.isEmpty()) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Returns the names of all sections managed by this {@code Ini} instance or an empty collection if there are
     * no sections.
     *
     * @return the names of all sections managed by this {@code Ini} instance or an empty collection if there are
     *         no sections.
     */
    public Set<String> getSectionNames() {
        return Collections.unmodifiableSet(sections.keySet());
    }

    /**
     * Returns the sections managed by this {@code Ini} instance or an empty collection if there are
     * no sections.
     *
     * @return the sections managed by this {@code Ini} instance or an empty collection if there are
     *         no sections.
     */
    public Collection<Section> getSections() {
        return Collections.unmodifiableCollection(sections.values());
    }

    /**
     * Returns the {@link Section} with the given name or {@code null} if no section with that name exists.
     *
     * @param sectionName the name of the section to retrieve.
     * @return the {@link Section} with the given name or {@code null} if no section with that name exists.
     */
    public Section getSection(String sectionName) {
        String name = cleanName(sectionName);
        return sections.get(name);
    }

    /**
     * Ensures a section with the specified name exists, adding a new one if it does not yet exist.
     *
     * @param sectionName the name of the section to ensure existence
     * @return the section created if it did not yet exist, or the existing Section that already existed.
     */
    public Section addSection(String sectionName) {
        String name = cleanName(sectionName);
        Section section = getSection(name);
        if (section == null) {
            section = new Section(name);
            this.sections.put(name, section);
        }
        return section;
    }

    /**
     * Removes the section with the specified name and returns it, or {@code null} if the section did not exist.
     *
     * @param sectionName the name of the section to remove.
     * @return the section with the specified name or {@code null} if the section did not exist.
     */
    public Section removeSection(String sectionName) {
        String name = cleanName(sectionName);
        return this.sections.remove(name);
    }

    private static String cleanName(String sectionName) {
        String name = StringUtils.clean(sectionName);
        if (name == null) {
            log.trace("Specified name was null or empty.  Defaulting to the default section (name = \"\")");
            name = DEFAULT_SECTION_NAME;
        }
        return name;
    }

    /**
     * Sets a name/value pair for the section with the given {@code sectionName}.  If the section does not yet exist,
     * it will be created.  If the {@code sectionName} is null or empty, the name/value pair will be placed in the
     * default (unnamed, empty string) section.
     *
     * @param sectionName   the name of the section to add the name/value pair
     * @param propertyName  the name of the property to add
     * @param propertyValue the property value
     */
    public void setSectionProperty(String sectionName, String propertyName, String propertyValue) {
        String name = cleanName(sectionName);
        Section section = getSection(name);
        if (section == null) {
            section = addSection(name);
        }
        section.put(propertyName, propertyValue);
    }

    /**
     * Returns the value of the specified section property, or {@code null} if the section or property do not exist.
     *
     * @param sectionName  the name of the section to retrieve to acquire the property value
     * @param propertyName the name of the section property for which to return the value
     * @return the value of the specified section property, or {@code null} if the section or property do not exist.
     */
    public String getSectionProperty(String sectionName, String propertyName) {
        Section section = getSection(sectionName);
        return section != null ? section.get(propertyName) : null;
    }

    /**
     * Returns the value of the specified section property, or the {@code defaultValue} if the section or
     * property do not exist.
     *
     * @param sectionName  the name of the section to add the name/value pair
     * @param propertyName the name of the property to add
     * @param defaultValue the default value to return if the section or property do not exist.
     * @return the value of the specified section property, or the {@code defaultValue} if the section or
     *         property do not exist.
     */
    public String getSectionProperty(String sectionName, String propertyName, String defaultValue) {
        String value = getSectionProperty(sectionName, propertyName);
        return value != null ? value : defaultValue;
    }

    /**
     * Creates a new {@code Ini} instance loaded with the INI-formatted data in the resource at the given path.  The
     * resource path may be any value interpretable by the
     * {@link ResourceUtils#getInputStreamForPath(String) ResourceUtils.getInputStreamForPath} method.
     *
     * @param resourcePath the resource location of the INI data to load when creating the {@code Ini} instance.
     * @return a new {@code Ini} instance loaded with the INI-formatted data in the resource at the given path.
     * @throws ConfigurationException if the path cannot be loaded into an {@code Ini} instance.
     */
    public static Ini fromResourcePath(String resourcePath) throws ConfigurationException {
        if (!StringUtils.hasLength(resourcePath)) {
            throw new IllegalArgumentException("Resource Path argument cannot be null or empty.");
        }
        Ini ini = new Ini();
        ini.loadFromPath(resourcePath);
        return ini;
    }

    /**
     * Loads data from the specified resource path into this current {@code Ini} instance.  The
     * resource path may be any value interpretable by the
     * {@link ResourceUtils#getInputStreamForPath(String) ResourceUtils.getInputStreamForPath} method.
     *
     * @param resourcePath the resource location of the INI data to load into this instance.
     * @throws ConfigurationException if the path cannot be loaded
     */
    public void loadFromPath(String resourcePath) throws ConfigurationException {
        InputStream is;
        try {
            is = ResourceUtils.getInputStreamForPath(resourcePath);
        } catch (IOException e) {
            throw new ConfigurationException(e);
        }
        load(is);
    }

    /**
     * Loads the specified raw INI-formatted text into this instance.
     *
     * @param iniConfig the raw INI-formatted text to load into this instance.
     * @throws ConfigurationException if the text cannot be loaded
     */
    public void load(String iniConfig) throws ConfigurationException {
        load(new Scanner(iniConfig));
    }

    /**
     * Loads the INI-formatted text backed by the given InputStream into this instance.  This implementation will
     * close the input stream after it has finished loading.  It is expected that the stream's contents are
     * UTF-8 encoded.
     *
     * @param is the {@code InputStream} from which to read the INI-formatted text
     * @throws ConfigurationException if unable
     */
    public void load(InputStream is) throws ConfigurationException {
        if (is == null) {
            throw new NullPointerException("InputStream argument cannot be null.");
        }
        InputStreamReader isr;
        try {
            isr = new InputStreamReader(is, DEFAULT_CHARSET_NAME);
        } catch (UnsupportedEncodingException e) {
            throw new ConfigurationException(e);
        }
        load(isr);
    }

    /**
     * Loads the INI-formatted text backed by the given Reader into this instance.  This implementation will close the
     * reader after it has finished loading.
     *
     * @param reader the {@code Reader} from which to read the INI-formatted text
     */
    public void load(Reader reader) {
        Scanner scanner = new Scanner(reader);
        try {
            load(scanner);
        } finally {
            try {
                scanner.close();
            } catch (Exception e) {
                log.debug("Unable to cleanly close the InputStream scanner.  Non-critical - ignoring.", e);
            }
        }
    }

    private void addSection(String name, StringBuilder content) {
        if (content.length() > 0) {
            String contentString = content.toString();
            String cleaned = StringUtils.clean(contentString);
            if (cleaned != null) {
                Section section = new Section(name, contentString);
                if (!section.isEmpty()) {
                    sections.put(name, section);
                }
            }
        }
    }

    /**
     * Loads the INI-formatted text backed by the given Scanner.  This implementation will close the
     * scanner after it has finished loading.
     *
     * @param scanner the {@code Scanner} from which to read the INI-formatted text
     */
    public void load(Scanner scanner) {

        String sectionName = DEFAULT_SECTION_NAME;
        StringBuilder sectionContent = new StringBuilder();

        while (scanner.hasNextLine()) {

            String rawLine = scanner.nextLine();
            String line = StringUtils.clean(rawLine);

            if (line == null || line.startsWith(COMMENT_POUND) || line.startsWith(COMMENT_SEMICOLON)) {
                //skip empty lines and comments:
                continue;
            }

            String newSectionName = getSectionName(line);
            if (newSectionName != null) {
                //found a new section - convert the currently buffered one into a Section object
                addSection(sectionName, sectionContent);

                //reset the buffer for the new section:
                sectionContent = new StringBuilder();

                sectionName = newSectionName;

                if (log.isDebugEnabled()) {
                    log.debug("Parsing " + SECTION_PREFIX + sectionName + SECTION_SUFFIX);
                }
            } else {
                //normal line - add it to the existing content buffer:
                sectionContent.append(rawLine).append("\n");
            }
        }

        //finish any remaining buffered content:
        addSection(sectionName, sectionContent);
    }

    protected static boolean isSectionHeader(String line) {
        String s = StringUtils.clean(line);
        return s != null && s.startsWith(SECTION_PREFIX) && s.endsWith(SECTION_SUFFIX);
    }

    protected static String getSectionName(String line) {
        String s = StringUtils.clean(line);
        if (isSectionHeader(s)) {
            return cleanName(s.substring(1, s.length() - 1));
        }
        return null;
    }

    public boolean equals(Object obj) {
        if (obj instanceof Ini) {
            Ini ini = (Ini) obj;
            return this.sections.equals(ini.sections);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return this.sections.hashCode();
    }

    public String toString() {
        if (CollectionUtils.isEmpty(this.sections)) {
            return "<empty INI>";
        } else {
            StringBuilder sb = new StringBuilder("sections=");
            int i = 0;
            for (Ini.Section section : this.sections.values()) {
                if (i > 0) {
                    sb.append(",");
                }
                sb.append(section.toString());
                i++;
            }
            return sb.toString();
        }
    }

    public int size() {
        return this.sections.size();
    }

    public boolean containsKey(Object key) {
        return this.sections.containsKey(key);
    }

    public boolean containsValue(Object value) {
        return this.sections.containsValue(value);
    }

    public Section get(Object key) {
        return this.sections.get(key);
    }

    public Section put(String key, Section value) {
        return this.sections.put(key, value);
    }

    public Section remove(Object key) {
        return this.sections.remove(key);
    }

    public void putAll(Map<? extends String, ? extends Section> m) {
        this.sections.putAll(m);
    }

    public void clear() {
        this.sections.clear();
    }

    public Set<String> keySet() {
        return Collections.unmodifiableSet(this.sections.keySet());
    }

    public Collection<Section> values() {
        return Collections.unmodifiableCollection(this.sections.values());
    }

    public Set<Entry<String, Section>> entrySet() {
        return Collections.unmodifiableSet(this.sections.entrySet());
    }

    /**
     * An {@code Ini.Section} is String-key-to-String-value Map, identifiable by a
     * {@link #getName() name} unique within an {@link Ini} instance.
     */
    public static class Section implements Map<String, String> {
        private final String name;
        private final Map<String, String> props;

        private Section(String name) {
            if (name == null) {
                throw new NullPointerException("name");
            }
            this.name = name;
            this.props = new LinkedHashMap<String, String>();
        }

        private Section(String name, String sectionContent) {
            if (name == null) {
                throw new NullPointerException("name");
            }
            this.name = name;
            Map<String,String> props;
            if (StringUtils.hasText(sectionContent) ) {
                props = toMapProps(sectionContent);
            } else {
                props = new LinkedHashMap<String,String>();
            }
            if ( props != null ) {
                this.props = props;
            } else {
                this.props = new LinkedHashMap<String,String>();
            }
        }

        private Section(Section defaults) {
            this(defaults.getName());
            putAll(defaults.props);
        }

        //Protected to access in a test case - NOT considered part of Shiro's public API

        protected static boolean isContinued(String line) {
            if (!StringUtils.hasText(line)) {
                return false;
            }
            int length = line.length();
            //find the number of backslashes at the end of the line.  If an even number, the
            //backslashes are considered escaped.  If an odd number, the line is considered continued on the next line
            int backslashCount = 0;
            for (int i = length - 1; i > 0; i--) {
                if (line.charAt(i) == ESCAPE_TOKEN) {
                    backslashCount++;
                } else {
                    break;
                }
            }
            return backslashCount % 2 != 0;
        }

        private static boolean isKeyValueSeparatorChar(char c) {
            return Character.isWhitespace(c) || c == ':' || c == '=';
        }

        private static boolean isCharEscaped(CharSequence s, int index) {
            return index > 0 && s.charAt(index - 1) == ESCAPE_TOKEN;
        }

        //Protected to access in a test case - NOT considered part of Shiro's public API
        protected static String[] splitKeyValue(String keyValueLine) {
            String line = StringUtils.clean(keyValueLine);
            if (line == null) {
                return null;
            }
            StringBuilder keyBuffer = new StringBuilder();
            StringBuilder valueBuffer = new StringBuilder();

            boolean buildingKey = true; //we'll build the value next:

            for (int i = 0; i < line.length(); i++) {
                char c = line.charAt(i);

                if (buildingKey) {
                    if (isKeyValueSeparatorChar(c) && !isCharEscaped(line, i)) {
                        buildingKey = false;//now start building the value
                    } else {
                        keyBuffer.append(c);
                    }
                } else {
                    if (valueBuffer.length() == 0 && isKeyValueSeparatorChar(c) && !isCharEscaped(line, i)) {
                        //swallow the separator chars before we start building the value
                    } else {
                        valueBuffer.append(c);
                    }
                }
            }

            String key = StringUtils.clean(keyBuffer.toString());
            String value = StringUtils.clean(valueBuffer.toString());

            if (key == null || value == null) {
                String msg = "Line argument must contain a key and a value.  Only one string token was found.";
                throw new IllegalArgumentException(msg);
            }

            log.trace("Discovered key/value pair: {}={}", key, value);

            return new String[]{key, value};
        }

        private static Map<String, String> toMapProps(String content) {
            Map<String, String> props = new LinkedHashMap<String, String>();
            String line;
            StringBuilder lineBuffer = new StringBuilder();
            Scanner scanner = new Scanner(content);
            while (scanner.hasNextLine()) {
                line = StringUtils.clean(scanner.nextLine());
                if (isContinued(line)) {
                    //strip off the last continuation backslash:
                    line = line.substring(0, line.length() - 1);
                    lineBuffer.append(line);
                    continue;
                } else {
                    lineBuffer.append(line);
                }
                line = lineBuffer.toString();
                lineBuffer = new StringBuilder();
                String[] kvPair = splitKeyValue(line);
                props.put(kvPair[0], kvPair[1]);
            }

            return props;
        }

        public String getName() {
            return this.name;
        }

        public void clear() {
            this.props.clear();
        }

        public boolean containsKey(Object key) {
            return this.props.containsKey(key);
        }

        public boolean containsValue(Object value) {
            return this.props.containsValue(value);
        }

        public Set<Entry<String, String>> entrySet() {
            return this.props.entrySet();
        }

        public String get(Object key) {
            return this.props.get(key);
        }

        public boolean isEmpty() {
            return this.props.isEmpty();
        }

        public Set<String> keySet() {
            return this.props.keySet();
        }

        public String put(String key, String value) {
            return this.props.put(key, value);
        }

        public void putAll(Map<? extends String, ? extends String> m) {
            this.props.putAll(m);
        }

        public String remove(Object key) {
            return this.props.remove(key);
        }

        public int size() {
            return this.props.size();
        }

        public Collection<String> values() {
            return this.props.values();
        }

        public String toString() {
            String name = getName();
            if (DEFAULT_SECTION_NAME.equals(name)) {
                return "<default>";
            }
            return name;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof Section) {
                Section other = (Section) obj;
                return getName().equals(other.getName()) && this.props.equals(other.props);
            }
            return false;
        }

        @Override
        public int hashCode() {
            return this.name.hashCode() * 31 + this.props.hashCode();
        }
    }

}
