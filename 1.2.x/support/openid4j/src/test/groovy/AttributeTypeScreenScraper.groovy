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

/**
 * @since 1.2
 */
class AttributeTypeScreenScraper extends GroovyTestCase {

    void testNothing() {}

    //used to generate constants in the AttributeProperty class:
    void doTestScrape() {

        //file copied from the OpenId website:
        def resource = "http://www.axschema.org/types/";

        def properties = []
        def property = [:]

        boolean parsing = false;

        resource.toURL().eachLine("UTF-8", { String line ->

            line = line.trim()

            if (line.equals("<table id=\"types\">")) {
                parsing = true;
            }
            if (parsing && line.equals("</table>")) {
                parsing = false
            }
            if (parsing) {
                if (line.equals("<tr>") && property.size() == 3) {
                    properties << property
                    property = [:]
                }
                if (line.startsWith("<td") && line.endsWith("</a></td>")) {
                    int index = line.lastIndexOf("http://");
                    line = line.substring(index, line.length() - "</a></td>".length())
                    property.uri = line
                } else if (line.startsWith("<td>") && line.endsWith("</td>") && !line.contains("&nbsp;")) {
                    line = line.substring(4, line.length() - 5)
                    property.label = line

                    String[] words = property.label.split(" ");
                    String varName = "";
                    for( String s : words ) {
                        s = s.replace("(", "")
                        s = s.replace(")", "")
                        s = s.replace(".", "")
                        int index = s.indexOf("/")
                        if (index > 0) {
                            s = s.substring(0, index)
                        }
                        varName += s.capitalize()
                    }

                    //special cases:
                    if (property.uri.endsWith("business")) {
                        varName = "Business" + varName;
                    }
                    if (varName == "Alias") {
                        varName = "Username"
                    }
                    if (varName == "Yahoo!IM") {
                        varName = "YahooIM"
                    }
                    if (varName == "4:3AspectImage") {
                        varName = "Aspect43Image"
                    }
                    if (varName == "3:4AspectImage") {
                        varName = "Aspect34Image"
                    }
                    property.name = varName;
                }
            }
        });
        for (def prop: properties) {
            String d = "${prop.name}(\"${prop.uri}\", \"${prop.label}\"), ";
            System.out.println(d);
        }
    }

}
