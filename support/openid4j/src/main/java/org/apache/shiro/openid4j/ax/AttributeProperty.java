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
package org.apache.shiro.openid4j.ax;

import java.util.HashMap;
import java.util.Map;

/**
 * An Enum representing all de-facto standard <a href="http://www.axschema.org/types/">
 * Attribute Exchange Types</a>.
 *
 * @since 1.2
 */
public enum AttributeProperty {

    Username("http://axschema.org/namePerson/friendly", "Alias/Username"),
    FullName("http://axschema.org/namePerson", "Full name"),
    NamePrefix("http://axschema.org/namePerson/prefix", "Name prefix"),
    FirstName("http://axschema.org/namePerson/first", "First name"),
    LastName("http://axschema.org/namePerson/last", "Last name"),
    MiddleName("http://axschema.org/namePerson/middle", "Middle name"),
    NameSuffix("http://axschema.org/namePerson/suffix", "Name suffix"),
    CompanyName("http://axschema.org/company/name", "Company name"),
    JobTitle("http://axschema.org/company/title", "Job title"),
    BirthDate("http://axschema.org/birthDate", "Birth date"),
    BirthYear("http://axschema.org/birthDate/birthYear", "Birth year"),
    BirthMonth("http://axschema.org/birthDate/birthMonth", "Birth month"),
    BirthDay("http://axschema.org/birthDate/birthday", "Birth day"),
    PhonePreferred("http://axschema.org/contact/phone/default", "Phone (preferred)"),
    PhoneHome("http://axschema.org/contact/phone/home", "Phone (home)"),
    PhoneWork("http://axschema.org/contact/phone/business", "Phone (work)"),
    PhoneMobile("http://axschema.org/contact/phone/cell", "Phone (mobile)"),
    PhoneFax("http://axschema.org/contact/phone/fax", "Phone (fax)"),
    Address("http://axschema.org/contact/postalAddress/home", "Address"),
    Address2("http://axschema.org/contact/postalAddressAdditional/home", "Address 2"),
    City("http://axschema.org/contact/city/home", "City"),
    State("http://axschema.org/contact/state/home", "State/Province"),
    Country("http://axschema.org/contact/country/home", "Country"),
    PostalCode("http://axschema.org/contact/postalCode/home", "Postal code"),
    BusinessAddress("http://axschema.org/contact/postalAddress/business", "Address"),
    BusinessAddress2("http://axschema.org/contact/postalAddressAdditional/business", "Address 2"),
    BusinessCity("http://axschema.org/contact/city/business", "City"),
    BusinessState("http://axschema.org/contact/state/business", "State/Province"),
    BusinessCountry("http://axschema.org/contact/country/business", "Country"),
    BusinessPostalCode("http://axschema.org/contact/postalCode/business", "Postal code"),
    Email("http://axschema.org/contact/email", "Email"),
    AOLIM("http://axschema.org/contact/IM/AIM", "AOL IM"),
    ICQIM("http://axschema.org/contact/IM/ICQ", "ICQ IM"),
    MSNIM("http://axschema.org/contact/IM/MSN", "MSN IM"),
    YahooIM("http://axschema.org/contact/IM/Yahoo", "Yahoo! IM"),
    JabberIM("http://axschema.org/contact/IM/Jabber", "Jabber IM"),
    SkypeIM("http://axschema.org/contact/IM/Skype", "Skype IM"),
    WebPage("http://axschema.org/contact/web/default", "Web page"),
    Blog("http://axschema.org/contact/web/blog", "Blog"),
    LinkedInURL("http://axschema.org/contact/web/Linkedin", "LinkedIn URL"),
    AmazonURL("http://axschema.org/contact/web/Amazon", "Amazon URL"),
    FlickrURL("http://axschema.org/contact/web/Flickr", "Flickr URL"),
    DeliciousURL("http://axschema.org/contact/web/Delicious", "del.icio.us URL"),
    SpokenName("http://axschema.org/media/spokenname", "Spoken name"),
    AudioGreeting("http://axschema.org/media/greeting/audio", "Audio greeting"),
    VideoGreeting("http://axschema.org/media/greeting/video", "Video greeting"),
    Image("http://axschema.org/media/image/default", "Image"),
    SquareImage("http://axschema.org/media/image/aspect11", "Square image"),
    Aspect43Image("http://axschema.org/media/image/aspect43", "4:3 aspect image"),
    Aspect34Image("http://axschema.org/media/image/aspect34", "3:4 aspect image"),
    FaviconImage("http://axschema.org/media/image/favicon", "Favicon image"),
    Gender("http://axschema.org/person/gender", "Gender"),
    Language("http://axschema.org/pref/language", "Language"),
    TimeZone("http://axschema.org/pref/timezone", "Time zone");

    private static final Map<String, AttributeProperty> caseInsensitiveNameMap;

    static {
        caseInsensitiveNameMap = new HashMap<String, AttributeProperty>();
        for (AttributeProperty prop : values()) {
            caseInsensitiveNameMap.put(prop.name().toLowerCase(), prop);
        }
    }

    private final String label;
    private final String uri;

    private AttributeProperty(String uri, String label) {
        this.uri = uri;
        this.label = label;
    }

    public static AttributeProperty fromName(String caseInsensitiveName) {
        if (caseInsensitiveName == null) {
            return null;
        }
        return caseInsensitiveNameMap.get(caseInsensitiveName.toLowerCase());
    }

    public String getLabel() {
        return label;
    }

    public String getUri() {
        return uri;
    }
}
