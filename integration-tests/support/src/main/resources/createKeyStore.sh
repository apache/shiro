#!/usr/bin/env bash
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
set -e

# This script will generate a self signed certificate, store it in a Java keystore and PEM format.
# The generated certificate is good for 10 years, and should NOT need to be recreated until then (unless
# changes to the certificate are needed).
# Last run with Java 1.8.0_252
#
# Usage: For JVM based applications, the resulting keystore MUST be configured to in order for clients to accept TLS
# connections.  Typical usage requires setting of the Java system property 'javax.net.ssl.trustStore' to the file path
# of the keystore. Either by adding a command line parameter: `-Djavax.net.ssl.trustStore=/path/to/keystore` or
# programmatically: `System.setProperty("javax.net.ssl.trustStore", "/path/to/keystore")`

dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
keystore_file="${dir}/test-keystore.jks"
file_prefix="${dir}/test-keystore"
rm -f ${file_prefix}*

echo "generate new keystore"
keytool -genkey \
        -keystore "${file_prefix}.jks" \
        -alias "localhost" \
        -keyalg RSA \
        -keysize 2048 \
        -validity 3650 \
        -dname "C=US; ST=Unknown; L=Springfield; O=Unknown; OU=Unknown; CN=localhost" \
        -ext SAN=dns:localhost \
        -keypass password \
        -storepass password \
        -noprompt

echo "self sign"
keytool -selfcert \
        -alias "localhost" \
        -keystore "${file_prefix}.jks" \
        -validity 3650 \
        -storepass password \
        -noprompt

echo "export to pem"
keytool -export \
        -alias "localhost" \
        -keystore "${file_prefix}.jks" \
        -rfc \
        -file "${file_prefix}.pem" \
        -storepass password \
        -noprompt
