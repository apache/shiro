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
def executor_number = System.getenv('EXECUTOR_NUMBER')
if (executor_number != null) {
    final int port_increment = 100
    final int admin_port_increment = 48
    int portbase = 4900 + (executor_number as int) * port_increment
    int adminPort
    // find a free port
    for (; portbase < 10000; portbase += port_increment) {
        def server_socket
        adminPort = portbase + admin_port_increment
        try {
            server_socket = new ServerSocket()
            server_socket.setReuseAddress true
            server_socket.bind(new InetSocketAddress(adminPort))
            break
        } catch (IOException e) {
            println "Admin port $adminPort is busy, trying next"
        } finally {
            server_socket?.close()
        }
    }

    int httpsPort = portbase + 81

    project.properties.'payara.portbase' = portbase as String
    project.properties.'payara.adminport' = adminPort as String
    project.properties.'payara.argLine' = "-DadminPort=$adminPort -Dpayara.https.port=$httpsPort" as String
    project.properties.'payara.restart.skip' = project.properties.'payara.start.skip'
    println "Payara: portbase = ${project.properties.'payara.portbase'}, " +
            "argLine = ${project.properties.'payara.argLine'}"
} else {
    project.properties.'payara.argLine' = ''
    project.properties.'payara.restart.skip' = 'true'
}
