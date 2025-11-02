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
