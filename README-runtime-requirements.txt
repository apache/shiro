Apache Ki Runtime Requirements
------------------------------

All 3rd party dependencies mentioned below are accessible in two ways:
1) In the jsecurity-<version>-with-dependencies.zip distribution's lib directory
2) After downloading jsecurity-<version>.zip (no dependencies), run 'ant retrieve-dependencies'.  This will download
the dependencies to a lib directory (peer to the build.xml).


Minimal required dependencies
-------------
Java 1.5 and later: Ensure jsecurity.jar and Apache commons-logging.jar are in your application's classpath.
Java 1.3 and 1.4 only: jsecurity.jar, commons-logging.jar and retroweaver.jar and its associated dependendencies


Feature-based dependencies
--------------------------
- .ini based configuration, either for a jsecurity.ini file in the classpath or embedded .ini in the Apache KiFilter
  in web.xml:
  . include Jakarta commons-beanutils-core.jar
