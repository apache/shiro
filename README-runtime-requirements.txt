Apache Ki Runtime Requirements
------------------------------

All 3rd party dependencies mentioned below are accessible in two ways:
1) In the ki-<version>-with-dependencies.zip distribution's lib directory
2) After downloading ki-<version>.zip (no dependencies), run 'ant retrieve-dependencies'.  This will download
the dependencies to a lib directory (peer to the build.xml).


Minimal required dependencies
-------------
Java 1.5 and later: Ensure ki-all.jar, slf4j-api.jar and one of slf4j's
                    bindings (slf4j-simple.jar, slf4j-log4j12, etc) are in your application's classpath.
Java 1.3 and 1.4 only: ki.jar, slf4j-api.jar, an slf4j bindng, retroweaver.jar and its associated dependendencies


Feature-based dependencies
--------------------------
- .ini based configuration, either for a ki.ini file in the classpath or embedded .ini in the KiFilter
  in web.xml:
  . include Jakarta commons-beanutils-core.jar
