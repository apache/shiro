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

def deployableBranch = env.BRANCH_NAME ==~ /(main|4.x)/
def latestSupportedJDK = 'jdk_25_latest'
def builtinVersion = '999-SNAPSHOT'
def nextVersion
def mavenArgs = '--show-version --errors --batch-mode --no-transfer-progress'
def skipCompilation = '-Dmaven.main.skip=true -Dmaven.test.compile.skip=true -Daspectj.skip=true'

pipeline {

    agent none

    options {
        // Configure an overall timeout for the build of one hour.
        timeout(time: 1, unit: 'HOURS')
        skipDefaultCheckout()
        // When we have test-fails e.g. we don't need to run the remaining steps
        skipStagesAfterUnstable()
        buildDiscarder(logRotator(numToKeepStr: '5', artifactNumToKeepStr: '5', daysToKeepStr: '30'))
    }

    stages {
        stage('Build') {
            agent {
                node {
                    // https://cwiki.apache.org/confluence/display/INFRA/ci-builds.apache.org
                    label 'ubuntu'
                    customWorkspace "workspace/${JOB_NAME}/BuildCheckout/"
                }
            }

            tools {
                // https://cwiki.apache.org/confluence/display/INFRA/Maven+Installation+Matrix
                maven 'maven_3_latest'
                jdk "${latestSupportedJDK}"
            }

            stages {
                stage('Checkout and Initialization') {
                    steps {
                        echo 'Cleaning up the workspace'
                        cleanBeforeCheckout()
                        echo 'Checking out branch ' + env.BRANCH_NAME
                        checkout scm
                        echo 'Building Branch: ' + env.BRANCH_NAME
                        echo 'Using PATH = ' + env.PATH
                        echo 'Slave Node = ' + env.NODE_NAME
                    }
                }

                stage('Use next -SNAPSHOT version') {
                    when {
                        expression { deployableBranch }
                        // is not a PR (GitHub) / MergeRequest (GitLab) / Change (Gerrit)?
                        not { changeRequest() }
                    }

                    steps {
                        echo 'Setting next -SNAPSHOT version'
                        script {
                            def latestRelease = sh(script: """
                                curl -sf https://repo.maven.apache.org/maven2/org/apache/shiro/shiro-root/maven-metadata.xml \
                                | xmllint --xpath '//metadata/versioning/versions/version/text()' - 2>/dev/null \
                                | egrep -vi "alpha|beta|RC"|tail -n1 \
                                || echo '$builtinVersion'
                                """, returnStdout: true
                            ).trim()

                            def parts = latestRelease.tokenize('.')
                            def nextPatch = parts[2].toInteger() + 1
                            nextVersion = "${parts[0]}.${parts[1]}.${nextPatch}-SNAPSHOT"
                            if (env.BRANCH_NAME == '4.x') {
                                nextVersion = '4.0.0-SNAPSHOT'
                            } else if (parts[0].toInteger() < 3) {
                                nextVersion = '3.0.0-SNAPSHOT'
                            }

                            echo "Latest release: ${latestRelease}, next SNAPSHOT: ${nextVersion}"
                        }

                        sh "./mvnw -B versions:set -DprocessAllModules=true -DgenerateBackupPoms=false \
                            -DoldVersion=${builtinVersion} -DnewVersion=${nextVersion}"
                    }
                }

                stage('Compile and package') {
                    steps {
                        echo 'Building'
                        sh "./mvnw verify ${mavenArgs} -Pdocs -DskipTests -DskipITs"
                        stash name: 'ci-build', includes: '**/target/**,**/pom.xml', excludes: '.mvn/**'
                    }
                }
            }

            post {
                success {
                    cleanBeforeCheckout()
                }
            }
        }

        stage('Test') {
            matrix {
                axes {
                    axis {
                        // https://cwiki.apache.org/confluence/display/INFRA/JDK+Installation+Matrix
                        name 'MATRIX_JDK'
                        values 'jdk_27_latest', 'jdk_25_latest', 'jdk_21_latest'
                    }
                    // Additional axes, like OS and maven version can be configured here.
                }

                agent {
                    node {
                        // https://cwiki.apache.org/confluence/display/INFRA/ci-builds.apache.org
                        label 'ubuntu'
                        customWorkspace "workspace/${JOB_NAME}/MatrixCheckout/${MATRIX_JDK}/"
                    }
                }

                tools {
                    // https://cwiki.apache.org/confluence/display/INFRA/Maven+Installation+Matrix
                    maven 'maven_3_latest'
                    jdk "${MATRIX_JDK}"
                }

                stages {
                    stage('Checkout and Restore build') {
                        steps {
                            echo 'Cleaning up the workspace'
                            cleanBeforeCheckout()
                            echo 'Checking out branch ' + env.BRANCH_NAME
                            checkout scm
                            echo 'Building Branch: ' + env.BRANCH_NAME
                            echo 'Using PATH = ' + env.PATH
                            echo 'Slave Node = ' + env.NODE_NAME
                            unstash 'ci-build'
                        }
                    }

                    stage('Run tests') {
                        steps {
                            sh "./mvnw verify ${mavenArgs} ${skipCompilation} \
                                -Pskip_jakarta_ee_tests -Dcheckstyle.skip -DminimalJavaBuildVersion=17 \
                                -Dmaven.test.failure.ignore=true"
                        }

                        post {
                            always {
                                junit(testResults: '**/surefire-reports/*.xml', allowEmptyResults: true)
                                junit(testResults: '**/failsafe-reports/*.xml', allowEmptyResults: true)
                                archiveArtifacts artifacts: '**/logs/server.log*', allowEmptyArchive: true
                            }
                        }
                    }

                    stage('Deploy') {
                        when {
                            expression { deployableBranch }
                            expression { MATRIX_JDK == latestSupportedJDK }
                            // is not a PR (GitHub) / MergeRequest (GitLab) / Change (Gerrit)?
                            not { changeRequest() }
                        }

                        steps {
                            echo 'Deploying'
                            sh "./mvnw deploy ${mavenArgs} ${skipCompilation} \
                                -Pdocs -DskipTests -DskipITs -Dmaven.install.skip=true -Dcheckstyle.skip"
                        }
                    }

                } // end of stages

                post {
                    success {
                        // Cleanup the build directory if the build was successful
                        // (in this case we probably don't have to do any post-build analysis)
                        cleanBeforeCheckout()
                        // remove MatrixCheckout directories older than 30 days to save disk space
                        sh '''
                            set -eu
                            base_dir="../../../.."
                            if [ -d "$base_dir" ]; then
                                find "$base_dir" -name MatrixCheckout -mindepth 3 -maxdepth 3 -type d -mtime +30 -exec rm -rf {} +
                            fi
                        '''
                    }
                } // end of post

            } // end of matrix

        } // main stage ('Test')

    } // main stages

    // Do any post build stuff ... such as sending emails depending on the overall build result.
    post {
        always {
            script {
                def result = currentBuild.currentResult
                // If this build was successful, and the previous build was not successful, send a "back to normal" email.
                def recovered = result == 'SUCCESS' && currentBuild.previousBuild != null \
                        && currentBuild.previousBuild.result != 'SUCCESS'
                if (deployableBranch && (result in ['FAILURE', 'UNSTABLE'] || recovered)) {
                    def status = recovered ? 'STABLE' : result
                    def job = "${env.JOB_NAME} [${env.BRANCH_NAME}] [${env.BUILD_NUMBER}]"
                    emailext(
                            subject: "[BUILD-${status}]: Job '${job}'",
                            body: recovered ? "BUILD-STABLE: Job '${job}': Is back to normal."
                                    : "BUILD-${status}: Job '${job}': Check console output at <a href='${env.BUILD_URL}'>${job}</a>",
                            to: 'dev@shiro.apache.org',
                            recipientProviders: [[$class: 'DevelopersRecipientProvider']]
                    )
                }
            }
        }
    }
}
