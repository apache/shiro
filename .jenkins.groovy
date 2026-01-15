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

def deployableBranch = env.BRANCH_NAME ==~ /(1.12.x|1.11.x|1.10.x|main)/
def builtinVersion = '999-SNAPSHOT'
def nextVersion

pipeline {

    agent none

    options {
        // When we have test-fails e.g. we don't need to run the remaining steps
        skipStagesAfterUnstable()
        buildDiscarder(logRotator(numToKeepStr: '5', artifactNumToKeepStr: '5'))
    }

    stages {
        stage('Build') {
            matrix {
                axes {
                    axis {
                        // https://cwiki.apache.org/confluence/display/INFRA/JDK+Installation+Matrix
                        name 'MATRIX_JDK'
                        values 'jdk_11_latest', 'jdk_17_latest', 'jdk_21_latest', 'jdk_25_latest'
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

                options {
                    // Configure an overall timeout for the build of one hour.
                    timeout(time: 1, unit: 'HOURS')
                }

                tools {
                    // https://cwiki.apache.org/confluence/display/INFRA/Maven+Installation+Matrix
                    maven 'maven_3_latest'
                    jdk "${MATRIX_JDK}"
                }

                stages {
                    stage('Initialization') {
                        steps {
                            echo 'Building Branch: ' + env.BRANCH_NAME
                            echo 'Using PATH = ' + env.PATH
                            echo 'Slave Node = ' + env.NODE_NAME
                        }
                    }

                    stage('Cleanup') {
                        steps {
                            echo 'Cleaning up the workspace'
                            cleanBeforeCheckout()
                        }
                    }

                    stage('Checkout') {
                        steps {
                            echo 'Checking out branch ' + env.BRANCH_NAME
                            checkout scm
                        }
                    }

                    stage('Use next -SNAPSHOT version') {
                        when {
                            expression { deployableBranch }
                            expression { MATRIX_JDK == 'jdk_11_latest' }
                            // is not a PR (GitHub) / MergeRequest (GitLab) / Change (Gerrit)?
                            not { changeRequest() }
                        }
                        steps {
                            echo 'Setting next -SNAPSHOT version'
                            script {
                                def latestRelease = sh(script: """
                                    curl -sf https://repo1.maven.org/maven2/org/apache/shiro/shiro-root/maven-metadata.xml \
                                    | xmllint --xpath '//metadata/versioning/latest/text()' - 2>/dev/null || echo '$builtinVersion'
                                    """, returnStdout: true
                                ).trim()

                                def parts = latestRelease.tokenize('.')
                                def nextPatch = parts[2].toInteger() + 1
                                nextVersion = "${parts[0]}.${parts[1]}.${nextPatch}-SNAPSHOT"

                                echo "Latest release: ${latestRelease}, next SNAPSHOT: ${nextVersion}"
                            }

                            sh "./mvnw -B versions:set -DprocessAllModules=true -DgenerateBackupPoms=false \
                                -DoldVersion=${builtinVersion} -DnewVersion=${nextVersion}"
                        }
                    }

                    stage('License check') {
                        steps {
                            echo 'License check'
                            sh './mvnw --batch-mode -Drat.consoleOutput=true apache-rat:check'
                        }
                    }

                    stage('Build') {
                        steps {
                            echo 'Building'
                            sh './mvnw clean verify --show-version --errors --batch-mode --no-transfer-progress -Pdocs \
                            -Dmaven.test.failure.ignore=true -Pskip_jakarta_ee_tests'
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
                            allOf {
                                expression { deployableBranch }
                                expression { MATRIX_JDK == 'jdk_11_latest' }
                                // is not a PR (GitHub) / MergeRequest (GitLab) / Change (Gerrit)?
                                not { changeRequest() }
                            }
                        }
                        steps {
                            echo 'Deploying'
                            sh './mvnw --batch-mode clean deploy -Pdocs -DskipTests -DskipITs'
                        }
                    }

                } // end of stages

                // Do any post build stuff ... such as sending emails depending on the overall build result.
                post {
                    // If this build failed, send an email to the list.
                    failure {
                        script {
                            if (deployableBranch) {
                                emailext(
                                        subject: "[BUILD-FAILURE]: Job '${env.JOB_NAME} [${env.BRANCH_NAME}] [${env.BUILD_NUMBER}]'",
                                        body: """
BUILD-FAILURE: Job '${env.JOB_NAME} [${env.BRANCH_NAME}] [${env.BUILD_NUMBER}]':
Check console output at "<a href="${env.BUILD_URL}">${env.JOB_NAME} [${env.BRANCH_NAME}] [${env.BUILD_NUMBER}]</a>"
""",
                                        to: "dev@shiro.apache.org",
                                        recipientProviders: [[$class: 'DevelopersRecipientProvider']]
                                )
                            }
                        }
                    }

                    // If this build didn't fail, but there were failing tests, send an email to the list.
                    unstable {
                        script {
                            if (deployableBranch) {
                                emailext(
                                        subject: "[BUILD-UNSTABLE]: Job '${env.JOB_NAME} [${env.BRANCH_NAME}] [${env.BUILD_NUMBER}]'",
                                        body: """
BUILD-UNSTABLE: Job '${env.JOB_NAME} [${env.BRANCH_NAME}] [${env.BUILD_NUMBER}]':
Check console output at "<a href="${env.BUILD_URL}">${env.JOB_NAME} [${env.BRANCH_NAME}] [${env.BUILD_NUMBER}]</a>"
""",
                                        to: "dev@shiro.apache.org",
                                        recipientProviders: [[$class: 'DevelopersRecipientProvider']]
                                )
                            }
                        }
                    }

                    // Send an email, if the last build was not successful and this one is.
                    success {
                        // Cleanup the build directory if the build was successful
                        // (in this case we probably don't have to do any post-build analysis)
                        cleanBeforeCheckout()
                        script {
                            if (deployableBranch
                                    && (currentBuild.previousBuild != null) && (currentBuild.previousBuild.result != 'SUCCESS')) {
                                emailext(
                                        subject: "[BUILD-STABLE]: Job '${env.JOB_NAME} [${env.BRANCH_NAME}] [${env.BUILD_NUMBER}]'",
                                        body: """
BUILD-STABLE: Job '${env.JOB_NAME} [${env.BRANCH_NAME}] [${env.BUILD_NUMBER}]':
Is back to normal.
""",
                                        to: "dev@shiro.apache.org",
                                        recipientProviders: [[$class: 'DevelopersRecipientProvider']]
                                )
                            }
                        }
                    }
                } // end of post

            } // end of matrix

        } // main stage ('Build')

    } // main stages
}
