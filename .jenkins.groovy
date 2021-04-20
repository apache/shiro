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
                        values 'jdk_1.8_latest', 'adopt_hs_8_latest', 'adopt_j9_8_latest',
                                'jdk_11_latest', 'adopt_hs_11_latest', 'adopt_j9_11_latest',
                                'jdk_15_latest', 'adopt_hs_15_latest', 'adopt_j9_15_latest'
                    }
                    // Additional axess, like OS and maven version can be configured here.
                }

                agent {
                    node {
                        // https://cwiki.apache.org/confluence/display/INFRA/ci-builds.apache.org
                        label 'ubuntu'
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
                        }
                    }

                    stage('Cleanup') {
                        steps {
                            echo 'Cleaning up the workspace'
                            cleanWs()
                        }
                    }

                    stage('Checkout') {
                        steps {
                            echo 'Checking out branch ' + env.BRANCH_NAME
                            checkout scm
                        }
                    }

                    stage('License check') {
                        steps {
                            echo 'License check'
                            sh 'mvn --batch-mode -Drat.consoleOutput=true apache-rat:check'
                        }
                    }

                    stage('Build') {
                        steps {
                            echo 'Building'
                            sh 'mvn --update-snapshots --batch-mode --errors clean verify -Pdocs -Dmaven.test.failure.ignore=true'
                        }
                        post {
                            always {
                                junit(testResults: '**/surefire-reports/*.xml', allowEmptyResults: true)
                                junit(testResults: '**/failsafe-reports/*.xml', allowEmptyResults: true)
                            }
                        }
                    }

                    stage('Deploy') {
                        when {
                            allOf {
                                expression { env.BRANCH_NAME ==~ /(1.6.x|1.7.x|main)/ }
                                expression { MATRIX_JDK == 'jdk_11_latest' }
                                // is not a PR (GitHub) / MergeRequest (GitLab) / Change (Gerrit)?
                                not { changeRequest() }
                            }
                        }
                        steps {
                            echo 'Deploying'
                            sh 'mvn --batch-mode clean deploy -Pdocs -DskipTests'
                        }
                    }

                } // end of stages

                // Do any post build stuff ... such as sending emails depending on the overall build result.
                post {
                    // If this build failed, send an email to the list.
                    failure {
                        script {
                            if (env.BRANCH_NAME == "1.6.x" || env.BRANCH_NAME == "1.7.x" || env.BRANCH_NAME == "main") {
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
                            if (env.BRANCH_NAME == "1.6.x" || env.BRANCH_NAME == "1.7.x" || env.BRANCH_NAME == "main") {
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
                        // (in this cae we probably don't have to do any post-build analysis)
                        cleanWs()
                        script {
                            if ((env.BRANCH_NAME == "1.6.x" || env.BRANCH_NAME == "1.7.x" || env.BRANCH_NAME == "main")
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
