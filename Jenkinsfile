pipeline {
    agent {
        node {
            label "nanopb_off_target"
        }
    }
    options {
        timeout(time: 1, unit: 'HOURS')
        timestamps()
        buildDiscarder(logRotator(numToKeepStr: '10'))
        skipDefaultCheckout()
    }
    triggers {
        issueCommentTrigger('.*TEST!.*')
    }
    stages {
        stage('checkout'){
            steps{
                checkout scm
            }
        }
        stage('build and test'){
            steps {
                dir("${env.WORKSPACE}") {
                    sh "bash ${env.WORKSPACE}/build_and_test.sh"
                }
            }
        }
    }
}
