#!/usr/bin/env groovy

@Library('sd')_
def kubeLabel = getKubeLabel()

pipeline {

  agent {
    kubernetes {
      label "${kubeLabel}"
      cloud 'Kube mwdevel'
      defaultContainer 'runner'
      inheritFrom 'ci-template'
      containerTemplate {
        name 'runner'
        image 'centos:7'
        ttyEnabled true
        command 'cat'
      }
    }
  }
  
  options {
    timeout(time: 2, unit: 'HOURS')
    buildDiscarder(logRotator(numToKeepStr: '5'))
  }
  
  stages {
    stage('prepare') {
      steps {
        script{
          def repofile = """
[argus-nightly]
name=argus-nightly
baseurl=https://repo.cloud.cnaf.infn.it/repository/argus/nightly/el7/
gpgcheck=0
          """
          writeFile file: 'argus.repo', text: "${repofile}"
          sh "cp argus.repo /etc/yum.repos.d/argus.repo"
        }

        sh "yum install -y epel-release"
        sh "yum -y groupinstall 'Development Tools'"
        sh """
          yum install -y git openssl-devel \\
	    globus-gridmap-callout-error-devel \\
	    globus-gssapi-gsi-devel \\
	    globus-gssapi-error-devel \\
	    globus-gss-assist-devel \\
            argus-pep-api-c-devel
        """
      }
    }

    stage('builder') {
      steps {
        sh './autotools.sh'
        sh './configure'
        sh 'make'
      }
    }
  }
  
  post {
    failure {
      slackSend color: 'danger', message: "${env.JOB_NAME} - #${env.BUILD_NUMBER} Failure (<${env.BUILD_URL}|Open>)"
    }
    
    changed {
      script {
        if ('SUCCESS'.equals(currentBuild.currentResult)) {
          slackSend color: 'good', message: "${env.JOB_NAME} - #${env.BUILD_NUMBER} Back to normal (<${env.BUILD_URL}|Open>)"
        }
      }
    }
  }
}
