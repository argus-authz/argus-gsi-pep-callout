#!/usr/bin/env groovy

pipeline {

  agent {
    kubernetes {
      cloud 'Kube mwdevel'
      label 'build'
      containerTemplate {
        name 'centos'
        image '7'
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
        container('build'){
          sh "yum install -y epel-release"
          sh "yum install -y git openssl-devel"
          sh "yum -y groupinstall 'Development Tools'"
          sh """
          	yum install -y globus-gssapi-gsi globus-gssapi-gsi-devel globus-gssapi-gsi \\
           		globus-gssapi-gsi-devel globus-gssapi-error globus-gssapi-error-devel \\
           		globus-gss-assist globus-gss-assist-devel globus-gridmap-callout-error \\
           		globus-callout globus-callout-devel globus-gridmap-callout-error globus-gridmap-callout-error-devel 
           """
          script{
          	def repofile = """
[argus-nightly]
name=argus-nightly
baseurl=https://jenkins.cloud.ba.infn.it/job/argus-nightly/lastStableBuild/artifact/el7/RPMS/
gpgcheck=0
          	"""
          	writeFile file: '/etc/yum.repos.d/argus.repo', text: "${repofile}"
          	sh "yum install -y argus-pep-api-c argus-pep-api-c-devel"
          }
        }
      }
    }

    stage('build') {
      steps {
        container('build'){
          sh './autotools.sh'
          sh './configure'
          sh 'make'
        }
      }
    }

    stage('result'){
      steps {
        script {
          currentBuild.result = 'SUCCESS'
        }
      }
    }
  }
  
  post {
    failure {
      slackSend color: 'danger', message: "${env.JOB_NAME} - #${env.BUILD_NUMBER} Failure (<${env.BUILD_URL}|Open>)"
    }
    
    changed {
      script{
        if('SUCCESS'.equals(currentBuild.result)) {
          slackSend color: 'good', message: "${env.JOB_NAME} - #${env.BUILD_NUMBER} Back to normal (<${env.BUILD_URL}|Open>)"
        }
      }
    }
  }
}
