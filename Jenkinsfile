#!/usr/bin/env groovy

pipeline {

  agent {
    kubernetes {
      cloud 'Kube mwdevel'
      label 'build'
      containerTemplate {
        name 'builder'
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
        container('builder'){
          script{
          	def repofile = """
[argus-nightly]
name=argus-nightly
baseurl=https://jenkins.cloud.ba.infn.it/job/argus-nightly/lastStableBuild/artifact/el7/RPMS/
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
    }

    stage('builder') {
      steps {
        container('builder'){
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
