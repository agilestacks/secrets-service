#!/usr/bin/env groovy

pipeline {
  triggers {
    githubPush()
    pollSCM('H/15 * * * *')
  }

  parameters {
    string(name: 'HUB_ELABORATE', defaultValue: env.HUB_ELABORATE, description: 'S3 location of current stack state')
    string(name: 'HUB_STATE', defaultValue: env.HUB_STATE, description: 'S3 location of current stack state')
    booleanParam(name: 'CLEAN_WORKSPACE', defaultValue: false, description: 'Start with empty workspace')
  }

  agent {
    kubernetes {
      label 'secrets-service-pipeline'
      inheritFrom 'toolbox'
      containerTemplate {
        name 'nodejs'
        image 'node:10'
        ttyEnabled true
        command 'cat'
      }
    }
  }

  stages {
    stage('Clean') {
      steps {
        script {
          if (params.CLEAN_WORKSPACE) {
            echo 'Wiping out workspace'
            deleteDir()
          } else {
            echo 'Skipping cleanup due to user setting'
          }
        }
      }
    }

    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Compile') {
      steps {
        container('nodejs') {
          dir('api') {
            sh script: 'npm install'
            sh script: 'npm run lint:junit'
          }
        }
      }
    }

    stage('Build') {
      steps {
        container('toolbox') {
          dir('api') {
            script {
              final component = hub.explain(state: params.HUB_STATE).components['secrets-service-ecr']
              imageName = component.outputs['component.docker.registry.image'] as String
              region = component.parameters['cloud.region'] as String
              image = "${imageName}:${gitscm.getShortCommit()}"

              sh script: """
                aws ecr get-login --region=${region} | sed -e 's/[ +]-e[ +]none[ +]/ /g' | sh -
                docker build -t ${image} .
                docker push ${image}
              """
            }
          }
        }
      }
    }

    stage('Deploy') {
      steps {
        container('toolbox') {
          script {
            hub.kubeconfig(state: params.HUB_STATE, switchContext: true)
            final namespace = 'automation-hub'
            final name = 'secrets-service'
            sh script: "kubectl -n ${namespace} --record 'deployment/${name}' set image 'api=${image}'"
          }
        }
      }
    }
  }

  post {
    always {
      junit testResults: 'api/*-junit.xml',
            allowEmptyResults: true,
            keepLongStdio: true
    }
    changed {
      slackSend color: slack.buildColor(),
                message: slack.buildReport()
    }
  }
}
