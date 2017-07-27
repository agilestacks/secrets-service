#!/usr/bin/env groovy

import com.amazonaws.util.*
import com.amazonaws.auth.*
import com.amazonaws.services.ecr.*
import com.amazonaws.services.ecr.model.*
import com.amazonaws.regions.*
import io.fabric8.kubernetes.api.model.NamespaceBuilder
import io.fabric8.kubernetes.client.*

def secretsServiceImage
def secretsServiceEndpoint
def commit
def imageTag1
def imageTag2
def namespace = 'automation-hub'
def region    = Regions.currentRegion.name

@NonCPS
def kubeClient() {
    return new DefaultKubernetesClient(new ConfigBuilder().withNamespace('automation-hub').build())
}

@NonCPS
def authenticateECR(region=EC2MetadataUtils.getEC2InstanceRegion()){
 def token = AmazonECRClientBuilder.
               standard().
               withCredentials(InstanceProfileCredentialsProvider.getInstance()).
               withRegion(region).
               build().
               getAuthorizationToken(new GetAuthorizationTokenRequest())
 def auth = token.authorizationData[0]
 login = new String(auth.authorizationToken.decodeBase64()).tokenize(':')
 return  [
     "registry" : auth.proxyEndpoint,
     "user"     : login[0],
     "password" : login[1]
 ]
}

@NonCPS
def updateDeploymentImage(deployment, imageWithVersion) {
    def imageWithoutVersion = imageWithVersion.split(':')[0]
    deployment.spec.template.spec.containers.find({ it ->
        it.image.startsWith(imageWithoutVersion)
    }).each({ it ->
        it.image = imageWithVersion
    })
    return deployment
}

@NonCPS
def commitHash() {
  sh 'git rev-parse HEAD > commit'
  readFile('commit').trim().substring(0, 7)
}

node('master') {
    stage('Checkout') {
        // checkout scm
        git credentialsId: 'github-user', url: 'https://github.com/agilestacks/secrets-service.git'
        commit = commitHash()
    }

    stage('Initialize') {
        def slurper   = new groovy.json.JsonSlurper()
        def jsonFile  = kubeClient().
                          configMaps().
                          inNamespace(namespace).
                          withName('jenkins').get().data['cloud.json']
        def conf  = slurper.parseText(jsonFile)

        secretsServiceImage    = conf.secrets_service_image
        secretsServiceEndpoint = conf.secrets_service_endpoint
    }
}

podTemplate( inheritFrom: 'agilestacks',label: 'pod',
    containers: [
      containerTemplate(name: 'node', image: 'node:8', ttyEnabled: true, command: 'cat'),
      containerTemplate(name: 'dredd', image: 'apiaryio/dredd', ttyEnabled: true, command: 'cat')
    ],
    volumes: [emptyDirVolume(memory: false, mountPath: '/var/lib/docker')]
) {
    node('pod') {
        dir('api') {
            stage('Compile') {
                container('node') {
                    sh 'make install lint'       
                }
            }
            stage('Build Container') {
                def auth = authenticateECR(region)
                imageTag1 = "${secretsServiceImage}:${commit}"
                imageTag2 = "${secretsServiceImage}:build-${env.BUILD_NUMBER}"

                container('dind') {
                    sh """
                        docker login -u ${auth.user} -p ${auth.password} ${auth.registry}
                        docker build -t ${imageTag1} . 
                        docker tag ${imageTag1} ${imageTag2}
                        docker push ${imageTag1}
                        docker push ${imageTag2}
                    """
                }
            
            }

            stage('Deploy Pod') {
                def client    = kubeClient()
                def deplOpts  = client.
                                  extensions().
                                  deployments().
                                  inNamespace(namespace).
                                  withName('secrets')

                def result    = updateDeploymentImage(deplOpts.get(), imageTag1)
                deplOpts.replace(result)
            }

            stage('Test') {
                container('dredd') {
                    // def dreddConfig = readFile file: 'test/dredd.yaml'
                    // echo "Replace URL from dredd.yaml to ${secretsServiceEndpoint}"
                    // dreddConfig.replaceAll(/endpoint:.*/, "endpoint: ${secretsServiceEndpoint}")
                    // writeFile file: 'test/dredd-jenkins.yaml', text: dreddConfig

                    // sh "dredd --config test/dredd-jenkins.yaml"
                    echo Do nothing so far
                    // sleep time: 600
                }
            }
        }
    }
}

