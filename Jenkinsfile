pipeline {
    agent any

    environment {
        REPO_URL = 'https://github.com/NobitaXD/SSD-Final.git'  // URL of your GitHub repository
    }

    stages {
        stage('Clone Repository') {
            steps {
                // Clone the repository from GitHub
                git url: "${REPO_URL}", branch: 'main' // Replace with the branch you are using (e.g., 'main', 'dev')
            }
        }

        stage('Install Dependencies') {
            steps {
                script {
                    // Assuming the application uses npm (adjust as necessary)
                    // Replace with the appropriate command to install dependencies for your project
                    sh 'npm install'  // or another command if not using Node.js
                }
            }
        }

        stage('Run Unit Tests') {
            steps {
                script {
                    // Replace with the command to run your unit tests
                    sh 'npm test'  // or other testing commands for your specific stack
                }
            }
        }

        stage('Build Application') {
            steps {
                script {
                    // Replace with the build command for your application (if applicable)
                    sh 'npm run build'  // Adjust according to your build process
                }
            }
        }

        stage('Deploy Application') {
            steps {
                script {
                    // Deploy the application, replace with the actual deployment command
                    sh './deploy.sh'  // Example: this could be a script or a command
                }
            }
        }
    }

    post {
        always {
            cleanWs()  // Clean workspace after build
        }
    }
}

