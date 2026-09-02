// benix-claim-agent CI: fmt -> clippy -> test -> build, plus a real musl
// cross-compile stage. Modeled on benix-mdns-advertiser's own Jenkinsfile
// shape, with one addition: this crate resolves fabric-kit from the
// private `lockamy` Nexus registry, so both stages need CARGO_HOME pointed
// at a directory carrying real registry credentials (Jenkins credential
// binding, not committed — same pattern fabric-kit's own Jenkinsfile and
// quickring/gateway's use).
//
// No publish stage yet. README.md's "Known gaps" section names this
// explicitly. Not run for real against this project's actual Jenkins
// instance from this environment (no Jenkins access here) — see the
// repo's GitHub Actions run for the real, executed equivalent of the same
// checks.
def RUST_IMAGE = 'rust:1.90-trixie'

pipeline {
  agent { label 'linux-build' }

  environment {
    CARGO_HOME = "${WORKSPACE}/.cargo-home"
  }

  stages {

    stage('Pre-flight') {
      steps {
        script {
          def msg = sh(script: 'git log -1 --pretty=%B', returnStdout: true).trim()
          if (msg.contains('[skip ci]')) {
            currentBuild.result = 'NOT_BUILT'
            error('Commit contains [skip ci] — aborting.')
          }
        }
      }
    }

    stage('Registry credentials') {
      steps {
        withCredentials([string(credentialsId: 'nexus-lockamy-cargo-token', variable: 'LOCKAMY_TOKEN')]) {
          sh '''
            mkdir -p "$CARGO_HOME"
            cp .cargo/config.toml "$CARGO_HOME/config.toml"
            printf '[registries.lockamy]\ntoken = "%s"\n' "$LOCKAMY_TOKEN" > "$CARGO_HOME/credentials.toml"
          '''
        }
      }
    }

    stage('Build & Test') {
      agent { docker { image RUST_IMAGE; reuseNode true } }
      steps {
        sh '''
          rustup component add rustfmt clippy
          cargo fmt --check
          cargo clippy --all-targets -- -D warnings
          cargo test
          cargo build --release
        '''
      }
    }

    stage('musl cross-compile') {
      agent { docker { image RUST_IMAGE; reuseNode true } }
      steps {
        sh '''
          apt-get update -qq
          apt-get install -y -qq --no-install-recommends musl-tools
          rustup target add x86_64-unknown-linux-musl
          cargo build --release --target x86_64-unknown-linux-musl
          out="$(file -b target/x86_64-unknown-linux-musl/release/benix-claim-agent)"
          echo "$out"
          case "$out" in
            *"statically linked"*|*"static-pie linked"*) echo "Confirmed static." ;;
            *) echo "Expected a static/static-pie binary, got: $out"; exit 1 ;;
          esac
        '''
      }
    }
  }
  post {
    success { echo 'benix-claim-agent pipeline succeeded' }
    failure { echo 'Pipeline failed.' }
    always  { cleanWs() }
  }
}
