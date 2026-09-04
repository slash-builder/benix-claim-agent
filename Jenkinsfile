// benix-claim-agent CI: fmt -> clippy -> test -> build, plus a real musl
// cross-compile stage. Modeled on benix-mdns-advertiser's own Jenkinsfile
// shape.
//
// This crate resolves fabric-kit from the private `lockamy` Nexus
// registry (`.cargo/config.toml`, committed — the index URL is not a
// secret). No credential binding is needed to build/test/clippy against
// it: checked before assuming otherwise, the `cargo-group` registry's
// index and crate downloads are unauthenticated reads (confirmed with a
// bare `curl` against both the sparse-index JSON and a crate .crate
// download — no `Authorization` header sent, both returned 200). A token
// is only needed for `cargo publish`, which this repo doesn't do.
// fabric-kit's own Jenkinsfile confirms the same shape — no
// `credentialsId`/Nexus-token binding anywhere in it either, and its own
// Build & Test / musl stages resolve the same registry regardless.
//
// No publish stage yet. README.md's "Known gaps" section names this
// explicitly. Not run for real against this project's actual Jenkins
// instance from this environment (no Jenkins access here) — see the
// repo's GitHub Actions run for the real, executed equivalent of the same
// checks.
def RUST_IMAGE = 'rust:1.90-trixie'

pipeline {
  agent { label 'linux-build' }

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
      // args '-u root:root' -- confirmed live, 2026-09-04: Jenkins' Docker
      // Pipeline plugin runs `docker { }` agent-block containers as a fixed
      // non-root UID (5005), so `apt-get update`/`install` below fails with
      // "Permission denied" on /var/lib/apt/lists/lock without this. Same
      // real bug found and fixed the same way tonight in
      // slash-builder/benix-mdns-advertiser and slash-builder/storage-kit --
      // this is the third repo in this kit-repo family hitting it.
      agent { docker { image RUST_IMAGE; reuseNode true; args '-u root:root' } }
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
