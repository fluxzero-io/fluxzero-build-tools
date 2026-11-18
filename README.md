# Fluxzero Build Tools

Experimental browser authentication for private Maven and Gradle downloads.
Public artifacts are hosted at [Fluxzero Packages](https://packages.fluxzero.io/maven/).

One repository, three modules: `common` owns PKCE login, session storage and the
per-build loopback proxy; `maven-extension` and `gradle-plugin` adapt their build
lifecycles. Both adapter JARs bundle common and Gson, so their bootstrap does not
require authentication. Maven/Gradle host APIs are not bundled.

## Status and prerequisites

This is an experimental release, not a production-ready authentication product.
The integration fixture tests Maven 3.9.16, Gradle 9.3.1 and Java 25 on Linux;
the originating local-IDP POC was also qualified on macOS. Sources target Java 17.
Requires POSIX file permissions. Windows, Maven 4, IDE import, private build/settings
plugins, included builds and crash recovery after a lost refresh response are not
qualified. Gradle configuration cache is deliberately rejected; run with
`--no-configuration-cache`. The plugin currently uses deprecated `buildFinished`.

No production IDP client or private Packages endpoint is provisioned by installing
these artifacts. A repository administrator must supply a compatible private
repository and native public OIDC client: code + refresh grants, S256 PKCE,
exact callback `http://127.0.0.1:18743/callback`, required scopes and audience.

## Shared public configuration

Set these environment variables for either build tool:

```sh
export PACKAGES_ISSUER='https://your-idp.example'
export PACKAGES_CLIENT_ID='your-native-client'
export PACKAGES_SCOPE='openid packages:read'
export PACKAGES_REPOSITORY='https://your-repository.example/private/'
export PACKAGES_SESSION_DIR="$HOME/.fluxzero-packages-session"
```

Use an existing parent directory; the extension creates the final session directory
with mode 0700 and writes files with mode 0600. Files are not encrypted or stored in
Keychain, and are accessible to other programs running as the same OS user.
Both tools share the session with a file lock and atomic replacement.

The first private download opens a browser. macOS uses `/usr/bin/open`; on Linux
set `PACKAGES_BROWSER` to the absolute path of a browser launcher such as `xdg-open`.
This variable names an executable, not a shell command. Refresh is automatic and
bounded by the IDP session. `CI=true`, `PACKAGES_INTERACTIVE=false`, or Maven batch
mode prevent interactive login. A valid existing session can refresh in CI.
Revocation clears saved state and fails the build; a later interactive build can
sign in again. Do not copy personal session files into shared CI environments.

## Maven

Add `.mvn/extensions.xml`:

```xml
<extensions>
  <extension>
    <groupId>io.fluxzero.buildtools</groupId>
    <artifactId>maven-extension</artifactId>
    <version>0.1.0</version>
  </extension>
</extensions>
```

The extension needs an anonymous **plugin repository in Maven settings**, available
before the project's private parent is resolved. Merge this profile into your
settings or a project `.mvn/settings.xml` selected using `--settings`:

```xml
<settings>
  <profiles>
    <profile>
      <id>fluxzero-bootstrap</id>
      <pluginRepositories>
        <pluginRepository>
          <id>fluxzero-public</id>
          <url>https://packages.fluxzero.io/maven</url>
        </pluginRepository>
      </pluginRepositories>
    </profile>
  </profiles>
  <activeProfiles><activeProfile>fluxzero-bootstrap</activeProfile></activeProfiles>
</settings>
```

The private repository in the project POM must have ID `packages-private` and its
URL must exactly match `PACKAGES_REPOSITORY`. The extension replaces only that
repository with its local proxy. Public repository configuration stays ordinary.

## Gradle

In `settings.gradle`, before other settings configuration:

```groovy
pluginManagement {
    repositories {
        maven { url = uri('https://packages.fluxzero.io/maven') }
        gradlePluginPortal()
    }
}
plugins {
    id 'io.fluxzero.packages' version '0.1.0'
}
```

Run `./gradlew --no-configuration-cache build`. The plugin adds the private
repository using the shared environment configuration. It cannot authenticate its
own bootstrap or plugins that were resolved before it was applied. The marker POM
is published to Packages; no Gradle Plugin Portal publication is required.

## Proxy lifetime

Each build starts an authenticated HTTP proxy on a free `127.0.0.1` port inside
its JVM, restricted to GET/HEAD for the configured upstream. There is no installed
background service. Tokens never enter Maven settings or Gradle credentials;
build tools receive a random per-build local password. The proxy refreshes tokens
per download, does not follow upstream redirects, and streams response chunks.
Maven session completion and Gradle build completion close it, including failed
builds; the Gradle daemon can remain alive. An upstream 401 permits one refresh
and retry. Immediate access-token revocation depends on the resource server.

## Build, test and release

```sh
./gradlew --no-daemon check publishAllPublicationsToFixtureRepository
python3 scripts/acceptance.py
```

The acceptance suite uses disposable wrapper projects and an explicitly simulated
OIDC issuer. It covers first login, reuse, refresh during downloads, concurrent
builds, rejection after revocation, configuration-cache rejection and CI denial.
It is not evidence of a real browser or production IDP login. Outputs and local
sessions stay under ignored `build/`; sessions are removed on normal exit.

Use `PUBLISHED_BOOTSTRAP=https://packages.fluxzero.io/maven/ python3 scripts/acceptance.py`
to test consumers against released artifacts instead of rebuilding the plugins.

All modules share the version in `gradle.properties`. Update the README examples
with it, run the checks, then push a matching `vX.Y.Z` tag. The release workflow
retests both wrappers, obtains short-lived GitHub OIDC credentials, publishes to
Packages, compares anonymous downloads to the tested bytes and reruns consumers
against the published artifacts. GitHub prereleases preserve publication files
in an archive. Uploads are unsigned; repository checksums are published.
Dependabot covers Gradle dependencies/wrapper and GitHub Actions weekly.
