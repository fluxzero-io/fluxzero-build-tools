package io.fluxzero.buildtools;

import org.gradle.api.Plugin;
import org.gradle.api.initialization.Settings;
import org.gradle.authentication.http.BasicAuthentication;

/** POC lifecycle: configuration cache explicitly rejected, so a cached endpoint cannot survive a build. */
public final class GradleAuth implements Plugin<Settings> {
    @Override public void apply(Settings settings) {
        if (settings.getGradle().getStartParameter().isConfigurationCacheRequested())
            throw new IllegalStateException("Packages browser-auth POC requires --no-configuration-cache.");
        try {
            RepositoryProxy proxy = new RepositoryProxy(!"true".equalsIgnoreCase(System.getenv("CI"))
                    && !"false".equalsIgnoreCase(System.getenv("PACKAGES_INTERACTIVE")));
            settings.getGradle().buildFinished(result -> proxy.close());
            settings.getDependencyResolutionManagement().getRepositories().maven(repository -> {
                repository.setName("packagesPrivate"); repository.setUrl(proxy.url()); repository.setAllowInsecureProtocol(true);
                repository.credentials(credentials -> { credentials.setUsername("local"); credentials.setPassword(proxy.password()); });
                repository.getAuthentication().create("basic", BasicAuthentication.class);
            });
            settings.getPluginManagement().getRepositories().maven(repository -> {
                repository.setName("packagesPrivatePlugins"); repository.setUrl(proxy.url()); repository.setAllowInsecureProtocol(true);
                repository.credentials(credentials -> { credentials.setUsername("local"); credentials.setPassword(proxy.password()); });
                repository.getAuthentication().create("basic", BasicAuthentication.class);
            });
        } catch (Exception e) { throw new IllegalStateException("Cannot start Packages authentication",e); }
    }
}
