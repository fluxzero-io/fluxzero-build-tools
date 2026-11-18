package io.fluxzero.buildtools;

import org.apache.maven.AbstractMavenLifecycleParticipant;
import org.apache.maven.execution.MavenSession;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.util.repository.AuthenticationBuilder;

public final class MavenAuth extends AbstractMavenLifecycleParticipant {
    private RepositoryProxy proxy;
    @Override public void afterSessionStart(MavenSession session) {
        try {
            proxy = new RepositoryProxy(session.getRequest().isInteractiveMode());

            var resolver = (DefaultRepositorySystemSession)session.getRepositorySession();
            var original = resolver.getAuthenticationSelector();
            var mirrors = resolver.getMirrorSelector();
            resolver.setMirrorSelector(repository -> {
                if (repository.getId().equals("packages-private")
                        && repository.getUrl().equals(Session.required("PACKAGES_REPOSITORY")))
                    return new org.eclipse.aether.repository.RemoteRepository.Builder("packages-private-proxy","default",proxy.url()).build();
                return mirrors.getMirror(repository);
            });
            resolver.setAuthenticationSelector(repository -> {
                if (repository.getId().equals("packages-private-proxy") && repository.getUrl().equals(proxy.url()))
                    return new AuthenticationBuilder().addUsername("local").addPassword(proxy.password()).build();
                return original.getAuthentication(repository);
            });
        } catch (Exception e) { throw new IllegalStateException("Cannot start Packages authentication",e); }
    }
    @Override public void afterSessionEnd(MavenSession session) { if (proxy!=null) proxy.close(); }
}
