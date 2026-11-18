package io.fluxzero.buildtools;

import com.sun.net.httpserver.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

/** Per-build, fixed-upstream read-only proxy. No open proxy and no token in build-tool configuration. */
public final class RepositoryProxy implements AutoCloseable {
    private final HttpServer server;
    private final ExecutorService executor;
    private final Session session;
    private volatile String failure;
    private final URI upstream;
    private final String password = Session.random();
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NEVER).build();
    public RepositoryProxy(boolean interactive) throws Exception {
        upstream = Session.endpoint(Session.required("PACKAGES_REPOSITORY"));
        if (!upstream.getPath().endsWith("/") || upstream.getRawQuery()!=null)
            throw new IllegalArgumentException("Repository must end in / and have no query.");
        session = new Session(interactive);
        server = HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        executor = Executors.newFixedThreadPool(4,r -> { Thread t = new Thread(r,"packages-proxy"); t.setDaemon(true); return t; });
        server.setExecutor(executor);
        server.createContext("/maven/",this::serve);
        server.start();
    }
    public String url() { return "http://127.0.0.1:"+server.getAddress().getPort()+"/maven/"; }
    public String password() { return password; }
    private void serve(HttpExchange exchange) throws java.io.IOException {
        try {
            String expected = "Basic "+Base64.getEncoder().encodeToString(("local:"+password).getBytes(StandardCharsets.UTF_8));
            String actual = exchange.getRequestHeaders().getFirst("Authorization");
            if (actual==null || !MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),actual.getBytes(StandardCharsets.UTF_8))) {
                exchange.getResponseHeaders().set("WWW-Authenticate","Basic realm=\"packages-local\"");
                exchange.sendResponseHeaders(401,-1); return;
            }
            String path = exchange.getRequestURI().getRawPath();
            String method = exchange.getRequestMethod();
            if (!Set.of("GET","HEAD").contains(method) || exchange.getRequestURI().getRawQuery()!=null
                    || !path.matches("/maven/[A-Za-z0-9_./+\\-]+")
                    || Arrays.asList(path.split("/")).contains("..")) {
                exchange.sendResponseHeaders(400,-1); return;
            }
            URI target = upstream.resolve(path.substring("/maven/".length()));
            if (!target.toString().startsWith(upstream.toString())) { exchange.sendResponseHeaders(400,-1); return; }
            if (failure!=null) { exchange.sendResponseHeaders(401,-1); return; }
            String token = session.token(false,null);
            HttpResponse<java.io.InputStream> response = fetch(target,method,token);
            if (response.statusCode()==401) {
                response.body().close();
                token = session.token(true,token);
                response = fetch(target,method,token);
            }
            int status = response.statusCode();
            if (status>=300 && status<400) { response.body().close(); exchange.sendResponseHeaders(502,-1); return; }
            exchange.getResponseHeaders().set("Cache-Control","no-store");
            // Do not forward upstream headers or error bodies, which can contain credentials or host details.
            if (status!=200 || method.equals("HEAD")) {
                response.body().close(); exchange.sendResponseHeaders(status,-1); return;
            }
            exchange.sendResponseHeaders(200,0);
            try (var body = response.body()) {
                var output = exchange.getResponseBody();
                byte[] buffer = new byte[8192];
                for (int count; (count = body.read(buffer)) != -1;) {
                    output.write(buffer, 0, count);
                    output.flush();
                }
            }
        } catch (Exception e) {
            if (e instanceof Session.Failure) {
                failure = e.getMessage();
                System.err.println("Packages: "+failure);
                exchange.sendResponseHeaders(401,-1);
            } else {
                System.err.println("Packages: private download failed; retry the build.");
                exchange.sendResponseHeaders(503,-1);
            }
        } finally { exchange.close(); }
    }
    private HttpResponse<java.io.InputStream> fetch(URI target,String method,String token) throws Exception {
        return http.send(HttpRequest.newBuilder(target).timeout(Duration.ofSeconds(30))
                .header("Authorization","Bearer "+token).method(method,HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofInputStream());
    }
    @Override public void close() { server.stop(0); executor.shutdownNow(); }
}
