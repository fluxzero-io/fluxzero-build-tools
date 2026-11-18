package io.fluxzero.buildtools;

import com.google.gson.*;
import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.net.http.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import static java.nio.file.StandardOpenOption.*;

/** Local POSIX prototype. Session files are private to the OS user, not encrypted at rest. */
public final class Session {
    private static final Object JVM_LOCK = new Object();
    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NEVER).build();
    private final String issuer = required("PACKAGES_ISSUER");
    private final String client = required("PACKAGES_CLIENT_ID");
    private final String scope = required("PACKAGES_SCOPE");
    private final Path directory;
    private final String identity;
    private final boolean interactive;
    private String authorizationEndpoint;
    private String tokenEndpoint;

    public Session(boolean interactive) throws Exception {
        endpoint(issuer);
        this.interactive = interactive && !"false".equalsIgnoreCase(System.getenv("PACKAGES_INTERACTIVE")) && !"true".equalsIgnoreCase(System.getenv("CI"));
        directory = Path.of(required("PACKAGES_SESSION_DIR")).toAbsolutePath();
        if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
            Files.createDirectory(directory, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        }
        secure(directory, "rwx------");
        identity = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest((issuer+'\n'+client+'\n'+scope).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }

    public String token(boolean forceRefresh, String rejectedToken) throws Exception {
        synchronized (JVM_LOCK) {
            Path lock = directory.resolve(identity+".lock");
            if (!Files.exists(lock, LinkOption.NOFOLLOW_LINKS)) {
                try { Files.createFile(lock, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))); }
                catch (FileAlreadyExistsException ignored) { }
            }
            secure(lock,"rw-------");
            try (FileChannel channel = FileChannel.open(lock, WRITE, LinkOption.NOFOLLOW_LINKS)) {
                FileLock held = null;
                long deadline = System.nanoTime()+TimeUnit.SECONDS.toNanos(interactive ? 180 : 15);
                while (held == null && System.nanoTime()<deadline) {
                    try { held = channel.tryLock(); } catch (OverlappingFileLockException ignored) { }
                    if (held == null) Thread.sleep(50);
                }
                if (held == null) throw new Failure("Packages login is busy; retry the build.");
                try (FileLock ignored = held) {
                    Path file = directory.resolve(identity+".json");
                    JsonObject saved = null;
                    if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
                        secure(file,"rw-------");
                        saved = JsonParser.parseString(Files.readString(file)).getAsJsonObject();
                    }
                    if (saved != null && saved.get("expires_at").getAsLong()>Instant.now().getEpochSecond()+1
                            && (!forceRefresh || !saved.get("access_token").getAsString().equals(rejectedToken))) {
                        return saved.get("access_token").getAsString();
                    }
                    discover();
                    JsonObject response;
                    if (saved != null) {
                        try {
                            response = exchange(Map.of("grant_type","refresh_token","client_id",client,
                                    "refresh_token",saved.get("refresh_token").getAsString()));
                        } catch (Revoked e) {
                            Files.deleteIfExists(file);
                            throw new Failure("Packages session expired or revoked. Run an interactive wrapper build to sign in again.");
                        }
                    } else {
                        if (!interactive) throw new Failure("Packages login required. Run an interactive wrapper build first; CI never opens a browser.");
                        response = login();
                    }
                    if (!response.has("refresh_token") || !response.has("access_token")
                            || !response.has("expires_in") || !"Bearer".equalsIgnoreCase(response.get("token_type").getAsString()))
                        throw new Failure("IDP returned an unsupported token response.");
                    long lifetime = response.get("expires_in").getAsLong();
                    if (lifetime<1 || lifetime>86400) throw new Failure("Unsupported access-token lifetime.");
                    JsonObject persisted = new JsonObject();
                    persisted.add("access_token",response.get("access_token"));
                    persisted.add("refresh_token",response.get("refresh_token"));
                    persisted.addProperty("expires_at",Instant.now().getEpochSecond()+lifetime);
                    Path temp = Files.createTempFile(directory,"session-",".tmp",
                            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                    try {
                        Files.writeString(temp,persisted.toString(),TRUNCATE_EXISTING);
                        try (FileChannel output = FileChannel.open(temp,WRITE)) { output.force(true); }
                        Files.move(temp,file,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
                    } finally { Files.deleteIfExists(temp); }
                    return persisted.get("access_token").getAsString();
                }
            }
        }
    }

    private void discover() throws Exception {
        if (tokenEndpoint!=null) return;
        HttpResponse<String> response = HTTP.send(HttpRequest.newBuilder(endpoint(issuer+"/.well-known/openid-configuration"))
                .timeout(Duration.ofSeconds(15)).GET().build(),HttpResponse.BodyHandlers.ofString());
        if (response.statusCode()!=200) throw new Failure("IDP discovery unavailable.");
        JsonObject metadata = JsonParser.parseString(response.body()).getAsJsonObject();
        if (!issuer.equals(metadata.get("issuer").getAsString())) throw new Failure("IDP issuer mismatch.");
        authorizationEndpoint = metadata.get("authorization_endpoint").getAsString();
        tokenEndpoint = metadata.get("token_endpoint").getAsString();
        // POC intentionally accepts endpoints only on the configured issuer origin.
        for (String value : List.of(authorizationEndpoint,tokenEndpoint)) {
            URI uri = endpoint(value), origin = URI.create(issuer);
            if (!Objects.equals(uri.getScheme(),origin.getScheme()) || !Objects.equals(uri.getAuthority(),origin.getAuthority()))
                throw new Failure("Cross-origin IDP endpoints are not supported by this POC.");
        }
    }

    private JsonObject login() throws Exception {
        String state = random(), verifier = random();
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256")
                .digest(verifier.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        int port = Integer.parseInt(System.getenv().getOrDefault("PACKAGES_CALLBACK_PORT","18743"));
        String redirect = "http://127.0.0.1:"+port+"/callback";
        HttpServer callback = HttpServer.create(new InetSocketAddress("127.0.0.1",port),0);
        CompletableFuture<String> code = new CompletableFuture<>();
        callback.createContext("/callback", exchange -> {
            try {
                Map<String,String> query = new HashMap<>();
                String raw = exchange.getRequestURI().getRawQuery();
                if (raw!=null) for (String item:raw.split("&")) {
                    String[] pair = item.split("=",2);
                    String key = URLDecoder.decode(pair[0],java.nio.charset.StandardCharsets.UTF_8);
                    if (query.put(key,pair.length==2?URLDecoder.decode(pair[1],java.nio.charset.StandardCharsets.UTF_8):"")!=null)
                        throw new IllegalArgumentException();
                }
                boolean valid = exchange.getRequestMethod().equals("GET")
                        && exchange.getRequestURI().getPath().equals("/callback") && state.equals(query.get("state"))
                        && ("127.0.0.1:"+port).equals(exchange.getRequestHeaders().getFirst("Host"))
                        && query.containsKey("code") && !query.containsKey("error");
                byte[] body = (valid?"Login received. You can close this tab.":"Invalid login callback.").getBytes();
                exchange.getResponseHeaders().set("Cache-Control","no-store");
                exchange.getResponseHeaders().set("Content-Security-Policy","default-src 'none'");
                exchange.sendResponseHeaders(valid?200:400,body.length);
                exchange.getResponseBody().write(body);
                if (valid) code.complete(query.get("code"));
            } catch (Exception ignored) { exchange.sendResponseHeaders(400,-1); }
            finally { exchange.close(); }
        });
        callback.start();
        try {
            String url = authorizationEndpoint+"?"+form(Map.of("response_type","code","client_id",client,
                    "redirect_uri",redirect,"scope",scope,"state",state,"nonce",random(),"code_challenge",challenge,"code_challenge_method","S256"));
            System.err.println("Packages: opening your browser for login (up to 120 seconds).");
            // No shell, URL not written to logs. Test browser executable is explicitly opt-in.
            String browser = System.getenv().getOrDefault("PACKAGES_BROWSER","/usr/bin/open");
            Process process = new ProcessBuilder(browser,url).redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .redirectError(ProcessBuilder.Redirect.DISCARD).start();
            if (!process.waitFor(10,TimeUnit.SECONDS) || process.exitValue()!=0) {
                process.destroyForcibly(); throw new Failure("Could not open the login browser.");
            }
            return exchange(Map.of("grant_type","authorization_code","client_id",client,"redirect_uri",redirect,
                    "code",code.get(120,TimeUnit.SECONDS),"code_verifier",verifier));
        } finally { callback.stop(0); }
    }

    private JsonObject exchange(Map<String,String> parameters) throws Exception {
        HttpResponse<String> response = HTTP.send(HttpRequest.newBuilder(endpoint(tokenEndpoint))
                .timeout(Duration.ofSeconds(20)).header("Content-Type","application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form(parameters))).build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode()!=200) {
            if (response.statusCode()==400 && response.body().contains("invalid_grant")) throw new Revoked();
            throw new Failure("IDP token request failed (HTTP "+response.statusCode()+").");
        }
        return JsonParser.parseString(response.body()).getAsJsonObject();
    }
    static final class Failure extends RuntimeException { Failure(String message) { super(message); } }
    private static class Revoked extends Exception { }
    static String required(String name) {
        String value = System.getenv(name);
        if (value==null || value.isBlank()) throw new Failure("Missing "+name);
        return value;
    }
    static String random() { byte[] bytes = new byte[32]; new SecureRandom().nextBytes(bytes); return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
    static URI endpoint(String value) {
        URI uri = URI.create(value);
        boolean local = (Set.of("127.0.0.1","localhost").contains(uri.getHost())
                || (uri.getHost()!=null && uri.getHost().endsWith(".localhost")));
        if (!("https".equals(uri.getScheme()) || ("http".equals(uri.getScheme()) && local))
                || uri.getRawUserInfo()!=null || uri.getRawFragment()!=null)
            throw new IllegalArgumentException("HTTPS required except for explicit loopback fixtures.");
        return uri;
    }
    private static String form(Map<String,String> values) {
        return values.entrySet().stream().map(e->URLEncoder.encode(e.getKey(),java.nio.charset.StandardCharsets.UTF_8)+"="
                +URLEncoder.encode(e.getValue(),java.nio.charset.StandardCharsets.UTF_8)).collect(java.util.stream.Collectors.joining("&"));
    }
    private static void secure(Path path, String mode) throws Exception {
        if (Files.isSymbolicLink(path) || !Files.getPosixFilePermissions(path,LinkOption.NOFOLLOW_LINKS)
                .equals(PosixFilePermissions.fromString(mode))
                || !Files.getOwner(path,LinkOption.NOFOLLOW_LINKS).getName().equals(System.getProperty("user.name")))
            throw new Failure("Session storage must be owned by you with permissions "+mode+" and no symlink.");
    }
}
