package org.wso2.spring.security.abac.soaputils;

import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.client.HttpClient;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.PrivateKeyDetails;
import org.apache.http.conn.ssl.PrivateKeyStrategy;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.protocol.HTTP;
import org.apache.http.protocol.HttpContext;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.util.Map;
import javax.net.ssl.SSLContext;

/**
 * @author Randika Navagamuwa
 */
public class CustomSSLHttpClientFactory implements FactoryBean<HttpClient> {

    protected Resource keyStoreFile;

    protected String keyStorePassword;

    protected String keyStoreType;

    protected Resource trustStoreFile;

    protected String trustStorePassword;

    protected String[] allowedProtocols;

    protected String certAlias;

    public CustomSSLHttpClientFactory() {

    }

    /**
     * Contructor for factory-bean
     *
     * @param keyStoreFile       org.springframework.core.io.Resource to specify the keystore
     * @param keyStorePassword
     * @param keyStoreType       if null default JKS will be used
     * @param trustStoreFile
     * @param trustStorePassword
     * @param allowedProtocols   authentication protocols
     * @param certAlias          the client certificate alias. If null default behavior
     */
    public CustomSSLHttpClientFactory(Resource keyStoreFile,
                                      String keyStorePassword,
                                      String keyStoreType,
                                      Resource trustStoreFile,
                                      String trustStorePassword,
                                      String[] allowedProtocols,
                                      String certAlias) {

        super();
        this.keyStoreFile = keyStoreFile;
        this.keyStorePassword = keyStorePassword;
        this.keyStoreType = keyStoreType;
        this.trustStoreFile = trustStoreFile;
        this.trustStorePassword = trustStorePassword;
        this.allowedProtocols = allowedProtocols;
        this.certAlias = certAlias;
    }

    /**
     * Little trick to pass over some stupid contentLength error
     *
     * @author roberto.gabrieli
     */
    private class ContentLengthHeaderRemover implements HttpRequestInterceptor {

        @Override
        public void process(HttpRequest request,
                            HttpContext context) throws HttpException, IOException {

            request.removeHeaders(HTTP.CONTENT_LEN);// fighting org.apache.http.protocol.RequestContent's ProtocolException("Content-Length header already present");
        }
    }

    /**
     * Private class to hack the certificate alias choice.
     *
     * @author roberto.gabrieli
     */
    private class AliasPrivateKeyStrategy implements PrivateKeyStrategy {

        private String alias;

        public AliasPrivateKeyStrategy(String alias) {

            this.alias = alias;
        }

        /**
         * This metod return the alias name specified in the constructor.
         */
        public String chooseAlias(Map<String, PrivateKeyDetails> aliases,
                                  Socket socket) {

            return alias;
        }

    }

    /**
     * Method that return a CloseableHttpClient
     */
    public CloseableHttpClient getObject() throws Exception {

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        KeyStore keyStore = KeyStore.getInstance(this.keyStoreType != null ? this.keyStoreType : KeyStore.getDefaultType());
        InputStream instreamTrust = trustStoreFile.getInputStream();
        InputStream instreamKeys = keyStoreFile.getInputStream();

        //Load of KEYSTORE and TRUSTSTORE
        try {
            trustStore.load(instreamTrust, trustStorePassword.toCharArray());
            keyStore.load(instreamKeys, keyStorePassword.toCharArray());
        } finally {
            instreamKeys.close();
            instreamTrust.close();
        }

        SSLContextBuilder sslCtxBuilder = SSLContexts.custom().loadTrustMaterial(trustStore, new TrustSelfSignedStrategy());

        PrivateKeyStrategy apks = null;
        // check if the alias is specified null and "" will mean -no alias-
        if (this.certAlias != null && !this.certAlias.trim().equals("")) {
            apks = new AliasPrivateKeyStrategy(this.certAlias);
            sslCtxBuilder = sslCtxBuilder.loadKeyMaterial(keyStore, keyStorePassword.toCharArray(), apks);
        } else {
            sslCtxBuilder = sslCtxBuilder.loadKeyMaterial(keyStore, keyStorePassword.toCharArray());
        }
        SSLContext sslcontext = sslCtxBuilder.build();

        //All the stuff for the connection build
        HttpClientBuilder builder = HttpClientBuilder.create();
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext, allowedProtocols, null, SSLConnectionSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER);

        builder.setSSLSocketFactory(sslsf);
        Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create().register("https", sslsf).register("http", new PlainConnectionSocketFactory()).build();
        HttpClientConnectionManager ccm = new BasicHttpClientConnectionManager(registry);
        builder.setConnectionManager(ccm);
        CloseableHttpClient httpclient = builder.build();

        return httpclient;
    }

    public Class<?> getObjectType() {

        return HttpClient.class;
    }

    public boolean isSingleton() {

        return false;
    }

}