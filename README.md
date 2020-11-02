# `gcr.io/paketo-buildpacks/ca-certificates`
The Paketo CA Certificates Buildpack is a Cloud Native Buildpack that adds CA certificates to the system truststore at build and runtime.

## Behavior
This buildpack always participates.

The buildpack will do the following:

* At build time:
  * Contributes the `ca-cert-helper` to the application image.
  * If one or more bindings with `type` of `ca-certificates` exists, it adds all CA certificates from the bindings to the system truststore.
  * If another buildpack provides an entry of `type` `ca-certifcates` in the build plan with `metadata.paths` containing an array of certificate paths, it adds all CA certificates from the given paths to the system truststore.
* At runtime:
  * If one or more bindings with `type` of `ca-certificates` exists, the `ca-cert-helper` adds all CA certificates from the bindings to the system truststore.

The buildpack configures trusted certs at both build and runtime by:
 1. Creating a directory.
 2. Creating symlinks within the directory pointing to any additional requested certficate files.
 3. Appending the directory to the `SSL_CERT_DIR` environment variable.
 3. Setting `SSL_CERT_FILE` to the default system CA file, if it was previously unset.

To learn about the conventional meaning of `SSL_CERT_DIR` and `SSL_CERT_FILE` environment variables see the OpenSSL documentation for [SSL_CTX_load_verify_locations][s]. This buildpack may not work with tools that do not respect these environment variables.

## Bindings
The buildpack optionally accepts the following bindings:

### Type: `ca-certificates`
|Key                   | Value   | Description
|----------------------|---------|------------
|`<certificate-name>` | `<ceritificate>` | CA certficate to trust. Should contain exactly one PEM encoded certificate.

## License
This buildpack is released under version 2.0 of the [Apache License][a].

[a]: http://www.apache.org/licenses/LICENSE-2.0
[s]: https://www.openssl.org/docs/man1.1.0/man3/SSL_CTX_set_default_verify_paths.html
