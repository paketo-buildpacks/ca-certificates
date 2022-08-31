# `gcr.io/paketo-buildpacks/ca-certificates`

The Paketo Buildpack for CA Certificates is a Cloud Native Buildpack that adds CA certificates to the system truststore at build and runtime.

## Behavior

This buildpack always participates.

The buildpack will do the following:

* At build time:
  * If `$BP_RUNTIME_CERT_BINDING_DISABLED` is false, it contributes the `ca-cert-helper` to the application image. Default is false.
  * If one or more bindings with `type` of `ca-certificates` exists, it adds all CA certificates from the bindings to the system truststore.
  * If another buildpack provides an entry of `type` `ca-certificates` in the build plan with `metadata.paths` containing an array of certificate paths, it adds all CA certificates from the given paths to the system truststore.
  * If `$BP_EMBED_CERTS` is true, it includes the layer with all of the CA certificates into the application image.
* At runtime:
  * If one or more bindings with `type` of `ca-certificates` exists, the `ca-cert-helper` adds all CA certificates from the bindings to the system truststore.

The buildpack configures trusted certs at both build and runtime by:
 1. Creating a directory.
 2. Creating symlinks within the directory pointing to any additional requested certificate files.
 3. Appending the directory to the `SSL_CERT_DIR` environment variable.
 3. Setting `SSL_CERT_FILE` to the default system CA file, if it was previously unset.

To learn about the conventional meaning of `SSL_CERT_DIR` and `SSL_CERT_FILE` environment variables see the OpenSSL documentation for [SSL_CTX_load_verify_locations][s]. This buildpack may not work with tools that do not respect these environment variables.

### Runtime Environment Support

| Feature              | Supported       | Detail                                                                  |
| -------------------- | --------------- | ---------------------------------------------------------------------------- |
| read-only runtime container | No       | Symlinks and/or new files are written for certificates provided via binding at runtime. A read-only container will run if no cert bindings are present at runtime.  |
| run as custom user          | Yes      | The custom user must be a member of the `CNB` group



## Bindings

The buildpack optionally accepts the following bindings:

### Type: `ca-certificates`

| Key                  | Value           | Description                                                                  |
| -------------------- | --------------- | ---------------------------------------------------------------------------- |
| `<certificate-name>` | `<certificate>` | CA certificate to trust. Should contain exactly one PEM encoded certificate. |

## Configuration

| Environment Variable                | Description                                                                                                                                                                                 |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `$BP_EMBED_CERTS`                   | Embed all CA certificate bindings present at buildtime into the application image. This removes the need to have any embedded CA certificate bindings present at runtime. Default is false. |
| `$BP_RUNTIME_CERT_BINDING_DISABLED` | Disable the helper that adds certificates at runtime. This means any provided CA certificates will not be included. Default to false, which means certificates are loaded by default.         |
| `$BP_ENABLE_RUNTIME_CERT_BINDING`   | Deprecated in favour of `$BP_RUNTIME_CERT_BINDING_DISABLED`. Enable/disable the ability to set certificates at runtime via the certificate helper layer. Default is true.                   |

## License

This buildpack is released under version 2.0 of the [Apache License][a].

[a]: http://www.apache.org/licenses/LICENSE-2.0
[s]: https://www.openssl.org/docs/man1.1.0/man3/SSL_CTX_set_default_verify_paths.html

