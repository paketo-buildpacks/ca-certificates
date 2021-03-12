# Opt Out of CA Certificate Buildpack Default Behaviour

## Proposal

Allow users an option to opt out of using the CA certificate buildpack all together. The default behaviour is to always detect, but users should have an option to
turn this behaviour off if they know they won't need it. The proposed way to enable this would be through an environment variable that a user can set at build-time.

## Motivation

Currently, the CA Certificates buildpack [always detects](https://github.com/paketo-buildpacks/ca-certificates/blob/5164ed35c28f957a0488f78e33b1217f13ca49b4/cacerts/detect.go#L34-L36). This is smart behaviour because it adds a "helper" layer so that certificates can be dynamically added at runtime without having to specify anything at build time. This is a helpful default, and without more user input claiming otherwise, the buildpack should continue to do this.

The issue lies in the fact that some users may not want CA certifiates at all, and have no simple way to turn this behaviour off. Any buildpacks that have the CA Certificates buildpack as an `optional` order group item in their `buildpack.toml` files will always have the CA Certificates detect. This clutters logs with CA Certificate buildpack output, which isn't ideal since we make a conscious effort to keep our logs streamlined. It also unnecessarily creates a layer when a user knows they won't want CA certificates.

## Implementation

A new `BP_CA_CERTIFICATES` environment variable that can be set to `false` at build-time if a user does not want the buildpack to detect. The default will be `true`, and the buildpack will proceed normally in this case.

## Source Material

[Node.js buildpack](https://github.com/paketo-buildpacks/nodejs) - includes the CA Certificates buildpack in order groupings

[CA Certificates buildpack README](https://github.com/paketo-buildpacks/ca-certificates/blob/main/README.md) - helpful information on how the buildpack works

## Unresolved Questions and Bikeshedding (Optional)

Alternatives would be to keep the buildpack as it is now, or to change the default behaviour to off. The latter option doesn't make sense until we have user feedback about what defaults would be helpful.
