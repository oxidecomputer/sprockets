== Overview

Sprockets provides a secure transport protocol for use in the Oxide bootstrap network. It is
designed specifically to work with a Root of Trust (RoT) capable of providing device identities, signing
capabilities, and a mechanism to retrieve measurements for remote attestation. The session
handshake, which utilizes the capabilities of the RoT and modern cryptography to establish a
confidential, integrity protected channel is described in the [session
README](https://github.com/oxidecomputer/sprockets/tree/main/session). This is a good place to start
to understand the structure of this code base.

== Navigating

*  `common` - no_std code that defines the messages to talk to the RoT as well as base types used in the rest of the
code.

* `host` - Code that runs on the host operating system - a rack sled in Oxide's case. This includes
code for interacting with the RoT, as well as code for creating async sessions.

* `hyper-sprockets` - Functionality allowing hyper to use a sprockets async session as transport in
the style of [hyper-tls](https://github.com/hyperium/hyper-tls).

* `proxy` - A mechanism for tunneling TCP traffic through sprockets sessions.
*
* `rot` - no_std code intended to run on an RoT.

* `session` - no_std code for creating a secure session.
