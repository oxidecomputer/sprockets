## Overview

Sprockets provides a secure transport protocol for use in the Oxide bootstrap
network. It is designed specifically to work with a Root of Trust (RoT) capable
of providing device identities, signing capabilities, and a mechanism to
retrieve measurements for remote attestation. The protocol utilizes TLS 1.3
via [rustls](https://github.com/rustls/rustls) for secure session establishment
between bootstrap agents with authentication provided by local RoTs. Remote
attestation is performed over secure TLS 1.3 channels.
