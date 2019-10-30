---
title: Extended Application Secret for TLS 1.3
docname: draft-iyengar-tls-extended-application-secret
category: info

ipr: trust200902
area: Security
workgroup: TLS
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: "S. Iyengar"
    name: "Subodh Iyengar"
    organization: "Facebook"
    email: subodh@fb.com

normative:

informative:



--- abstract

Some Transport protocols such as QUIC, use TLS 1.3 {{!RFC8446}} as a service to
securely negotiate parameters and exchange application data encryption keys.
These protocols can process data out of order and this can result in cases
where a transport may process application data before processing the
confirmation of the handshake if care is not taken to avoid this via the TLS
implementation.  This document specifies an extension to TLS 1.3 which changes
the derivation of the client's application encryption key in order to provide
protection at the protocol level against out of order processing of client
application data.

--- middle

# Introduction

TLS 1.3 {{!RFC8446}} provides authentication of parameter negotiation via
confirmation messages called "Finished" messages.  These messages are signed
transcripts of the handshake seen by both the client and the server to make
sure that they have the same view of the handshake, and that no-one tampered
with the handshake. The client may send a Finished message in the same flight
of data as 1-RTT application data.  A server MUST process the client's
Finished message first before processing any of the application data.  A server
might request client authentication, in which case the server would want to
make sure that the client's certificate is presented, or that a server might
want to verify that the client had never observed a client authentication.
Security analysis of TLS (citation neeeded) depends on a server processing the
Finished message before the client's application data.

When TLS 1.3 is layered over TCP, this property is achieved trivially, since
TCP provides TLS with an in-order delivery guarantee.  However when TLS 1.3 is
layered over out-of-order protocols such as QUIC, a client's 1-RTT encrypted
application data may be received by a server before the client's Finished
message and may be incorrectly processed by the server.  The reason for this
is the structure of the Key Schedule in TLS 1.3.  In the TLS 1.3 Key Schedule,
the application encryption keys for the client are derived from the transcript
up-to the server's first flight of data, which means that the server would have
the keys available to decrypt the client's 1-RTT data even before receving the
Finished message.  If a server incorrectly makes a transport protocol aware of
the availability of the client keys before processing the Finished message, it
might be able to decrypt and process application data, which might result in a
vulnerability.  This is a very easy implementation mistake to make.  It would
be better if TLS 1.3 prevented this mistake at a protocol level and this
document proposes an extension to the Key Schedule of TLS 1.3 to be able to
avoid mistakes.


# Extended Application Secret

Extended application secret changes the key schedule to include the client
messages that are sent in the client's final flight to be included in the key
derivation for the client's application traffic secret.

When a client and server negotiate an extended application secret, they change
their Key Schedule to be:

~~~~
                 0
                 |
                 v
   PSK ->  HKDF-Extract = Early Secret
                 |
                 +-----> Derive-Secret(.,
                 |                     "ext binder" |
                 |                     "res binder",
                 |                     "")
                 |                     = binder_key
                 |
                 +-----> Derive-Secret(., "c e traffic",
                 |                     ClientHello)
                 |                     = client_early_traffic_secret
                 |
                 +-----> Derive-Secret(., "e exp master",
                 |                     ClientHello)
                 |                     = early_exporter_master_secret
                 v
           Derive-Secret(., "derived", "")
                 |
                 v
(EC)DHE -> HKDF-Extract = Handshake Secret
                 |
                 +-----> Derive-Secret(., "c hs traffic",
                 |                     ClientHello...ServerHello)
                 |                     = client_handshake_traffic_secret
                 |
                 +-----> Derive-Secret(., "s hs traffic",
                 |                     ClientHello...ServerHello)
                 |                     = server_handshake_traffic_secret
                 v
           Derive-Secret(., "derived", "")
                 |
                 v
      0 -> HKDF-Extract = Master Secret
                 |
                 +-----> Derive-Secret(., "s ap traffic",
                 |                     ClientHello...server Finished)
                 |                     = server_application_traffic_secret_0
                 |
                 +-----> Derive-Secret(., "exp master",
                 |                     ClientHello...server Finished)
                 |                     = exporter_master_secret
                 |
                 +-----> Derive-Secret(., "res master",
                 |                     ClientHello...client Finished)
                 |                     = resumption_master_secret
                 |
                 +-----> Derive-Secret(., "ec ap traffic",
                                       ClientHello...client Finished)
                                       = extended_client_application_traffic_secret_0
~~~~

Where an extended_client_application_traffic_secret_0 is used as the
client's application encryption keys instead of the the original
client_application_traffic_secret_0.

TBD: do we need to do anything for exporters?

By forcing the application traffic secrets to depend on the entire flight of
client messages, the server has to process all the client messages before being
able to decrypt 1-RTT application data.  This makes it much more difficult to
process data out of order accidentally.

## Negotiation

This document defines the following extension code point:

~~~~~~~~~~
   enum {
     ...
     extended_client_application_traffic_secret(TBD),
     (65535)
   } ExtensionType;
~~~~~~~~~~

A client would send this extension in it's ClientHello message to indicate that
it wished to negotiate extended application traffic secrets.

If a server also supports this mechanism, they would respond with the same
extension in the ServerHello message.

A client and server would switch to the new key schedule once they knew that
their peer supported it.

# Security Considerations

## Downgrade protection

The mechanism does not change the computation of the Finished message. Thus it
should be subject to the same security properties of any extension negotiation.

# IANA Considerations

TBD

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
