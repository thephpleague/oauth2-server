---
layout: default
title: Database Setup
permalink: /database-setup/
---

# Database Setup

This library has been developed so that you can use any type of backend storage; relational, document, key value, columnar or even hardcoded.

The documentation for each of the repository interfaces describes what sort of data you might want to store not how to store it.

Please note that IDs for users and clients should be globally unique. For the authorization grant, the subject of the JWT bearer token will 
typically identify an authorized accessor for which the access token is being requested (i.e. the resource owner or an authorized delegate).
For client authentication, the subject will be the Client ID. Having globally unique IDs for these records will make it easier to identify
the subject of the bearer token.

* [Access Token Repository Interface documentation](/access-token-repository-interface/)
* [Client Repository Interface documentation](/client-repository-interface/)
* [Refresh Token Repository Interface documentation](/refresh-token-repository-interface/)
* [Scope Repository Interface documentation](/scope-repository-interface/)
* [Auth Code Repository Interface documentation](/auth-code-repository-interface/)
* [User Repository Interface documentation](/user-repository-interface/)
