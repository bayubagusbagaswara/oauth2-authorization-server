# OAuth 2.0

`OAuth 2.0`, which stands for "Open Authorization", is a standard designed to allow a website or application to access resources hosted by other web apps on behalf of a user.

- OAuth 2.0 is an authorization protocol and NOT an authentication protocol
- It is designed primarily as a means of granting access to a set of resources. For example, remote APIs or user's data
- OAuth 2.0 uses Access Tokens

# OAuth 2.0 Roles

- Resource Owner
- Client
- Authorization Server
- Resource Server

# Resource Owner

The user or system that owns the protected resources and can grant access to them.

# Client

The client is the system that requires access to the protected resources. To access resources, the Client must hold the appropriate Access Token.

# Authorization Server

This server receives requests from the Client for Access Tokens and issues them upon successful authentication and consent by the Resource Owner.

# Resource Server

A server that protects the user's resources and receives access requests from the Client. It accepts and validates an Access Token from the Client and return the appropriate resources to it.

# Authorization Server 

- Digunakan untuk mengautorisasi username dan password yang dikirimkan oleh user
- Jika berhasil mengautentikasi username dan password (username dan password nya cocok), maka akan diterbitkan access token
- Untuk mengakses authorization server, user akan mengirimkan request berupa data username, password, grant_type, dll