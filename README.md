# Client-Server-Authentication

Class project dealing with client-server challenge authentication to gain remote shell access.

1) Client first establish connection with server
2) Server generates challenge nonce using RNG (resistance to replay attack) then sends it to client
3) Client then sends authentication to server
4) Server compares authentication w/ internal document
