# Client-Server-Authentication

Class project dealing with client-server challenge authentication to gain remote shell access.

1) Client first establish connection with server
2) Server generates challenge nonce using RNG (resistance to replay attack) then sends it to client
3) Client then sends authentication to server
4) Server compares authentication w/ internal document

<p>
<img src="https://user-images.githubusercontent.com/61510855/139593960-88d99f22-f421-4af5-a82f-24ade6b5ab68.png" width="250" height="500">

<img src="https://user-images.githubusercontent.com/61510855/139593961-42f8bbf1-8f29-410b-a948-bea49ff6fcf7.png" width="250" height="500">

<img src="https://user-images.githubusercontent.com/61510855/139593963-18e5a781-169f-4a53-8654-ffff9908ff28.png" width="250" height="500">
  
<img src="https://user-images.githubusercontent.com/61510855/139593964-304c31ac-6d16-4ce5-888a-7db7b6658d62.png" width="250" height="500">
</p>
