As of 2022-07-07, the game is using Unity 2019.4.23f1.

## Asset extraction
The assets are 'obfuscated' by the addition of a 16 byte key to the beginning of every asset file.
What this key is doesn't matter, as it is not verified anywhere by the game.
The asset loader will simply omit the first 16 bytes.

Unfortunately, this breaks every ready-made asset extraction tool out there, so it needs to be stripped first.
You can do this by running a script from this repo with: 
`python3 strip_key.py path/to/RiichiCity`

Note that this will render the game unrunnable.
To revert this, run `fd path/to/RiichiCity -e backup -x mv {} {.}`

Once stripped, you can just extract the assets with any Unity asset extraction tool you like.
[AssetStudio](https://github.com/Perfare/AssetStudio/) worked best for me.

## Code extraction
Most of the game logic happens in the Lua code, which lives in the assets.
If you did the asset extraction step, you already have it.

A few interesting parts still remain in the compiled C# code, inside the `Assembly-CSharp.dll` file, as it is always the case with Unity games.
Use [dnSpy](https://github.com/dnSpyEx/dnSpy/) to get a decent disassembly of it.

The generic asset extraction tools don't try to organize the Lua code packed inside the assets.
If you care about that, you can try an alternative, easier, albeit less precise method of extraction:
- run the game with `bin/run_n_gun.exe path/to/RiichiCity/Mahjong-JP.exe bin/luadump.dll`
- click around the menus to light up as many code paths as possible
- find your extracted Lua in `luachunks/`

## Capturing traffic
All communication happens through HTTPS/WSS.
It will reject invalid certificates as it should, so if you want to proxy encrypted traffic, you will need to add your self-signed certificate to the system store.

For the most part, things will work just by changing the system proxy settings.
What won't work is proxying the websocket connection, which is only really used for actually playing mahjong.
Everything else happens through the HTTP API and will be proxied properly.

If you'd like to also capture websocket, the most reliable way I found is to change the `hosts` file and point the domains used by the game to your proxy.
Of course, in this case your proxy will need to listen on privileged port 443.

An alternative way would be to patch the Lua source to use plain HTTP/WS.
The game servers still listen on these port, so this should work, but I won't go into the detail here.

### Linux specific advice
If you don't care about the Websocket traffic (which you shouldn't unless you are writing bots), you can configure a per-process proxy for wine like so:
```sh
all_proxy=127.0.0.1:8080 wine path/to/RiichiCity/Mahjong-JP.exe
```

Websocket traffic doesn't respect this proxy setting, but you can redirect all traffic by changing the host resolution via the `hosts` file. The problem with overriding domains in `/etc/hosts` is that it will also affect your proxy if you don't hardcode the addresses. You probably don't want to bother with that unless you require it.
On Linux, there's a workaround for that, using namespaces.

```sh
# run everything here as root
su
# disable DNS cache to make the system not ignore namespaced hosts file
systemctl stop nscd
# globally point domains used by the game to 127.0.0.1
echo "127.0.0.1 dunu5s1vzgz6j.cloudfront.net d3qgi0t347dz44.cloudfront.net" >> /etc/hosts
# open a new namespace with its own mount points
unshare --mount
# create a new, default hosts file
echo "127.0.0.1 localhost" > hosts
# replace the hosts file within the namespace
mount hosts /etc/hosts --bind
# start the proxy - since it needs to run on a privileged port, might as well do it as root
mitmweb --listen-port 443
```

Note that if you run the game in a different namespace, you will get no sound.
I didn't bother to figure out why or how to fix it.

If you still want to do that, invert the steps that write the `hosts` files and log in as a regular user before running the game.

```sh
exec su - user
wine path/to/RiichiCity/Mahjong-JP.exe
```

## Multiboxing
This is quite useful for testing, as the game doesn't have bots you can add to a private match.

The game stores all relevant settings as well as the credentials in the registry entries under `[HKEY_CURRENT_USER\Software\麻雀一番街]`.

If you want to run multiple clients at the same time you need run the game with this part of the registry isolated.
*Important note*: Game sends "deviceid", determined by [deviceUniqueIdentifier](https://docs.unity3d.com/ScriptReference/SystemInfo-deviceUniqueIdentifier.html), with every request it makes. If you don't want Frank to know what you are up to, you should probably spoof that.

### Windows
I believe that to accomplish multiboxing on Windows, it's enough to change the game executable's file properties to run it as a different user.
This is completely untested by me.
There could be a better way.

I do not know how to spoof `deviceid` on Windows.

### Linux
Assuming you are using either wine or proton to run the game, you can run each instance in a separate wine prefix, like so: `WINEPREFIX=~/.wine_riichicity wine path/to/RiichiCity/Mahjong-JP.exe`.

Each wine prefix has the base cost of around 400MB disk space. You can reduce that by symlinking `$WINEPREFIX/{dosdevices,drive_c}` to a single instance. This leaves just the ~4MB of `.reg` files that are unique per prefix.

Out of the 5 properties that go into the generation of `deviceid`, we can easily control one: product ID.
Wine hardcodes this in the `$WINEPREFIX/system.reg`, to the same value every time. This can be spoofed simply by editing every instance of `ProductId` found there. On my system I found it in:
```
[Software\Microsoft\Windows NT\CurrentVersion]
[Software\Wow6432Node\Microsoft\Windows\CurrentVersion]
[Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion]
```

## API
HTTP is used for fetching nearly all remote data, such as checking information about players (including your own), lobbies, tourneys, interacting with tourneys, mailbox or events.

Websocket seems to be only used for sending heartbeats, joining games and actually playing mahjong.
Unless you are planning to build bots, this isn't very important.

Game makes requests to two different servers:
- d3qgi0t347dz44.cloudfront.net - hosts all game assets for updates and is used to discover the game server via a request to https://d3qgi0t347dz44.cloudfront.net/release/notice/domain_name.ncc
- dunu5s1vzgz6j.cloudfront.net (determined at runtime, so it may change) - the game server, all HTTP requests and Websocket connections should go there

### HTTP
HTTP API endpoints and used payloads are defined in sources under `luachunks/@Models/`.
Check these files to find out what you can send and where.

#### Authentication flow
All other requests require an authenticated session.
Authentication is done in two steps:

- obtain the session ID (`sid`)
  ```sh
  curl -H 'Cookies: {"channel":"default","deviceid":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","lang":"en","version":"1.1.3.7266","platform":"pc"}' -X POST https://dunu5s1vzgz6j.cloudfront.net/users/initSession | jq
  ```
  ```json
  {
    "code": 0,
    "data": "yyyyyyyyyyyyyyyyyyyyyyyyyy",
    "message": "ok"
  }
  ```

- login with your credentials and the obtained `sid`
  ```sh
  curl -H 'Cookies: {"channel":"default","deviceid":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","lang":"en","sid":"yyyyyyyyyyyyyyyyyyyyyyyyyy","version":"1.1.3.7266","platform":"pc"}' -X POST https://dunu5s1vzgz6j.cloudfront.net/users/emailLogin -d '{"passwd":"c35312fb3a7e05b7a44db2326bd29040","email":"chi@pon.nya"}' | jq
  ```
  `passwd` is the MD5 hash of your actual password.

  ```json
  {
    "code": 0,
    "data": {
      "init": false,
      "isCompleteNew": true,
      "tokenTypes": [
        6
      ],
      "user": {
        "avatar": "",
        "email": "chi@pon.nya",
        "id": 123456789,
        "nickname": "chinponya",
        "status": 0
      }
    },
    "message": "ok"
  }
  ```

Once that's done you can make requests to other endpoints.

```sh
curl -H 'Cookies: {"channel":"default","deviceid":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","lang":"en","sid":"yyyyyyyyyyyyyyyyyyyyyyyyyy","region":"cn","uid":123456789,"version":"1.1.3.7266","platform":"pc"}' -X POST https://dunu5s1vzgz6j.cloudfront.net/users/homeUserData | jq
```

Technically, only the `sid` cookie is required. If you don't specify the `lang` it will by default return text in chinese where applicable (for example, the mailbox contents).

```sh
curl -H 'Cookies: {"sid":"yyyyyyyyyyyyyyyyyyyyyyyyyy"}' -X POST https://dunu5s1vzgz6j.cloudfront.net/users/homeUserData | jq
```

```json
{
  "code": 0,
  "data": {
    "nickname": "chinponya",
    "profileFrameID": 0,
    "rValueMap": {
      "3": 1000000,
      "4": 1000000
    },
    "roleID": 10001,
    "skinID": 1000201,
    "stageLevelMap": {
      "3": 12,
      "4": 12 
    },
    "stageNextPtMap": {
      "3": 800,
      "4": 800
    },
    "stagePtMap": {
      "3": 400,
      "4": 400 
    }
  },
  "message": "ok"
}
```

Without `sid` or a valid session, you get this.
```sh
curl -X POST https://dunu5s1vzgz6j.cloudfront.net/users/homeUserData | jq
```
```json
{
  "code": 10,
  "message": "please login first"
}
```

### Websocket
Websocket payloads are defined under `luachunks/@Network/`. Packets are assembled and parsed in `RiichiCity/Mahjong-JP_Data/Managed/Assembly-CSharp.dll/GameFrame/WPacket.cs`.

#### Authentication flow
You have to authenticate your `sid` through the HTTP API, as described above.
Once you successfully establish the connection, send your `sid` through it.
```
\x00\x00\x00a\x00\x0f\x00\x01\x00\x00\x00\x0e\x00\x01\x01{"platform":"pc","uid":"123456789","lang":"en","sid":"yyyyyyyyyyyyyyyyyyyyyyyyyy"}
```

#### Message format
```c++
typedef enum {
    // don't ask me what all these are exactly
    // you can find the same thing in `protocal.lua` (not a typo) with some comments in chinese
    CMDHeartbeat
    CMDAuth
    CMDUnAuth
    CMDDisconnect
    CMDInRoom
    CMDOutRoom
    CMDPlaying
    CMDBroadcast
    CMDRoomReconnect
    CMDKickOut
    CMDRspHeartbeat
    CMDRspAuth
    CMDUnAuth
    CMDRspDisconnect
    CMDRspInRoom
    CMDRspOutRoom
    CMDRspPlaying
    CMDRspRoomReconnect
    CMDInGame
    CMDRoomChange
} command;

typedef uint16_t command_t;

typedef struct {
    // size of the entire packet
    uint32_t packet_size;
    // size of this section until json_payload
    // it's always '15' in this version
    uint16_t header_size;
    // version of the protocol
    // it's always '1' in this version
    uint16_t version;
    // the game internally refers to it as 'session index' and 'seqIndex', which is a bit misleading
    // it acts as an identifier for the message exchange in the async context
    // it starts at 0 and is incremented by 1 with every request
    // the server will include the same value in the response
    uint32_t message_index;
    // any `command` enum value as uint16_t
    command_t cmd;
    // this is used to denote whether there is anything in json_payload
    // it's used as a byte-sized boolean... it's always either 0 or 1
    uint8_t has_body;
    // optional, JSON-encoded message
    const char *json_payload;
} packet_t;
```