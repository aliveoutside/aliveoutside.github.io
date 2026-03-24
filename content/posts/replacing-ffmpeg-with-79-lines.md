+++
title = "Replacing FFmpeg with 79 Lines of Java"
date = 2026-03-24T00:00:00Z
draft = false
description = "I needed to extract AAC audio from HLS streams on Android. FFmpeg added 10MB to the APK. So I read the spec and wrote a demuxer from scratch."
tags = ["android", "multimedia", "reverse-engineering", "mpeg-ts", "optimization"]
+++

So I had this problem. I was working on an Android app that downloads audio from HLS streams. The pipeline: fetch an M3U8 playlist, download the encrypted `.ts` segments, decrypt them with AES, and then extract raw AAC audio from the MPEG Transport Stream container.

The obvious answer is FFmpeg. Everyone uses FFmpeg. But FFmpeg adds something like 10MB of native libraries to your APK, needs JNI bridging, and it felt ridiculous to pull in this massive thing just to strip a container off some audio bytes.

I do Android RE for a living, so I spend most of my time staring at binary data and decompiled code anyway. Parsing a documented binary format sounded way easier than dealing with FFmpeg's cross-compilation and JNI. So I opened the [MPEG-TS spec](https://en.wikipedia.org/wiki/MPEG_transport_stream) and it turned out to be surprisingly simple. The whole demuxer ended up being 79 lines of Java.

## MPEG-TS basics

The nice thing about MPEG-TS is that everything is **188-byte packets**. Always. No variable sizes, no length-prefixed frames, just a steady stream of 188-byte chunks. You read 188 bytes, you got a packet.

If you've ever opened a `.ts` file in a hex editor, you'll see `0x47` repeating every 188 bytes. That's the sync byte at the start of each packet.

Each packet has a 4-byte header. Here's what an actual one looks like, let's say `47 41 00 30`:

```
Byte 0: 0x47
  Sync byte. Always 0x47, that's how you know you're at a packet boundary.

Byte 1: 0x41 = 0b01000001
  Bit 7 (0): Transport Error Indicator, no error, good
  Bit 6 (1): Payload Unit Start Indicator, this packet starts a new PES unit
  Bits 4-0 (00001): upper 5 bits of PID

Byte 2: 0x00 = 0b00000000
  Lower 8 bits of PID
  
  PID = (00001 << 8) | 00000000 = 0x0100 = 256, that's our audio stream

Byte 3: 0x30 = 0b00110000
  Bits 7-6 (00): Transport Scrambling Control, not scrambled
  Bits 5-4 (11): Adaptation Field Control, adaptation field + payload present
  Bits 3-0 (0000): Continuity Counter
```

So from 4 bytes we know: valid packet (`0x47`), start of a new audio frame (PID 256, payload unit start = 1), and there's an adaptation field we need to skip before the actual audio data.

The **PID** is the key field. A TS stream multiplexes multiple streams together, video on one PID, audio on another, metadata on another. I only care about audio (PID 256), everything else gets ignored.

When **Payload Unit Start Indicator** is 1, the packet contains the beginning of a PES (Packetized Elementary Stream) packet, which is another header wrapping the actual audio data. More on that below.

**Adaptation Field Control** tells you what comes after the 4-byte header:
- `01`: Payload only (most common, nice and simple)
- `10`: Adaptation field only, no payload (padding/timing)
- `11`: Adaptation field followed by payload (skip the adaptation field first)

The whole algorithm: read 188 bytes, check sync, check PID, skip adaptation field if present, skip PES header if present, write whatever's left.

## The code

Here's the whole thing:

```java
public class MpegDemuxer {
    public static void convert(byte[] inBytes, String out) throws IOException {
        try (InputStream inStream = new ByteArrayInputStream(inBytes)) {
            convert(inStream, out);
        }
    }

    public static void convert(InputStream in, String out) throws IOException {
        int packetSize = 188;
        int desiredPid = 256;

        var buffer = new byte[packetSize];
        var packet = ByteBuffer.wrap(buffer).order(ByteOrder.BIG_ENDIAN);

        try (var fis = new BufferedInputStream(in);
             var fos = new BufferedOutputStream(new FileOutputStream(out))) {
            while (fis.read(buffer) != -1) {
                packet.clear();

                int firstByte = packet.get() & 0xFF;
                int secondByte = packet.get() & 0xFF;
                int thirdByte = packet.get() & 0xFF;
                int fourthByte = packet.get() & 0xFF;

                int syncByte = firstByte;
                int transportErrorIndicator = (secondByte & 0x80) >> 7;
                int payloadUnitStartIndicator = (secondByte & 0x40) >> 6;

                int pid = ((secondByte & 0x1F) << 8) | (thirdByte & 0xFF);

                int adaptationFieldControl = (fourthByte & 0x30) >> 4;

                if (syncByte != 0x47) {
                    continue;
                }

                if (transportErrorIndicator == 1) {
                    continue;
                }

                if (adaptationFieldControl == 2 || adaptationFieldControl == 3) {
                    int adaptationFieldLength = packet.get() & 0xFF;
                    packet.position(packet.position() + adaptationFieldLength);
                }

                if (pid == desiredPid) {
                    if (payloadUnitStartIndicator == 1) {
                        packet.position(packet.position() + 4);
                        int pesPacketLength = packet.getShort() & 0xFFFF;

                        if (pesPacketLength != 0) {
                            packet.position(packet.position() + 2);
                            int pesHeaderDataLength = packet.get() & 0xFF;
                            packet.position(packet.position() + pesHeaderDataLength);
                        }
                    }

                    fos.write(packet.array(), packet.position(),
                              packetSize - packet.position());
                }
            }
        }
    }
}
```

Some notes on the less obvious parts.

### Extracting the PID

```java
int pid = ((secondByte & 0x1F) << 8) | (thirdByte & 0xFF);
```

PID is 13 bits spread across two bytes. Mask off the upper 3 bits (those are flags we already extracted), shift the remaining 5 bits up by 8, OR with byte 2. If you've ever parsed binary protocols this is pretty standard stuff.

### Skipping the adaptation field

```java
if (adaptationFieldControl == 2 || adaptationFieldControl == 3) {
    int adaptationFieldLength = packet.get() & 0xFF;
    packet.position(packet.position() + adaptationFieldLength);
}
```

When there's an adaptation field, its first byte is the length. We don't care what's in it (PCR timestamps, stuffing bytes, various flags), just jump over it.

### The PES header

This part tripped me up the most:

```java
if (payloadUnitStartIndicator == 1) {
    packet.position(packet.position() + 4);
    int pesPacketLength = packet.getShort() & 0xFFFF;

    if (pesPacketLength != 0) {
        packet.position(packet.position() + 2);
        int pesHeaderDataLength = packet.get() & 0xFF;
        packet.position(packet.position() + pesHeaderDataLength);
    }
}
```

When a packet starts a new PES unit, there's a header before the audio data:

```
00 00 01     PES start code prefix (always 0x000001)
C0           Stream ID (0xC0 = MPEG audio)
XX XX        PES packet length
XX XX        Optional header flags (DTS/PTS flags, etc.)
XX           PES header data length
[...]        Header data (timestamps etc., variable length)
[...]        Actual audio payload starts here
```

We skip the start code + stream ID (4 bytes), read the packet length, then use `pesHeaderDataLength` to skip past the optional timing data. After that we're at the raw AAC bytes.

I figured this out by intercepting actual HLS traffic and staring at the bytes in a hex editor, cross-referencing with the spec until things clicked. The spec alone was a bit abstract, but once you see real bytes next to it, the structure becomes obvious pretty fast.

### Writing output

```java
fos.write(packet.array(), packet.position(), packetSize - packet.position());
```

After all the skipping, `ByteBuffer`'s position is right at the audio data. Write from there to the end of the 188-byte packet. Output is raw AAC that you can feed into a tagger or player.

## Results

- 79 lines, single file, no dependencies beyond `java.nio` and `java.io`
- ~10MB smaller APK (no more FFmpeg native libs for arm64, armeabi, x86, x86_64)
- ~2.3x faster downloads, since there's no FFmpeg process spawn and no JNI overhead
- Ran in production for 200k+ users without issues

This obviously won't work for everything. It handles one PID, assumes well-formed input, doesn't parse PAT/PMT tables. If you need transcoding or format conversion or anything with video, just use FFmpeg.

But yeah, for my specific case it worked out. MPEG-TS looked intimidating before I actually sat down with the spec, and the subset I needed turned out to be pretty small. Sometimes you don't need the Swiss army knife.
