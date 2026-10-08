#!/usr/bin/env python3
"""Generate test-voice.wav: 5 s linear sine sweep 312 Hz -> 864 Hz, mono 16-bit 48 kHz.

The wav is a build artifact (git-ignored). Run this if test-voice.wav is missing:
    python3 make-test-voice.py
"""
import math
import struct
import wave

RATE = 48000
SECS = 5
F0, F1 = 312.0, 864.0
AMP = 20000

n = RATE * SECS
frames = bytearray()
phase = 0.0
for i in range(n):
    t = i / RATE
    f = F0 + (F1 - F0) * (i / n)
    phase += 2 * math.pi * f / RATE
    frames += struct.pack('<h', int(AMP * math.sin(phase)))

with wave.open('test-voice.wav', 'wb') as w:
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(RATE)
    w.writeframes(bytes(frames))

print(f"wrote test-voice.wav ({SECS}s sweep {F0:.0f}Hz->{F1:.0f}Hz)")
