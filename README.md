# yaesu-ft3dr-decrypt

Decrypt the firmware image carried by an official Yaesu FT3DR updater executable.

The updater is a PE32 program. The encrypted image sits in a custom resource. This tool reads that resource, reads the cipher tables out of the same executable, derives a session key from the resource timestamp, and writes the plaintext bytes.

The program does not embed key material. The static tables are read from the updater executable.

## Build

Requires a Rust toolchain. No crates are fetched.

```text
cargo build --release
```

The binary is `target/release/yaesu-ft3dr-decrypt` (`yaesu-ft3dr-decrypt.exe` on Windows).

## Window

Version 1.1 opens a window when the program is started with no arguments. Double-clicking the exe is that case.

The window title is `FT3DR Firmware Decrypt`.

Browse selects the updater executable. The updater can also be dropped onto the window. The first dropped file is used.

The output path starts as the updater's file stem with `.bin`, in the same directory. Save as, or typing in the output field, chooses a different path. After the user edits that field, picking a new updater does not replace it.

Decrypt reads the updater, writes the plaintext firmware image, and shows the timestamp with its UTC text, the trailer strings, the byte count, the SHA-256 of the plaintext, and the path written.

If the output file already exists, the program asks `Replace the existing file?` and does not write on No.

Errors are shown in a dialog and on the status line. Success status is `Done.`

Enter activates Decrypt. Escape closes the window.

A release build does not open a console window when started with no arguments. Passing an updater on the command line still prints to the console when one is attached.

## Run

Arguments select the command line. No arguments select the window.

```text
yaesu-ft3dr-decrypt <updater.exe> [-o output.bin]
```

If `-o` is omitted, the plaintext is written in the same directory as the updater, with the same file stem and the extension `.bin`.

Stdout is five lines. Errors go to stderr and the process exits 1.

```text
timestamp: 1576569521 (20191217075841 UTC)
trailer: FT3DR/E(MAIN), EXP, 1.02
bytes: 1048576
sha256: 8e3ecd05409b2c314ebed77320ece5930bf31c8333cd84aeef4f6b0264c1bcce
wrote: firmware.bin
```

`sha256` is the SHA-256 of the plaintext only.

## Resource layout

Custom resource type 23, name `RES_UPDATE_INFO`.

The blob is:

1. A 4-byte little-endian Unix timestamp.
2. Ciphertext. The length is one of `0x100000`, `0x400000`, `0x80000`, `0x200000`, or `0x800000`.
3. A trailer. Its first dword repeats the ciphertext length. Later bytes hold short ASCII strings (model, region, version): printable runs of length 3 or more.

The plaintext is the ciphertext after decryption. The trailer is not decrypted. Every accepted length is a multiple of the 8-byte block.

## Static tables

Two structural searches, both inside the executable that was opened:

- In `.rdata`, one run of 16 little-endian dwords whose values are only 1 or 2, with at least eight 2s. That 64-byte run is the key-schedule configuration. The bytes that follow it are a 48-byte index table (values 1 through 56), a 48-byte index table (values 1 through 32), 2048 bytes of only 0 and 1, and a 32-byte permutation of 1 through 32.
- In `.text`, one site that pushes four addresses 56 bytes apart. Each address points at 56 bytes that contain both 0 and 1 and nothing else. Those are the four timestamp tables, in push order. A push is the byte `0x68` followed by a little-endian virtual address. The four encodings lie in a 96-byte window. Virtual addresses are converted with the PE image base and the section table. Addresses outside the image are rejected.

## Cipher

Block size is 8 bytes. Each bit of a block is stored as its own byte, 0 or 1.

1. Format the timestamp in UTC with `%Y%m%d%H%M%S` (14 ASCII digits).
2. Four rounds. Each round installs one 56-byte timestamp table as the key, XORs the next date digits into a 64-byte buffer as individual bits (most significant bit of each digit first), and runs the block function in the encrypt direction. Digits past the 14th are zero.
3. The first 56 bytes of that buffer are the session key. Key setup expands them to a 768-byte schedule: on each of 16 rounds it rotates two 28-byte halves left by one or two positions (the key-schedule configuration selects one versus two), then gathers 48 bytes through the 48-byte index table.
4. For each 8 ciphertext bytes, expand each byte to 8 bits, run the block function in the decrypt direction, and pack the bits back.

The block function runs 16 rounds over the 64-byte bit buffer. Decrypt starts at schedule slot 15 and walks down to 0. Encrypt starts at slot 0 and walks up. The last round only XORs. Earlier rounds also swap halves of each 4-bit group. The 32-byte permutation chooses the XOR source. Each round mixes six bits at a time through the 2048-byte substitution table. The substitution index for bits `a` through `f` is

```text
((a << 5) + 2) | ((b << 4) + 2) | ((c << 3) + 2) | ((d << 2) + 2) | ((e << 1) + 2) | (f + 2)
```

The additions stay inside the parentheses.

## Check

Official ver 1.02 images decrypt to:

| Image | Bytes    | SHA-256                                                          |
| ----- | -------- | ---------------------------------------------------------------- |
| MAIN  | 1048576  | `8e3ecd05409b2c314ebed77320ece5930bf31c8333cd84aeef4f6b0264c1bcce` |
| SUB   | 4194304  | `b93570b3c2f69ccb51c113c893b4bc4c414cf78ceddde478748404e0768c6230` |
