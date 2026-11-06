"""Generate ``docs/demo.gif`` - the animated terminal demo for beyond-pslist.

Runs the real ``bps sift`` command against the synthetic fixtures, captures its
actual stdout, and animates a faux terminal: a typed command -> streaming
output -> hold -> loop. The output is exactly what the tool prints, not a
mock-up, with the single CANDIDATE row highlighted as the punchline.

This is an AUTHORING-TIME tool. Pillow is NOT a runtime dependency of
beyond-pslist; it is only needed to regenerate the GIF.

Usage
-----
    pip install pillow          # one-off, into your dev environment
    python scripts/make_demo_gif.py

Run it from anywhere; the repo root is derived from this file's location.
On Windows it uses Consolas; elsewhere it falls back to DejaVu Sans Mono.
"""

import contextlib
import io
import os
import runpy
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFont

# --- repo layout: this file lives in <repo>/scripts/, so the repo root is one
#     directory up. Everything is derived from that, so the script is portable.
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)  # import beyondpslist from source without installing
os.chdir(REPO)

# ---- palette (Catppuccin Mocha) ----
BG = (30, 30, 46)
FG = (205, 214, 244)
CYAN = (137, 220, 235)
GREEN = (166, 227, 161)
YELLOW = (249, 226, 175)
RED = (243, 139, 168)
DIM = (108, 112, 134)
MUTED = (147, 153, 178)

# ---- 1. build the synthetic fixtures, then capture the REAL command output ----
runpy.run_path(os.path.join(REPO, "examples", "make_synthetic.py"), run_name="__main__")

from beyondpslist.cli import main as cli_main

TARGET = os.path.join("examples", "out", "target.bin")
BASELINE = os.path.join("examples", "out", "baseline.bin")
COMMAND = "bps sift examples/out/target.bin examples/out/baseline.bin"

_buf = io.StringIO()
with contextlib.redirect_stdout(_buf):
    cli_main(["sift", TARGET, BASELINE])
OUTPUT_LINES = _buf.getvalue().rstrip("\n").split("\n")


# ---- 2. colourise each captured line into (char, rgb, bold) segments ----
def _seg(text, rgb, bold=False):
    return [(ch, rgb, bold) for ch in text]


def colourise(line):
    stripped = line.strip()
    # separator rule
    if stripped and set(stripped) == {"-"}:
        return _seg(line, DIM)
    # summary line
    if "IOC-looking strings examined" in line:
        out = []
        for ch in line:
            out.append((ch, FG, True))
        # recolour the uppercase verdict words
        for word, col in (("RESIDUE", RED), ("CANDIDATE", GREEN)):
            idx = line.find(word)
            if idx != -1:
                for k in range(idx, idx + len(word)):
                    out[k] = (line[k], col, True)
        return out
    # candidate row: the punchline, bright and bold
    if line.startswith("[CANDIDATE]"):
        return _seg(line, GREEN, True)
    # residue row: red tag, muted remainder
    if line.startswith("[RESIDUE"):
        tag = "[RESIDUE  ]"
        return _seg(tag, RED, True) + _seg(line[len(tag):], MUTED)
    # reason continuation line
    if stripped.startswith("- "):
        return _seg(line, DIM)
    return _seg(line, FG)


final_rows = [colourise(line) for line in OUTPUT_LINES]


# ---- fonts (monospace; Consolas on Windows, DejaVu elsewhere) ----
def _load_font(size, bold=False):
    candidates = (
        [r"C:\Windows\Fonts\consolab.ttf", "DejaVuSansMono-Bold.ttf"]
        if bold else
        [r"C:\Windows\Fonts\consola.ttf", "DejaVuSansMono.ttf"]
    )
    for path in candidates:
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    raise SystemExit(
        "No monospace font found. Install Consolas (Windows) or DejaVu Sans "
        "Mono, or edit _load_font() to point at a .ttf on your system."
    )


SIZE = 20
font = _load_font(SIZE)
font_b = _load_font(SIZE, bold=True)
CW = int(round(font.getlength("M")))
asc, desc = font.getmetrics()
LH = asc + desc + 6

MARGIN_X, MARGIN_Y = 22, 18
TITLE_BAR = 34  # faux window title bar height

PROMPT_SEGS = [("PS ", CYAN), (r"Z:\beyond-pslist", GREEN), ("> ", FG)]
PROMPT_LEN = sum(len(t) for t, _ in PROMPT_SEGS)

MAX_COLS = max(
    PROMPT_LEN + len(COMMAND),
    max((len(r) for r in final_rows), default=0),
) + 2
TOTAL_ROWS = 1 + len(final_rows) + 2  # prompt + output + spacer + trailing prompt

W = MARGIN_X * 2 + MAX_COLS * CW
H = TITLE_BAR + MARGIN_Y * 2 + TOTAL_ROWS * LH

RED_DOT = (243, 139, 168)
YEL_DOT = (249, 226, 175)
GREEN_DOT = (166, 227, 161)


def new_canvas():
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, TITLE_BAR], fill=(43, 43, 60))
    for i, col in enumerate((RED_DOT, YEL_DOT, GREEN_DOT)):
        cx = 20 + i * 22
        d.ellipse([cx, TITLE_BAR // 2 - 6, cx + 12, TITLE_BAR // 2 + 6], fill=col)
    caption = "beyond-pslist  -  sift"
    d.text((W // 2 - len(caption) * CW // 2, TITLE_BAR // 2 - 10), caption,
           font=font, fill=(150, 155, 175))
    return img, d


def draw_row(d, row_idx, segs, cursor_after=None):
    y = TITLE_BAR + MARGIN_Y + row_idx * LH
    for col, (ch, rgb, bold) in enumerate(segs):
        x = MARGIN_X + col * CW
        d.text((x, y), ch, font=(font_b if bold else font), fill=rgb)
    if cursor_after is not None:
        x = MARGIN_X + cursor_after * CW
        d.rectangle([x, y + 2, x + CW - 2, y + LH - 4], fill=FG)


def prompt_segments():
    out = []
    for text, rgb in PROMPT_SEGS:
        out.extend((ch, rgb, False) for ch in text)
    return out


def frame(typed_len, output_count, cursor=False):
    img, d = new_canvas()
    psegs = prompt_segments()
    cmd = [(c, FG, False) for c in COMMAND[:typed_len]]
    draw_row(d, 0, psegs + cmd,
             cursor_after=(PROMPT_LEN + typed_len) if cursor else None)
    for i in range(output_count):
        draw_row(d, 1 + i, final_rows[i])
    return img


frames, durations = [], []


def add(img, ms):
    frames.append(img)
    durations.append(ms)


# 1. blink at empty prompt
add(frame(0, 0, cursor=True), 350)
add(frame(0, 0, cursor=False), 250)
# 2. type the command (2 chars per frame)
i = 0
while i < len(COMMAND):
    i = min(i + 2, len(COMMAND))
    add(frame(i, 0, cursor=True), 55)
# 3. pause on the full command
add(frame(len(COMMAND), 0, cursor=True), 450)
add(frame(len(COMMAND), 0, cursor=False), 150)
# 4. stream output rows
for k in range(1, len(final_rows) + 1):
    add(frame(len(COMMAND), k), 48)
# 5. hold the final frame
final = frame(len(COMMAND), len(final_rows))
add(final, 2600)


# 6. trailing prompt with a blinking cursor under the output
def frame_with_trailing(cursor):
    img = frame(len(COMMAND), len(final_rows))
    d = ImageDraw.Draw(img)
    row = 1 + len(final_rows) + 1
    psegs = prompt_segments()
    draw_row(d, row, psegs, cursor_after=len(psegs) if cursor else None)
    return img


for _ in range(2):
    add(frame_with_trailing(True), 500)
    add(frame_with_trailing(False), 450)

os.makedirs(os.path.join(REPO, "docs"), exist_ok=True)
out = os.path.join(REPO, "docs", "demo.gif")

pal_frames = [f.convert("P", palette=Image.ADAPTIVE, colors=128) for f in frames]
pal_frames[0].save(
    out, save_all=True, append_images=pal_frames[1:], loop=0,
    duration=durations, disposal=2, optimize=True,
)

preview = os.path.join(tempfile.gettempdir(), "beyond_pslist_demo_final_frame.png")
final.save(preview)

print(f"rows={len(final_rows)} cols={MAX_COLS} canvas={W}x{H} frames={len(frames)}")
print(f"gif={out} size={os.path.getsize(out) // 1024}KB")
print(f"preview frame: {preview}")
