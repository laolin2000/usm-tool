"""Capture the game window directly via PrintWindow (works for fullscreen/exclusive windows)."""
import ctypes, ctypes.wintypes as wt, time, sys
from PIL import Image

u32 = ctypes.windll.user32
g32 = ctypes.windll.gdi32
u32.SetProcessDPIAware()

def find_window(keyword='Sinmai'):
    found = []
    EnumProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)
    def cb(hwnd, lparam):
        ln = u32.GetWindowTextLengthW(hwnd)
        if ln:
            buf = ctypes.create_unicode_buffer(ln + 1)
            u32.GetWindowTextW(hwnd, buf, ln + 1)
            cls = ctypes.create_unicode_buffer(256)
            u32.GetClassNameW(hwnd, cls, 256)
            if keyword.lower() in buf.value.lower() or 'UnityWndClass' in cls.value:
                found.append((hwnd, buf.value, cls.value, bool(u32.IsWindowVisible(hwnd))))
        return True
    u32.EnumWindows(EnumProc(cb), 0)
    return found

wins = find_window()
print('=== candidate windows ===')
for h, t, c, v in wins:
    print(f'  hwnd={h} visible={v} class={c!r} title={t!r}')
if not wins:
    print('no window'); sys.exit(1)

hwnd, title, cls, vis = wins[0]
rect = wt.RECT()
u32.GetWindowRect(hwnd, ctypes.byref(rect))
w, h = rect.right - rect.left, rect.bottom - rect.top
print(f'\ncapturing hwnd={hwnd} {w}x{h}')

hdc = u32.GetWindowDC(hwnd)
mdc = g32.CreateCompatibleDC(hdc)
bmp = g32.CreateCompatibleBitmap(hdc, w, h)
g32.SelectObject(mdc, bmp)

PW_RENDERFULLCONTENT = 0x00000002
ok = u32.PrintWindow(hwnd, mdc, PW_RENDERFULLCONTENT)
print('PrintWindow ->', ok)

class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [('biSize', wt.DWORD), ('biWidth', wt.LONG), ('biHeight', wt.LONG),
                ('biPlanes', wt.WORD), ('biBitCount', wt.WORD), ('biCompression', wt.DWORD),
                ('biSizeImage', wt.DWORD), ('biXPelsPerMeter', wt.LONG), ('biYPelsPerMeter', wt.LONG),
                ('biClrUsed', wt.DWORD), ('biClrImportant', wt.DWORD)]

bi = BITMAPINFOHEADER()
bi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
bi.biWidth, bi.biHeight = w, -h
bi.biPlanes, bi.biBitCount = 1, 32
bi.biCompression = 0

buf = ctypes.create_string_buffer(w * h * 4)
got = g32.GetDIBits(mdc, bmp, 0, h, buf, ctypes.byref(bi), 0)
print('GetDIBits lines =', got)

img = Image.frombuffer('RGBA', (w, h), buf, 'raw', 'BGRA', 0, 1).convert('RGB')
out = r'C:\Users\<you>\Desktop\DSHStool\usm-tool\game2.png'
img.save(out)
# crude brightness so we know if it's black/blank
px = img.resize((64, 40)).load()
vals = [sum(px[x, y]) / 3 for y in range(40) for x in range(64)]
print(f'saved {out} {img.size}  mean_luma={sum(vals)/len(vals):.1f} max={max(vals):.0f}')

g32.DeleteObject(bmp); g32.DeleteDC(mdc); u32.ReleaseDC(hwnd, hdc)
