"""Navigate the song list looking for a target title, using OCR of the song-name band."""
import ctypes, ctypes.wintypes as wt, time, sys, subprocess, os
from PIL import Image

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

def safe(s):
    """ASCII-only view so console encoding never raises."""
    return ''.join(ch if 32 <= ord(ch) < 127 else '?' for ch in s)

u32 = ctypes.windll.user32; g32 = ctypes.windll.gdi32
u32.SetProcessDPIAware()
OUT = r'C:\Users\<you>\Desktop\DSHStool\usm-tool'
OCR = r'C:\Users\<you>\.dsh\skills\image-recognition\ocr.ps1'
VK_RIGHT, VK_LEFT, VK_ENTER = 0x27, 0x25, 0x0D

def find_hwnd(keyword='Sinmai'):
    found = []
    EP = ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)
    def cb(hwnd, l):
        ln = u32.GetWindowTextLengthW(hwnd)
        if ln and u32.IsWindowVisible(hwnd):
            b = ctypes.create_unicode_buffer(ln+1); u32.GetWindowTextW(hwnd, b, ln+1)
            if keyword.lower() in b.value.lower(): found.append(hwnd)
        return True
    u32.EnumWindows(EP(cb), 0)
    return found[0] if found else None

def press(vk, hold=0.05, wait=0.12):
    u32.keybd_event(vk, 0, 0, 0); time.sleep(hold)
    u32.keybd_event(vk, 0, 2, 0); time.sleep(wait)

def cap(hwnd, path):
    rect = wt.RECT(); u32.GetWindowRect(hwnd, ctypes.byref(rect))
    w, h = rect.right-rect.left, rect.bottom-rect.top
    hdc = u32.GetWindowDC(hwnd); mdc = g32.CreateCompatibleDC(hdc)
    bmp = g32.CreateCompatibleBitmap(hdc, w, h); g32.SelectObject(mdc, bmp)
    u32.PrintWindow(hwnd, mdc, 2)
    class BIH(ctypes.Structure):
        _fields_ = [('biSize', wt.DWORD), ('biWidth', wt.LONG), ('biHeight', wt.LONG),
                    ('biPlanes', wt.WORD), ('biBitCount', wt.WORD), ('biCompression', wt.DWORD),
                    ('biSizeImage', wt.DWORD), ('biXPelsPerMeter', wt.LONG), ('biYPelsPerMeter', wt.LONG),
                    ('biClrUsed', wt.DWORD), ('biClrImportant', wt.DWORD)]
    bi = BIH(); bi.biSize = ctypes.sizeof(BIH); bi.biWidth, bi.biHeight = w, -h
    bi.biPlanes, bi.biBitCount, bi.biCompression = 1, 32, 0
    buf = ctypes.create_string_buffer(w*h*4)
    g32.GetDIBits(mdc, bmp, 0, h, buf, ctypes.byref(bi), 0)
    Image.frombuffer('RGBA', (w, h), buf, 'raw', 'BGRA', 0, 1).convert('RGB').save(path)
    g32.DeleteObject(bmp); g32.DeleteDC(mdc); u32.ReleaseDC(hwnd, hdc)
    return path

def ocr(path):
    r = subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                        '-File', OCR, '-Path', path], capture_output=True, text=True, errors='replace')
    return (r.stdout or '') + (r.stderr or '')

target = sys.argv[1] if len(sys.argv) > 1 else 'TAKE CONTROL'
max_steps = int(sys.argv[2]) if len(sys.argv) > 2 else 60

hwnd = find_hwnd()
if not hwnd: print('no window'); sys.exit(1)
u32.ShowWindow(hwnd, 9); time.sleep(0.3)
u32.SetForegroundWindow(hwnd); time.sleep(0.6)
print(f'hwnd={hwnd} looking for {target!r} up to {max_steps} steps')

for step in range(max_steps + 1):
    p = cap(hwnd, os.path.join(OUT, 'nav.png'))
    text = ocr(p)
    flat = text.replace(' ', '').upper()
    hit = target.replace(' ', '').upper() in flat
    tail = [l for l in text.splitlines() if l.strip()][:6]
    print(f'  step {step:3d}: {"*** FOUND ***" if hit else ""} {safe(" | ".join(tail))[:150]}')
    if hit:
        print('target found, saving nav_found.png')
        cap(hwnd, os.path.join(OUT, 'nav_found.png'))
        break
    press(VK_RIGHT, wait=0.18)
else:
    print('target not found within step limit')
