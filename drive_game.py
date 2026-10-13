"""Send keystrokes to the game window (via keybd_event) and capture after each step."""
import ctypes, ctypes.wintypes as wt, time, sys
from PIL import Image

u32 = ctypes.windll.user32
g32 = ctypes.windll.gdi32
u32.SetProcessDPIAware()

VK = {'enter': 0x0D, 'space': 0x20, 'esc': 0x1B, 'f1': 0x70, 'f2': 0x71,
      'num0': 0x60, 'num1': 0x61, 'num2': 0x62, 'num3': 0x63, 'num4': 0x64,
      'num5': 0x65, 'num6': 0x66, 'num7': 0x67, 'num8': 0x68, 'num9': 0x69,
      'numenter': 0x0D, 'up': 0x26, 'down': 0x28, 'left': 0x25, 'right': 0x27}

def focus(keyword='Sinmai'):
    found = []
    EP = ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)
    def cb(hwnd, l):
        ln = u32.GetWindowTextLengthW(hwnd)
        if ln and u32.IsWindowVisible(hwnd):
            b = ctypes.create_unicode_buffer(ln + 1); u32.GetWindowTextW(hwnd, b, ln + 1)
            if keyword.lower() in b.value.lower():
                found.append(hwnd)
        return True
    u32.EnumWindows(EP(cb), 0)
    return found[0] if found else None

def press(vk, hold=0.06):
    u32.keybd_event(vk, 0, 0, 0)
    time.sleep(hold)
    u32.keybd_event(vk, 0, 2, 0)
    time.sleep(0.25)

def cap(hwnd, path):
    rect = wt.RECT(); u32.GetWindowRect(hwnd, ctypes.byref(rect))
    w, h = rect.right - rect.left, rect.bottom - rect.top
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

hwnd = focus()
if not hwnd:
    print('Sinmai window not found'); sys.exit(1)
print(f'hwnd={hwnd}')
u32.ShowWindow(hwnd, 9); time.sleep(0.3)
u32.SetForegroundWindow(hwnd); time.sleep(0.8)

seq = sys.argv[1:] or ['enter']
for i, name in enumerate(seq):
    vk = VK.get(name.lower())
    if vk is None:
        print('unknown key', name); continue
    press(vk)
    p = cap(hwnd, rf'C:\Users\<you>\Desktop\DSHStool\usm-tool\step{i}_{name}.png')
    print(f'sent {name} -> {p}')
