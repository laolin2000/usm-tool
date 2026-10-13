"""Focus the game window, bring it to front, and capture just that window."""
import ctypes, ctypes.wintypes as wt, time, sys
from PIL import ImageGrab

u32 = ctypes.windll.user32
u32.SetProcessDPIAware()

# find the Sinmai window
targets = []
EnumProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)
def cb(hwnd, lparam):
    if not u32.IsWindowVisible(hwnd):
        return True
    ln = u32.GetWindowTextLengthW(hwnd)
    if ln == 0:
        return True
    buf = ctypes.create_unicode_buffer(ln + 1)
    u32.GetWindowTextW(hwnd, buf, ln + 1)
    cls = ctypes.create_unicode_buffer(256)
    u32.GetClassNameW(hwnd, cls, 256)
    targets.append((hwnd, buf.value, cls.value))
    return True
u32.EnumWindows(EnumProc(cb), 0)

print('=== visible windows ===')
for hwnd, title, cls in targets:
    if any(k in title for k in ('Sinmai', 'maimai', 'amdaemon', 'Sinmai.exe')) or 'Unity' in cls:
        print(f'  hwnd={hwnd} class={cls!r} title={title!r}')

# pick the Sinmai window
cand = [t for t in targets if t[1].strip().lower().startswith('sinmai')]
if not cand:
    cand = [t for t in targets if 'Unity' in t[2]]
if not cand:
    print('Sinmai window not found'); sys.exit(1)
hwnd, title, cls = cand[0]
print(f'\nusing hwnd={hwnd} title={title!r} class={cls!r}')

# restore + foreground
u32.ShowWindow(hwnd, 9)          # SW_RESTORE
time.sleep(0.4)
u32.SetForegroundWindow(hwnd)
time.sleep(1.0)

rect = wt.RECT()
u32.GetWindowRect(hwnd, ctypes.byref(rect))
print(f'window rect: ({rect.left},{rect.top})-({rect.right},{rect.bottom})  '
      f'{rect.right-rect.left}x{rect.bottom-rect.top}')

out = r'C:\Users\<you>\Desktop\DSHStool\usm-tool\game1.png'
img = ImageGrab.grab(bbox=(rect.left, rect.top, rect.right, rect.bottom), all_screens=True)
img.save(out)
print('saved', out, img.size)
