"""Measure the two green marks inside a single known test window, without saving its contents."""
import ctypes
from ctypes import wintypes as w
import json
import sys


def measure(pid, hwnd, left, top, right, bottom, color=(61, 220, 151)):
    u = ctypes.WinDLL("user32", use_last_error=True)
    g = ctypes.WinDLL("gdi32", use_last_error=True)

    def api(dll, name, result, *args):
        entry = getattr(dll, name)
        entry.argtypes, entry.restype = args, result
        return entry

    # UI Automation gives screen coordinates in physical pixels.
    api(u, "SetProcessDPIAware", w.BOOL)()
    owner = w.DWORD()
    rect = w.RECT()
    if (not api(u, "GetWindowThreadProcessId", w.DWORD, w.HWND, ctypes.POINTER(w.DWORD))(hwnd, ctypes.byref(owner))
            or owner.value != pid or not api(u, "GetWindowRect", w.BOOL, w.HWND, ctypes.POINTER(w.RECT))(hwnd, ctypes.byref(rect))):
        raise ValueError("unexpected test window")
    width, height = rect.right - rect.left, rect.bottom - rect.top
    left, top, right, bottom = left - rect.left, top - rect.top, right - rect.left, bottom - rect.top
    if not (0 <= left < right <= width and 0 <= top < bottom <= height):
        raise ValueError("status outside of test window")
    original = api(u, "GetWindowDC", w.HDC, w.HWND)(hwnd)
    memory = api(g, "CreateCompatibleDC", w.HDC, w.HDC)(original)
    bitmap = api(g, "CreateCompatibleBitmap", w.HBITMAP, w.HDC, ctypes.c_int, ctypes.c_int)(original, width, height)
    select = api(g, "SelectObject", w.HGDIOBJ, w.HDC, w.HGDIOBJ)
    old = select(memory, bitmap)
    try:
        if not api(u, "PrintWindow", w.BOOL, w.HWND, w.HDC, w.UINT)(hwnd, memory, 2):
            raise OSError("test window capture failed")
        pixel = api(g, "GetPixel", w.DWORD, w.HDC, ctypes.c_int, ctypes.c_int)
        counts = [0, 0]
        for y in range(max(0, top - 2), min(height, bottom + 2)):
            for x in range(max(0, left - 36), min(right, left + 180)):
                value = pixel(memory, x, y)
                rgb = (value & 255, (value >> 8) & 255, (value >> 16) & 255)
                if all(abs(channel - expected) <= 18 for channel, expected in zip(rgb, color)):
                    counts[int(x >= left - 2)] += 1
        return dict(dot_pixels=counts[0], text_pixels=counts[1])
    finally:
        select(memory, old)
        api(g, "DeleteObject", w.BOOL, w.HGDIOBJ)(bitmap)
        api(g, "DeleteDC", w.BOOL, w.HDC)(memory)
        api(u, "ReleaseDC", ctypes.c_int, w.HWND, w.HDC)(hwnd, original)


if __name__ == "__main__":
    if len(sys.argv) not in (7, 8) or (len(sys.argv) == 8 and sys.argv[7] != "amber"):
        raise SystemExit("arguments: pid hwnd left top right bottom [amber]")
    color = (242, 181, 58) if len(sys.argv) == 8 else (61, 220, 151)
    label = "amber" if len(sys.argv) == 8 else "green"
    counts = measure(*(int(v) for v in sys.argv[1:7]), color=color)
    print(json.dumps({f"{label}_{k}": value for k, value in counts.items()}))
