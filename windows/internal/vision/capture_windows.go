//go:build windows

package vision

import (
	"errors"
	"image"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modUser32               = syscall.NewLazyDLL("user32.dll")
	modGdi32                = syscall.NewLazyDLL("gdi32.dll")
	procGetDC               = modUser32.NewProc("GetDC")
	procReleaseDC           = modUser32.NewProc("ReleaseDC")
	procGetSystemMetrics    = modUser32.NewProc("GetSystemMetrics")
	procGetForegroundWindow = modUser32.NewProc("GetForegroundWindow")
	procGetWindowTextW      = modUser32.NewProc("GetWindowTextW")
	procShowWindow          = modUser32.NewProc("ShowWindow")
	procPostMessageW        = modUser32.NewProc("PostMessageW")

	procCreateCompatibleDC     = modGdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = modGdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject           = modGdi32.NewProc("SelectObject")
	procBitBlt                 = modGdi32.NewProc("BitBlt")
	procGetDIBits              = modGdi32.NewProc("GetDIBits")
	procDeleteObject           = modGdi32.NewProc("DeleteObject")
	procDeleteDC               = modGdi32.NewProc("DeleteDC")
)

const (
	smCxScreen   = 0
	smCyScreen   = 1
	srccopy      = 0x00CC0020
	biRGB        = 0
	dibRGBColors = 0
	swMinimize   = 6
	wmClose      = 0x0010
)

type bitmapInfoHeader struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

type bitmapInfo struct {
	BmiHeader bitmapInfoHeader
	BmiColors [1]uint32
}

// CaptureActiveScreen captures the primary Windows display strictly in RAM (never saved to disk).
// Skips scanning when AegisGuard's own dashboard is in foreground.
func CaptureActiveScreen() (*image.RGBA, string, error) {
	title := foregroundTitle()
	if strings.Contains(strings.ToLower(title), "aegisguard") {
		return nil, title, nil
	}

	w, _, _ := procGetSystemMetrics.Call(smCxScreen)
	h, _, _ := procGetSystemMetrics.Call(smCyScreen)
	width, height := int(w), int(h)
	if width <= 0 || height <= 0 {
		return nil, title, errors.New("no active desktop display")
	}

	hdcScreen, _, _ := procGetDC.Call(0)
	if hdcScreen == 0 {
		return nil, title, errors.New("GetDC failed")
	}
	defer procReleaseDC.Call(0, hdcScreen)

	hdcMem, _, _ := procCreateCompatibleDC.Call(hdcScreen)
	if hdcMem == 0 {
		return nil, title, errors.New("CreateCompatibleDC failed")
	}
	defer procDeleteDC.Call(hdcMem)

	hBitmap, _, _ := procCreateCompatibleBitmap.Call(hdcScreen, uintptr(width), uintptr(height))
	if hBitmap == 0 {
		return nil, title, errors.New("CreateCompatibleBitmap failed")
	}
	defer procDeleteObject.Call(hBitmap)

	oldObj, _, _ := procSelectObject.Call(hdcMem, hBitmap)
	defer procSelectObject.Call(hdcMem, oldObj)

	ok, _, _ := procBitBlt.Call(hdcMem, 0, 0, uintptr(width), uintptr(height), hdcScreen, 0, 0, srccopy)
	if ok == 0 {
		return nil, title, errors.New("BitBlt failed")
	}

	var bi bitmapInfo
	bi.BmiHeader.BiSize = uint32(unsafe.Sizeof(bi.BmiHeader))
	bi.BmiHeader.BiWidth = int32(width)
	bi.BmiHeader.BiHeight = -int32(height) // top-down DIB
	bi.BmiHeader.BiPlanes = 1
	bi.BmiHeader.BiBitCount = 32
	bi.BmiHeader.BiCompression = biRGB

	bgra := make([]byte, width*height*4)
	lines, _, _ := procGetDIBits.Call(
		hdcMem,
		hBitmap,
		0,
		uintptr(height),
		uintptr(unsafe.Pointer(&bgra[0])),
		uintptr(unsafe.Pointer(&bi)),
		dibRGBColors,
	)
	if lines == 0 {
		return nil, title, errors.New("GetDIBits failed")
	}

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for i := 0; i < len(bgra); i += 4 {
		img.Pix[i] = bgra[i+2]   // R
		img.Pix[i+1] = bgra[i+1] // G
		img.Pix[i+2] = bgra[i]   // B
		img.Pix[i+3] = 255       // A
	}
	return img, title, nil
}

// InterveneOnVisualBlock immediately minimizes and closes the offending explicit window.
func InterveneOnVisualBlock() {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return
	}
	title := strings.ToLower(foregroundTitle())
	if strings.Contains(title, "aegisguard") || strings.Contains(title, "program manager") {
		return
	}
	procShowWindow.Call(hwnd, swMinimize)
	if !strings.Contains(title, "explorer") {
		procPostMessageW.Call(hwnd, wmClose, 0, 0)
	}
}

func foregroundTitle() string {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return ""
	}
	buf := make([]uint16, 256)
	n, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:n])
}
