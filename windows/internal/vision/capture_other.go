//go:build !windows

package vision

import "image"

func CaptureActiveScreen() (*image.RGBA, string, error) {
	return nil, "", nil
}

func InterveneOnVisualBlock() {}
