package visual

import (
	"crypto/rand"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"

	"github.com/skip2/go-qrcode"
)

// VisualPaths holds output image locations for the bonus visual crypto feature.
type VisualPaths struct {
	QRPath       string
	Share1Path   string
	Share2Path   string
	CombinedPath string
}

// GenerateVisualShares makes a QR code from the recovery share, splits it into two
// visual-crypto shares (2,2), and writes QR/share/combined PNG files to outDir.
func GenerateVisualShares(recoveryShare64, outDir string) (VisualPaths, error) {
	if recoveryShare64 == "" {
		return VisualPaths{}, fmt.Errorf("recovery share is empty")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return VisualPaths{}, fmt.Errorf("create output dir: %w", err)
	}

	qr, err := qrcode.New(recoveryShare64, qrcode.Medium)
	if err != nil {
		return VisualPaths{}, fmt.Errorf("create qr: %w", err)
	}
	qrImg := qr.Image(256)
	bw := toMonochrome(qrImg)

	share1, share2, err := splitVisual(bw)
	if err != nil {
		return VisualPaths{}, err
	}
	combined := combineShares(share1, share2)

	paths := VisualPaths{
		QRPath:       filepath.Join(outDir, "qr.png"),
		Share1Path:   filepath.Join(outDir, "share1.png"),
		Share2Path:   filepath.Join(outDir, "share2.png"),
		CombinedPath: filepath.Join(outDir, "combined.png"),
	}

	if err := savePNG(paths.QRPath, bw); err != nil {
		return VisualPaths{}, err
	}
	if err := savePNG(paths.Share1Path, share1); err != nil {
		return VisualPaths{}, err
	}
	if err := savePNG(paths.Share2Path, share2); err != nil {
		return VisualPaths{}, err
	}
	if err := savePNG(paths.CombinedPath, combined); err != nil {
		return VisualPaths{}, err
	}
	return paths, nil
}

func toMonochrome(img image.Image) *image.Gray {
	b := img.Bounds()
	gray := image.NewGray(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			c := color.GrayModel.Convert(img.At(x, y)).(color.Gray)
			if c.Y < 128 {
				gray.SetGray(x, y, color.Gray{Y: 0})
			} else {
				gray.SetGray(x, y, color.Gray{Y: 255})
			}
		}
	}
	return gray
}

func splitVisual(src *image.Gray) (*image.Gray, *image.Gray, error) {
	b := src.Bounds()
	w := b.Dx()
	h := b.Dy()
	shareW := w * 2
	shareH := h * 2
	share1 := image.NewGray(image.Rect(0, 0, shareW, shareH))
	share2 := image.NewGray(image.Rect(0, 0, shareW, shareH))

	patternA := [4]uint8{0, 255, 255, 0}
	patternB := [4]uint8{255, 0, 0, 255}

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			isBlack := src.GrayAt(b.Min.X+x, b.Min.Y+y).Y < 128
			useAlt, err := randomBit()
			if err != nil {
				return nil, nil, err
			}

			p1 := patternA
			p2 := patternA
			if useAlt {
				p1 = patternB
				p2 = patternB
			}
			if isBlack {
				if useAlt {
					p1 = patternA
					p2 = patternB
				} else {
					p1 = patternB
					p2 = patternA
				}
			}
			applyPattern(share1, x*2, y*2, p1)
			applyPattern(share2, x*2, y*2, p2)
		}
	}
	return share1, share2, nil
}

func applyPattern(img *image.Gray, x, y int, p [4]uint8) {
	img.SetGray(x, y, color.Gray{Y: p[0]})
	img.SetGray(x+1, y, color.Gray{Y: p[1]})
	img.SetGray(x, y+1, color.Gray{Y: p[2]})
	img.SetGray(x+1, y+1, color.Gray{Y: p[3]})
}

func combineShares(s1, s2 *image.Gray) *image.Gray {
	b1 := s1.Bounds()
	b2 := s2.Bounds()
	if b1.Dx() != b2.Dx() || b1.Dy() != b2.Dy() {
		return image.NewGray(image.Rect(0, 0, 1, 1))
	}
	out := image.NewGray(image.Rect(0, 0, b1.Dx(), b1.Dy()))
	for y := 0; y < b1.Dy(); y++ {
		for x := 0; x < b1.Dx(); x++ {
			p1 := s1.GrayAt(x+b1.Min.X, y+b1.Min.Y).Y
			p2 := s2.GrayAt(x+b2.Min.X, y+b2.Min.Y).Y
			if p1 < 128 || p2 < 128 {
				out.SetGray(x, y, color.Gray{Y: 0})
			} else {
				out.SetGray(x, y, color.Gray{Y: 255})
			}
		}
	}
	return out
}

func savePNG(path string, img image.Image) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		return fmt.Errorf("encode png %s: %w", path, err)
	}
	return nil
}

func randomBit() (bool, error) {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return false, err
	}
	return b[0]&1 == 1, nil
}
