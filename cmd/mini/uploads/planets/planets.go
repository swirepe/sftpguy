package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

const (
	resetColor   = "\033[0m"
	terrainChars = " .:-=+*#%@"
	starChar     = "✦"
	moonChar     = "o"
	// removed: ringChars, replaced by dynamic ring compositions
)

type Atmosphere struct {
	Name            string
	BaseColor       int
	TerrainHueShift int
	GlowWidth       float64
}

var atmosphereTypes = []Atmosphere{
	{"Cyan: Earthlike (O₂/N₂)", 45, 0, 1.5},
	{"Red: CO₂-dense (hostile)", 160, 50, 2.0},
	{"Green: Chlorinated (toxic)", 82, 30, 1.8},
	{"White: Thin/Icy", 250, -20, 1.2},
	{"Purple: Exotic", 129, 70, 2.5},
}

var (
	planetName  = flag.String("name", "", "Name of the planet")
	summaryOnly = flag.Bool("summary", false, "Only display the planet summary")
	noColor     = flag.Bool("no-color", false, "Disable ANSI colors")
	monoColor   = flag.Bool("mono", false, "Alias for --no-color")
	widthScale  = flag.Float64("width-scale", 1.0, "Horizontal scaling factor for the planet (e.g. 1.5 = wider)")
)

func main() {
	flag.Parse()

	if *monoColor {
		*noColor = true
	}

	name := *planetName
	if name == "" {
		name = generateScientificPlanetName(strconv.FormatInt(time.Now().UnixNano(), 10))
	} else {
		name = strings.Title(strings.ToLower(name))
	}

	planet, summary := generateDetailedPlanet(name)
	if *summaryOnly {
		fmt.Print(summary)
		return
	}
	fmt.Print(planet)
	fmt.Print(summary)
}

func generateScientificPlanetName(seed string) string {
	prefixes := []string{"HD", "Gliese", "Kepler", "Tau", "XK", "Zeta", "PSR", "KIC", "BD", "HIP", "LHS"}
	suffixLetters := []rune("bcdefghijklmnop")
	greekRoots := []string{"aer", "ther", "xen", "stel", "noct", "luma", "cryo", "astro", "neo", "chron", "hydro", "pyra"}

	hash := sha256.Sum256([]byte(seed))
	prefix := prefixes[int(hash[0])%len(prefixes)]
	number := 100 + int(hash[1]) + int(hash[2])
	root := greekRoots[int(hash[3])%len(greekRoots)]
	suffix := string(suffixLetters[int(hash[4])%len(suffixLetters)])

	extraCode := ""
	if hash[5]%100 < 30 {
		extraCode = fmt.Sprintf("-%c%d", 'A'+(hash[6]%6), 1+int(hash[7])%9)
	}

	return fmt.Sprintf("%s %d%s %s%s", prefix, number, extraCode, strings.Title(root), suffix)
}

func generateDetailedPlanet(seed string) (string, string) {
	hash := sha256.Sum256([]byte(seed))
	var b strings.Builder

	radius := 16 + int(hash[0])%9
	width := int(float64(radius*2) * *widthScale)
	height := radius

	hasAtmosphere := hash[2]%100 < 80
	hasRings := radius >= 21 && hash[3]%100 < 75

	moonFactor := int(math.Max(0, float64(radius-14)))
	numMoons := int((hash[4] % uint8(moonFactor+1)))
	if radius >= 22 {
		numMoons += int(hash[5] % 2)
	}
	if radius < 18 && hash[6]%100 < 30 {
		numMoons = 0
	}

	numStars := int(hash[7]%3) + 1
	starChance := 3 + numStars*2 // Star density scales with # of visible stars
	hasCore := hash[8]%100 < 70
	hasSuperStorm := hasAtmosphere && hash[9]%100 < 40
	tiltAngle := int(hash[10]) % 45
	hasMagneticField := hash[11]%100 < 65
	hasBiomes := hasAtmosphere && hash[12]%100 < 60

	type RingComposition struct {
		Name      string
		BaseColor int
		Chars     string
	}

	var ringCompositionsData = []RingComposition{
		{"Icy", 231, " ~"},
		{"Rocky", 245, "=/|"},
		{"Dusty", 130, "--:."},
		{"Organic", 94, "::."},
	}

	var atmo Atmosphere
	if hasAtmosphere {
		atmo = atmosphereTypes[int(hash[1])%len(atmosphereTypes)]
	}

	for y := -height - 5; y <= height+5; y++ {
		for x := -width - 8; x <= width+8; x++ {
			xf := float64(x) + 0.5
			yf := float64(y) * 1.8
			d := math.Sqrt(xf*xf + yf*yf)

			if hasAtmosphere && d >= float64(radius)+0.5 && d <= float64(radius)+atmo.GlowWidth {
				glowChar := rune(terrainChars[0])
				noise := int(safeHashByte(hash, x+y)) % 10
				glowColor := color256(atmo.BaseColor + noise)
				writeToPlanet(&b, noColor, glowColor, glowChar)
				continue
			}

			if d < float64(radius) {
				lat := float64(y+height) / float64(height*2)
				lon := float64(x+width) / float64(width*2)

				h1 := safeHashByte(hash, x*y)
				h2 := safeHashByte(hash, x+y)

				rawTidx := int(lat*10 + float64(h1%5) + math.Sin((lon*10)+float64(tiltAngle)/10)*3)
				if rawTidx < 0 {
					rawTidx = -rawTidx
				}
				tidx := rawTidx % len(terrainChars)
				char := rune(terrainChars[tidx])

				base := int(lat*100) + int(h2)%30 + tidx*7
				if hasAtmosphere {
					base += atmo.TerrainHueShift
				}
				if base < 0 {
					base += 240
				}
				color := color256(base % 240)

				if hasCore && d < float64(radius)*0.25 {
					color = color256(196 + int(h1)%8)
					char = rune(terrainChars[int(h1)%3])
				}
				if math.Abs(yf) > float64(radius)*1.4 {
					color = color256(15)
					char = rune(terrainChars[len(terrainChars)-1])
				}
				if hasSuperStorm && int(y)%7 == 0 && int(float64(x)*lat*lon*1000)%11 == 0 {
					color = color256(124 + (int(x+y) % 10))
					char = 'S'
				}
				if hasBiomes && int(h2)%20 == 0 {
					color = color256(28 + int(h1)%60)
					char = '#'
				}

				writeToPlanet(&b, noColor, color, char)
				continue
			}

			// Updated rings: composition-based, wider, axial-tilted and optionally horizontal
			if hasRings {
				ringComp := ringCompositionsData[int(hash[13])%len(ringCompositionsData)]
				ringViewHorizontal := hash[14]%100 < 40 // ~40% chance
				if ringViewHorizontal {
					ringYOffset := math.Tan(float64(tiltAngle)*math.Pi/180) * xf * 0.2
					if math.Abs(yf-ringYOffset) < 2 && math.Abs(xf) < float64(width) {
						char := rune(ringComp.Chars[int(math.Abs(xf))%len(ringComp.Chars)])
						color := color256(ringComp.BaseColor + int(safeHashByte(hash, x*y+int(xf)))%10)
						writeToPlanet(&b, noColor, color, char)
						continue
					}
				} else {
					tiltedY := yf - math.Tan(float64(tiltAngle)*math.Pi/180)*xf*0.2
					ringDistance := math.Abs(math.Sqrt(xf*xf+tiltedY*tiltedY) - float64(radius) - 1.5)
					if ringDistance >= 0 && ringDistance <= 4.5 {
						band := int(ringDistance * 2)
						char := rune(ringComp.Chars[band%len(ringComp.Chars)])
						color := color256(ringComp.BaseColor + int(safeHashByte(hash, x*y+band))%10)
						writeToPlanet(&b, noColor, color, char)
						continue
					}
				}
			}

			if numMoons > 0 && y < -radius-2 {
				if renderMoonSystem(&b, hash, x, y, radius, numMoons) {
					continue
				}
			}

			// Render starfield
			spaceHash := safeHashByte(hash, x*y+y-x)
			if int(spaceHash)%100 < starChance &&
				(math.Abs(xf) > float64(width)*0.6 || math.Abs(yf) > float64(height)*0.6) {

				starChars := []rune(" .:*✶✦")
				brightness := int(spaceHash) % len(starChars)
				char := starChars[brightness]
				if *noColor {
					char = '*'
				}
				color := color256(230 + brightness*2)
				writeToPlanet(&b, noColor, color, char)
			} else {
				b.WriteString(" ")
			}
		}
		b.WriteString("\n")
	}

	var summary strings.Builder
	ringCompositions := []string{"Icy", "Rocky", "Dusty", "Organic"}
	ringType := ringCompositions[int(hash[13])%len(ringCompositions)]
	summary.WriteString(fmt.Sprintf("Rings: %s", map[bool]string{true: "Present", false: "Absent"}[hasRings]))
	if hasRings {
		summary.WriteString(fmt.Sprintf(" (%s composition)", ringType))
	}
	summary.WriteString(fmt.Sprintf("\nMoons: %d\n", numMoons))
	summary.WriteString(fmt.Sprintf("Stars Visible: %d\n", numStars))
	summary.WriteString(fmt.Sprintf("Core: %s\n", map[bool]string{true: "Visible", false: "Not visible"}[hasCore]))
	summary.WriteString(fmt.Sprintf("Axial Tilt: %d°\n", tiltAngle))
	if hasSuperStorm {
		summary.WriteString("Superstorms: Detected\n")
	}
	if hasMagneticField {
		summary.WriteString("Magnetic Field: Strong\n")
	}
	if hasBiomes {
		summary.WriteString("Biomes: Diverse regions detected\n")
	}
	summary.WriteString(fmt.Sprintf("Radius: %d\n", radius))
	return b.String(), summary.String()
}

func writeToPlanet(b *strings.Builder, noColor *bool, color string, char rune) {
	if *noColor {
		b.WriteRune(char)
	} else {
		b.WriteString(color + string(char) + resetColor)
	}
}

func safeHashByte(hash [32]byte, i int) byte {
	i = i % len(hash)
	if i < 0 {
		i += len(hash)
	}
	return hash[i]
}

func color256(index int) string {
	return fmt.Sprintf("[38;5;%dm", 16+index%240)
}

type MoonType struct {
	Name      string
	Glyphs    []rune
	BaseColor int
	SizeBias  float64 // Multiplier for orbit radius and visual impact
}

var moonTypes = []MoonType{
	{"Rocky", []rune{'●', '◍', 'o'}, 244, 1.0},
	{"Icy", []rune{'◯', '◌', '◦'}, 252, 1.1},
	{"Volcanic", []rune{'⬤', '⊙', '⦿'}, 202, 0.9},
	{"Artificial", []rune{'☉', '⊖', '⊗'}, 226, 0.7},
	{"Dusty", []rune{'·', '.', '˚'}, 250, 0.8},
	{"Anomalous", []rune{'Ω', 'Ψ', '?'}, 129, 1.2},
}

func renderMoonSystem(b *strings.Builder, hash [32]byte, x, y, radius, numMoons int) bool {
	shown := false

	for i := range numMoons {
		moonHash := int(safeHashByte(hash, i+17))
		moonType := moonTypes[moonHash%len(moonTypes)]

		phase := float64(safeHashByte(hash, i*3+29)) / 255.0 * 2 * math.Pi
		moonTilt := 0.4 + float64(safeHashByte(hash, i+31)%30)/60.0
		eccentricity := 1.0 + float64(safeHashByte(hash, i+11)%20)/60.0
		dist := moonType.SizeBias * float64(radius+3+i*2)

		mx := int(dist * math.Cos(phase) * eccentricity)
		my := int(dist * math.Sin(phase) * moonTilt)

		if x == mx && y == my {
			char := moonType.Glyphs[safeHashByte(hash, x+y)%byte(len(moonType.Glyphs))]
			moonColor := color256(moonType.BaseColor + int(safeHashByte(hash, x-y+i))%8)
			writeToPlanet(b, noColor, moonColor, char)
			shown = true
		} else {
			if drawMoonOrbit(b, hash, x, y, dist, eccentricity, moonTilt) {
				shown = true
			}

		}
	}

	return shown
}

func drawMoonOrbit(b *strings.Builder, hash [32]byte, x, y int, dist float64, eccentricity, tilt float64) bool {
	for t := 0.0; t < 2*math.Pi; t += 0.15 {
		ox := int(dist * math.Cos(t) * eccentricity)
		oy := int(dist * math.Sin(t) * tilt)

		if math.Hypot(float64(x-ox), float64(y-oy)) < 1.0 {
			continue
		}
		if x == ox && y == oy {
			orbitChars := []rune{'.', '·', '∘', '⸰'}
			char := orbitChars[safeHashByte(hash, x+y)%byte(len(orbitChars))]
			fade := int(230 + 10*math.Sin(t))
			writeToPlanet(b, noColor, color256(fade), char)

			return true
		}
	}
	return false
}
