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
	resetColor = "\033[0m"
	starChar   = "✦"
	moonChar   = "o"
)

// TerrainType represents a specific type of terrain with its characters and color range
type TerrainType struct {
	Name       string
	Chars      string
	BaseColor  int
	ColorRange int
}

// Define different terrain types with their visual representations
var terrainTypes = []TerrainType{
	{"Ocean", "~≈≋≈~", 20, 10},    // Blue-ish
	{"Plains", ".:-=", 64, 15},    // Light greenish
	{"Mountains", "^▲∆▴", 94, 20}, // Brown/gray
	{"Forests", "♣♠φ", 28, 8},     // Dark green
	{"Desert", "░▒∴∷", 184, 12},   // Yellow/orange
	{"Tundra", "❄❅❆", 231, 10},    // White/light blue
	{"Volcanic", "♨*#", 196, 15},  // Red/black
	{"Canyon", "≡≣≢", 130, 12},    // Red-brown
	{"Swamp", "≠≃≄", 100, 10},     // Dark green/brown
	{"Ice Cap", "◊◇◈", 159, 8},    // Cyan/white
	{"Reef", "◌○◍", 45, 10},       // Cyan/blue patterns
	{"Plateau", "■□▢", 179, 12},   // Light brown
	{"Crystals", "✧✦✵", 51, 20},   // Crystal formations (exotic)
	{"Radiation", "☢☣⚠", 118, 25}, // Highly radioactive areas
	{"Strange", "⊛⊗⊙", 93, 30},    // Anomalous terrain
}

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
	{"Orange: Methane-rich", 208, 40, 1.7},
	{"Blue: Argon-Nitrogen", 27, -10, 1.4},
}

type BiomeDistribution struct {
	Name            string
	TerrainTypes    []int  // Indices to terrainTypes
	MainType        int    // Index of the dominant terrain
	DistPattern     string // "Bands", "Patches", "Hemispheres", "Scattered"
	HasSeasons      bool
	HasWeather      bool
	PolarCapType    int     // Index to special polar terrain, -1 if none
	EquatorType     int     // Special equator terrain, -1 if none
	ElevationFactor float64 // How much elevation affects terrain
}

var biomeDistributions = []BiomeDistribution{
	{
		Name:            "Earth-like",
		TerrainTypes:    []int{0, 1, 2, 3, 4},
		MainType:        0, // Ocean
		DistPattern:     "Realistic",
		HasSeasons:      true,
		HasWeather:      true,
		PolarCapType:    5, // Tundra
		EquatorType:     4, // Desert
		ElevationFactor: 1.0,
	},
	{
		Name:            "Desert World",
		TerrainTypes:    []int{4, 7, 11},
		MainType:        4, // Desert
		DistPattern:     "Bands",
		HasSeasons:      true,
		HasWeather:      false,
		PolarCapType:    -1,
		EquatorType:     7, // Canyon
		ElevationFactor: 0.8,
	},
	{
		Name:            "Ice Planet",
		TerrainTypes:    []int{5, 9, 0},
		MainType:        5, // Tundra
		DistPattern:     "Patches",
		HasSeasons:      false,
		HasWeather:      true,
		PolarCapType:    9, // Ice Cap
		EquatorType:     0, // Small oceans
		ElevationFactor: 0.5,
	},
	{
		Name:            "Jungle World",
		TerrainTypes:    []int{3, 8, 0, 12},
		MainType:        3, // Forest
		DistPattern:     "Scattered",
		HasSeasons:      true,
		HasWeather:      true,
		PolarCapType:    -1,
		EquatorType:     8, // Swamp
		ElevationFactor: 1.2,
	},
	{
		Name:            "Volcanic",
		TerrainTypes:    []int{6, 2, 13},
		MainType:        6, // Volcanic
		DistPattern:     "Patches",
		HasSeasons:      false,
		HasWeather:      true,
		PolarCapType:    -1,
		EquatorType:     -1,
		ElevationFactor: 1.5,
	},
	{
		Name:            "Ocean World",
		TerrainTypes:    []int{0, 10, 1},
		MainType:        0, // Ocean
		DistPattern:     "Scattered",
		HasSeasons:      true,
		HasWeather:      true,
		PolarCapType:    9,  // Ice Cap
		EquatorType:     10, // Reef
		ElevationFactor: 0.7,
	},
	{
		Name:            "Exotic Anomaly",
		TerrainTypes:    []int{12, 14, 6, 13},
		MainType:        12, // Crystals
		DistPattern:     "Chaotic",
		HasSeasons:      false,
		HasWeather:      false,
		PolarCapType:    -1,
		EquatorType:     14, // Strange
		ElevationFactor: 2.0,
	},
}

type RingComposition struct {
	Name      string
	BaseColor int
	Chars     string
}

var ringCompositions = []RingComposition{
	{"Icy", 231, " ~≈"},
	{"Rocky", 245, "=/|"},
	{"Dusty", 130, "--:."},
	{"Organic", 94, "::."},
	{"Metallic", 248, "≡≢≣"},
	{"Crystalline", 51, "✧✦✵"},
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

type WeatherPattern struct {
	Name       string
	Symbol     rune
	BaseColor  int
	ColorRange int
	Frequency  float64 // How common this pattern is
}

var weatherPatterns = []WeatherPattern{
	{"Hurricane", '⊗', 33, 5, 0.2},
	{"Storm", '⚡', 226, 10, 0.4},
	{"Cloud System", '☁', 252, 3, 0.5},
	{"Rain", ':', 21, 2, 0.7},
	{"Dust Storm", '∿', 172, 5, 0.3},
	{"Vortex", '※', 201, 10, 0.2},
}

type Planet struct {
	Name             string
	Radius           int
	Width            int
	Height           int
	HasAtmosphere    bool
	AtmosphereType   Atmosphere
	HasRings         bool
	RingType         RingComposition
	NumMoons         int
	NumStars         int
	HasCore          bool
	HasSuperStorm    bool
	TiltAngle        int
	HasMagneticField bool
	HasBiomes        bool
	BiomeType        BiomeDistribution
	ElevationMap     [][]float64
	TerrainMap       [][]int
	WeatherMap       [][]int
	Hash             [32]byte
}

var (
	planetName  = flag.String("name", "", "Name of the planet")
	summaryOnly = flag.Bool("summary", false, "Only display the planet summary")
	noColor     = flag.Bool("no-color", false, "Disable ANSI colors")
	monoColor   = flag.Bool("mono", false, "Alias for --no-color")
	widthScale  = flag.Float64("width-scale", 1.0, "Horizontal scaling factor for the planet (e.g. 1.5 = wider)")
	detailLevel = flag.Int("detail", 1, "Detail level for terrain (1-3)")
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

	planet := generatePlanet(name)

	if *summaryOnly {
		fmt.Print(generatePlanetSummary(planet))
		return
	}

	fmt.Print(renderPlanet(planet))
	fmt.Print(generatePlanetSummary(planet))
}

func generateScientificPlanetName(seed string) string {
	prefixes := []string{"HD", "Gliese", "Kepler", "Tau", "XK", "Zeta", "PSR", "KIC", "BD", "HIP", "LHS", "Trappist"}
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

func generatePlanet(name string) Planet {
	hash := sha256.Sum256([]byte(name))

	planet := Planet{
		Name:   name,
		Radius: 16 + int(hash[0])%9,
		Hash:   hash,
	}

	planet.Width = int(float64(planet.Radius*2) * *widthScale)
	planet.Height = planet.Radius

	planet.HasAtmosphere = hash[2]%100 < 80
	planet.HasRings = planet.Radius >= 21 && hash[3]%100 < 75

	moonFactor := int(math.Max(0, float64(planet.Radius-14)))
	planet.NumMoons = int((hash[4] % uint8(moonFactor+1)))
	if planet.Radius >= 22 {
		planet.NumMoons += int(hash[5] % 2)
	}
	if planet.Radius < 18 && hash[6]%100 < 30 {
		planet.NumMoons = 0
	}

	planet.NumStars = int(hash[7]%3) + 1
	planet.HasCore = hash[8]%100 < 70
	planet.HasSuperStorm = planet.HasAtmosphere && hash[9]%100 < 40
	planet.TiltAngle = int(hash[10]) % 45
	planet.HasMagneticField = hash[11]%100 < 65
	planet.HasBiomes = planet.HasAtmosphere && hash[12]%100 < 60

	if planet.HasAtmosphere {
		planet.AtmosphereType = atmosphereTypes[int(hash[1])%len(atmosphereTypes)]
	}

	if planet.HasRings {
		planet.RingType = ringCompositions[int(hash[13])%len(ringCompositions)]
	}

	if planet.HasBiomes {
		planet.BiomeType = biomeDistributions[int(hash[14])%len(biomeDistributions)]
		generateTerrainMap(&planet)
	}

	return planet
}

// Generate elevation and terrain maps for the planet
func generateTerrainMap(planet *Planet) {
	// Initialize maps
	elevationMap := make([][]float64, planet.Height*2+1)
	terrainMap := make([][]int, planet.Height*2+1)
	weatherMap := make([][]int, planet.Height*2+1)

	// Generate elevation using multiple layers of noise
	for y := 0; y < planet.Height*2+1; y++ {
		elevationMap[y] = make([]float64, planet.Width*2+1)
		terrainMap[y] = make([]int, planet.Width*2+1)
		weatherMap[y] = make([]int, planet.Width*2+1)

		for x := 0; x < planet.Width*2+1; x++ {
			// Calculate position relative to center
			xr := float64(x)/float64(planet.Width*2)*2 - 1
			yr := float64(y)/float64(planet.Height*2)*2 - 1

			// Distance from center (0 to 1)
			dist := math.Sqrt(xr*xr + yr*yr)

			// Skip if outside planet radius
			if dist > 1.0 {
				continue
			}

			// Base elevation with several noise layers
			elevation := 0.0

			// Use hash-based noise for terrain generation
			h1 := safeHashFloatAt(planet.Hash, x, y)
			h2 := safeHashFloatAt(planet.Hash, x+100, y+100)
			h3 := safeHashFloatAt(planet.Hash, x*2, y*3)

			// Large scale features
			elevation += (h1*0.3 + h2*0.2) * 1.5

			// Medium scale features
			elevation += (h2*0.15 + h3*0.15) * 0.7

			// Small scale features
			elevation += h3 * 0.3

			// Apply latitude effect
			latitude := math.Abs(yr)

			// Store elevation
			elevationMap[y][x] = elevation

			// Assign terrain type based on biome distribution
			terrainType := assignTerrainType(planet, elevation, latitude, xr, yr)
			terrainMap[y][x] = terrainType

			// Assign weather if applicable
			if planet.BiomeType.HasWeather && safeHashByteAt(planet.Hash, x, y)%100 < 5 {
				weatherMap[y][x] = int(safeHashByteAt(planet.Hash, x+50, y+50)) % len(weatherPatterns)
			} else {
				weatherMap[y][x] = -1
			}
		}
	}

	planet.ElevationMap = elevationMap
	planet.TerrainMap = terrainMap
	planet.WeatherMap = weatherMap
}

func assignTerrainType(planet *Planet, elevation float64, latitude, xr, yr float64) int {
	biome := planet.BiomeType

	// Handle polar caps
	if biome.PolarCapType >= 0 && latitude > 0.75 {
		return biome.PolarCapType
	}

	// Handle equator special terrain
	if biome.EquatorType >= 0 && latitude < 0.2 {
		return biome.EquatorType
	}

	// Use different distribution patterns
	switch biome.DistPattern {
	case "Bands":
		// Latitude-based banding
		latBand := int(latitude*10) % len(biome.TerrainTypes)
		return biome.TerrainTypes[latBand]

	case "Patches":
		// Create more distinct regions
		noiseVal := safeHashFloatAt(planet.Hash, int(xr*100), int(yr*100))
		idx := int(noiseVal * float64(len(biome.TerrainTypes)))
		return biome.TerrainTypes[idx%len(biome.TerrainTypes)]

	case "Hemispheres":
		// Different terrain in northern/southern hemispheres
		if yr >= 0 {
			return biome.TerrainTypes[0]
		}
		return biome.TerrainTypes[min(1, len(biome.TerrainTypes)-1)]

	case "Scattered":
		// More random distribution
		noiseVal := safeHashFloatAt(planet.Hash, int(xr*200), int(yr*200))
		if noiseVal > 0.75 {
			return biome.TerrainTypes[min(1, len(biome.TerrainTypes)-1)]
		} else if noiseVal > 0.5 {
			return biome.TerrainTypes[min(2, len(biome.TerrainTypes)-1)]
		} else {
			return biome.MainType
		}

	case "Chaotic":
		// Completely random distribution
		idx := int(safeHashByteAt(planet.Hash, int(xr*100), int(yr*100))) % len(biome.TerrainTypes)
		return biome.TerrainTypes[idx]

	default: // "Realistic"
		// Elevation-based with some randomness
		if elevation > 0.6 {
			// Mountains
			return biome.TerrainTypes[min(2, len(biome.TerrainTypes)-1)]
		} else if elevation < 0.3 {
			// Oceans/low areas
			return biome.TerrainTypes[0]
		} else {
			// Mid elevations
			return biome.TerrainTypes[min(1, len(biome.TerrainTypes)-1)]
		}
	}
}

func renderPlanet(planet Planet) string {
	var b strings.Builder

	for y := -planet.Height - 5; y <= planet.Height+5; y++ {
		for x := -planet.Width - 8; x <= planet.Width+8; x++ {
			xf := float64(x) + 0.5
			yf := float64(y) * 1.8
			d := math.Sqrt(xf*xf + yf*yf)

			// Render atmosphere
			if planet.HasAtmosphere && d >= float64(planet.Radius)+0.5 && d <= float64(planet.Radius)+planet.AtmosphereType.GlowWidth {
				glowChar := ' '
				noise := int(safeHashByteAt(planet.Hash, x+y, 0)) % 10
				glowColor := color256(planet.AtmosphereType.BaseColor + noise)
				writeToPlanet(&b, noColor, glowColor, glowChar)
				continue
			}

			// Render planet surface
			if d < float64(planet.Radius) {
				renderPlanetSurface(planet, &b, x, y, d)
				continue
			}

			// Render rings
			if planet.HasRings && renderRings(planet, &b, x, y, xf, yf) {
				continue
			}

			// Render moons
			if planet.NumMoons > 0 && y < -planet.Radius-2 {
				if renderMoonSystem(&b, planet.Hash, x, y, planet.Radius, planet.NumMoons) {
					continue
				}
			}

			// Render starfield
			renderStarfield(planet, &b, x, y, xf, yf)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func renderPlanetSurface(planet Planet, b *strings.Builder, x, y int, d float64) {
	// Convert to planet surface coordinates
	surfX := x + planet.Width
	surfY := y + planet.Height

	// Check boundaries
	if surfX < 0 || surfY < 0 || surfX >= planet.Width*2+1 || surfY >= planet.Height*2+1 {
		b.WriteString(" ")
		return
	}

	// Basic surface properties
	lat := float64(y+planet.Height) / float64(planet.Height*2)
	lon := float64(x+planet.Width) / float64(planet.Width*2)

	h1 := safeHashByteAt(planet.Hash, x*y, 0)
	h2 := safeHashByteAt(planet.Hash, x+y, 0)

	// If we have biomes, use the terrain map
	if planet.HasBiomes && surfY < len(planet.TerrainMap) && surfX < len(planet.TerrainMap[surfY]) {
		terrainIdx := planet.TerrainMap[surfY][surfX]
		if terrainIdx >= 0 && terrainIdx < len(terrainTypes) {
			terrain := terrainTypes[terrainIdx]

			// Select character from terrain type
			charIdx := int(h1) % len(terrain.Chars)
			char := rune(terrain.Chars[charIdx])

			// Select color with variation
			colorVar := int(h2) % terrain.ColorRange
			color := color256((terrain.BaseColor + colorVar) % 240)

			// Apply atmosphere color shift if present
			if planet.HasAtmosphere {
				color = color256((terrain.BaseColor + colorVar + planet.AtmosphereType.TerrainHueShift) % 240)
			}

			// Check for weather
			if planet.BiomeType.HasWeather &&
				surfY < len(planet.WeatherMap) &&
				surfX < len(planet.WeatherMap[surfY]) &&
				planet.WeatherMap[surfY][surfX] >= 0 {

				weatherIdx := planet.WeatherMap[surfY][surfX]
				weather := weatherPatterns[weatherIdx]

				// Override with weather
				char = weather.Symbol
				colorVar = int(h2) % weather.ColorRange
				color = color256(weather.BaseColor + colorVar)
			}

			// Special case for core visibility
			if planet.HasCore && d < float64(planet.Radius)*0.25 {
				color = color256(196 + int(h1)%8)
				char = '✹'
			}

			// Super storm system
			if planet.HasSuperStorm && int(y)%7 == 0 && int(float64(x)*lat*lon*1000)%11 == 0 {
				color = color256(124 + (int(x+y) % 10))
				char = '⊗'
			}

			writeToPlanet(b, noColor, color, char)
			return
		}
	}

	// Fallback to basic terrain if no biome or out of bounds
	rawTidx := int(lat*10 + float64(h1%5) + math.Sin((lon*10)+float64(planet.TiltAngle)/10)*3)
	if rawTidx < 0 {
		rawTidx = -rawTidx
	}

	basicTerrainChars := "·.:+*#%@"
	tidx := rawTidx % len(basicTerrainChars)
	char := rune(basicTerrainChars[tidx])

	base := int(lat*100) + int(h2)%30 + tidx*7
	if planet.HasAtmosphere {
		base += planet.AtmosphereType.TerrainHueShift
	}
	if base < 0 {
		base += 240
	}
	color := color256(base % 240)

	writeToPlanet(b, noColor, color, char)
}

func renderRings(planet Planet, b *strings.Builder, x, y int, xf, yf float64) bool {
	ringComp := planet.RingType
	ringViewHorizontal := planet.Hash[14]%100 < 40 // ~40% chance

	if ringViewHorizontal {
		ringYOffset := math.Tan(float64(planet.TiltAngle)*math.Pi/180) * xf * 0.2
		if math.Abs(yf-ringYOffset) < 2 && math.Abs(xf) < float64(planet.Width) {
			char := rune(ringComp.Chars[int(math.Abs(xf))%len(ringComp.Chars)])
			color := color256(ringComp.BaseColor + int(safeHashByteAt(planet.Hash, x*y+int(xf), 0))%10)
			writeToPlanet(b, noColor, color, char)
			return true
		}
	} else {
		tiltedY := yf - math.Tan(float64(planet.TiltAngle)*math.Pi/180)*xf*0.2
		ringDistance := math.Abs(math.Sqrt(xf*xf+tiltedY*tiltedY) - float64(planet.Radius) - 1.5)
		if ringDistance >= 0 && ringDistance <= 4.5 {
			band := int(ringDistance * 2)
			char := rune(ringComp.Chars[band%len(ringComp.Chars)])
			color := color256(ringComp.BaseColor + int(safeHashByteAt(planet.Hash, x*y+band, 0))%10)
			writeToPlanet(b, noColor, color, char)
			return true
		}
	}

	return false
}

func renderStarfield(planet Planet, b *strings.Builder, x, y int, xf, yf float64) {
	// Calculate star chance based on number of stars
	starChance := 3 + planet.NumStars*2 // Star density scales with # of visible stars

	spaceHash := safeHashByteAt(planet.Hash, x*y+y-x, 0)
	if int(spaceHash)%100 < starChance &&
		(math.Abs(xf) > float64(planet.Width)*0.6 || math.Abs(yf) > float64(planet.Height)*0.6) {

		starChars := []rune(" .:*✶✦")
		brightness := int(spaceHash) % len(starChars)
		char := starChars[brightness]
		if *noColor {
			char = '*'
		}
		color := color256(230 + brightness*2)
		writeToPlanet(b, noColor, color, char)
	} else {
		b.WriteString(" ")
	}
}

func renderMoonSystem(b *strings.Builder, hash [32]byte, x, y, radius, numMoons int) bool {
	shown := false

	for i := range numMoons {
		moonHash := int(safeHashByteAt(hash, i+17, 0))
		moonType := moonTypes[moonHash%len(moonTypes)]

		phase := float64(safeHashByteAt(hash, i*3+29, 0)) / 255.0 * 2 * math.Pi
		moonTilt := 0.4 + float64(safeHashByteAt(hash, i+31, 0)%30)/60.0
		eccentricity := 1.0 + float64(safeHashByteAt(hash, i+11, 0)%20)/60.0
		dist := moonType.SizeBias * float64(radius+3+i*2)

		mx := int(dist * math.Cos(phase) * eccentricity)
		my := int(dist * math.Sin(phase) * moonTilt)

		if x == mx && y == my {
			char := moonType.Glyphs[safeHashByteAt(hash, x+y, 0)%byte(len(moonType.Glyphs))]
			moonColor := color256(moonType.BaseColor + int(safeHashByteAt(hash, x-y+i, 0))%8)
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
			char := orbitChars[safeHashByteAt(hash, x+y, 0)%byte(len(orbitChars))]
			fade := int(230 + 10*math.Sin(t))
			writeToPlanet(b, noColor, color256(fade), char)

			return true
		}
	}
	return false
}

func generatePlanetSummary(planet Planet) string {
	var summary strings.Builder

	summary.WriteString(fmt.Sprintf("======== %s ========\n", planet.Name))

	// Basic properties
	summary.WriteString(fmt.Sprintf("Radius: %d\n", planet.Radius))
	summary.WriteString(fmt.Sprintf("Axial Tilt: %d°\n", planet.TiltAngle))

	// Atmospheric properties
	summary.WriteString(fmt.Sprintf("Atmosphere: %s\n", map[bool]string{true: "Present", false: "Absent"}[planet.HasAtmosphere]))
	if planet.HasAtmosphere {
		summary.WriteString(fmt.Sprintf("  Type: %s\n", planet.AtmosphereType.Name))
	}

	// Ring properties
	summary.WriteString(fmt.Sprintf("Rings: %s", map[bool]string{true: "Present", false: "Absent"}[planet.HasRings]))
	if planet.HasRings {
		summary.WriteString(fmt.Sprintf(" (%s composition)", planet.RingType.Name))
	}
	summary.WriteString("\n")

	// Moons
	summary.WriteString(fmt.Sprintf("Moons: %d\n", planet.NumMoons))
	summary.WriteString(fmt.Sprintf("Stars Visible: %d\n", planet.NumStars))

	// Special features
	summary.WriteString(fmt.Sprintf("Core: %s\n", map[bool]string{true: "Visible", false: "Not visible"}[planet.HasCore]))
	if planet.HasMagneticField {
		summary.WriteString("Magnetic Field: Strong\n")
	}
	if planet.HasSuperStorm {
		summary.WriteString("Superstorms: Detected\n")
	}

	// Biome information
	if planet.HasBiomes {
		summary.WriteString(fmt.Sprintf("Biome: %s\n", planet.BiomeType.Name))
		summary.WriteString("Terrain Types:\n")

		for _, terrainIdx := range planet.BiomeType.TerrainTypes {
			if terrainIdx >= 0 && terrainIdx < len(terrainTypes) {
				summary.WriteString(fmt.Sprintf("  - %s\n", terrainTypes[terrainIdx].Name))
			}
		}

		if planet.BiomeType.HasWeather {
			summary.WriteString("Weather Systems: Active\n")
		}
		if planet.BiomeType.HasSeasons {
			summary.WriteString("Seasonal Variations: Present\n")
		}
	}

	return summary.String()
}

func writeToPlanet(b *strings.Builder, noColor *bool, color string, char rune) {
	if *noColor {
		b.WriteRune(char)
	} else {
		b.WriteString(color + string(char) + resetColor)
	}
}

func safeHashByteAt(hash [32]byte, x, y int) byte {
	i := (x*31 + y) % len(hash)
	if i < 0 {
		i += len(hash)
	}
	return hash[i]
}

func safeHashFloatAt(hash [32]byte, x, y int) float64 {
	return float64(safeHashByteAt(hash, x, y)) / 255.0
}

func color256(index int) string {
	return fmt.Sprintf("\033[38;5;%dm", 16+index%240)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
