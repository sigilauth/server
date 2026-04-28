package pictogram

// Wordlist returns the canonical 64-word pictogram wordlist.
//
// This wordlist is used to map 6-bit indices (0-63) to human-friendly words.
// The list is ordered and must remain stable across all Sigil Auth implementations.
//
// Word selection criteria:
// - Short (1-2 syllables preferred)
// - Globally recognizable (food, animals, vehicles, nature, objects)
// - Unambiguous (no homophones or easily confused words)
// - Family-friendly
//
// Per D10: These are the speakable names, not emoji characters.
// Emoji rendering is platform-specific; speakable names are canonical.
func Wordlist() [64]string {
	return [64]string{
		// 0-7: Fruits
		"apple", "banana", "grapes", "orange", "lemon", "cherry", "strawberry", "kiwi",

		// 8-15: Vegetables
		"carrot", "corn", "broccoli", "mushroom", "pepper", "avocado", "onion", "peanut",

		// 16-23: Food
		"pizza", "burger", "taco", "donut", "cookie", "cake", "cupcake", "popcorn",

		// 24-31: Vehicles
		"car", "taxi", "bus", "rocket", "plane", "helicopter", "sailboat", "bicycle",

		// 32-39: Animals
		"dog", "cat", "fish", "butterfly", "bee", "fox", "lion", "elephant",

		// 40-47: Nature
		"tree", "sunflower", "cactus", "clover", "blossom", "rainbow", "star", "moon",

		// 48-55: Places
		"house", "mountain", "peak", "volcano", "island", "moai", "tent", "castle",

		// 56-63: Objects
		"key", "bell", "books", "guitar", "anchor", "crown", "diamond", "fire",
	}
}
