package harness

// emojiList is the canonical 64-emoji list from protocol-spec §3.6.
var emojiList = []string{
	"🍎", "🍌", "🍇", "🍊", "🍋", "🍒", "🍓", "🥝",
	"🥕", "🌽", "🥦", "🍄", "🌶️", "🥑", "🧅", "🥜",
	"🍕", "🍔", "🌮", "🍩", "🍪", "🎂", "🧁", "🍿",
	"🚗", "🚕", "🚌", "🚀", "✈️", "🚁", "⛵", "🚲",
	"🐕", "🐈", "🐟", "🦋", "🐝", "🦊", "🦁", "🐘",
	"🌲", "🌻", "🌵", "🍀", "🌸", "🌈", "⭐", "🌙",
	"🏠", "🏔️", "⛰️", "🌋", "🏝️", "🗿", "⛺", "🏰",
	"🔑", "🔔", "📚", "🎸", "⚓", "👑", "💎", "🔥",
}

// emojiNames maps indices to canonical speakable names.
var emojiNames = []string{
	"apple", "banana", "grapes", "orange", "lemon", "cherry", "strawberry", "kiwi",
	"carrot", "corn", "broccoli", "mushroom", "pepper", "avocado", "onion", "peanut",
	"pizza", "burger", "taco", "donut", "cookie", "cake", "cupcake", "popcorn",
	"car", "taxi", "bus", "rocket", "plane", "helicopter", "sailboat", "bicycle",
	"dog", "cat", "fish", "butterfly", "bee", "fox", "lion", "elephant",
	"tree", "sunflower", "cactus", "clover", "blossom", "rainbow", "star", "moon",
	"house", "mountain", "peak", "volcano", "island", "moai", "tent", "castle",
	"key", "bell", "books", "guitar", "anchor", "crown", "diamond", "fire",
}

// derivePictogram derives a 5-emoji pictogram from a fingerprint.
// Uses first 30 bits (5 × 6 bits) to index into the 64-emoji list.
func derivePictogram(fingerprint []byte) (emojis []string, speakable string) {
	if len(fingerprint) < 4 {
		return nil, ""
	}
	
	// First 4 bytes as uint32
	bits := uint32(fingerprint[0])<<24 | uint32(fingerprint[1])<<16 | uint32(fingerprint[2])<<8 | uint32(fingerprint[3])
	
	emojis = make([]string, 5)
	names := make([]string, 5)
	
	// Extract 5 × 6-bit indices
	emojis[0] = emojiList[(bits>>26)&0x3F]
	emojis[1] = emojiList[(bits>>20)&0x3F]
	emojis[2] = emojiList[(bits>>14)&0x3F]
	emojis[3] = emojiList[(bits>>8)&0x3F]
	emojis[4] = emojiList[(bits>>2)&0x3F]
	
	names[0] = emojiNames[(bits>>26)&0x3F]
	names[1] = emojiNames[(bits>>20)&0x3F]
	names[2] = emojiNames[(bits>>14)&0x3F]
	names[3] = emojiNames[(bits>>8)&0x3F]
	names[4] = emojiNames[(bits>>2)&0x3F]
	
	speakable = names[0] + "-" + names[1] + "-" + names[2] + "-" + names[3] + "-" + names[4]
	return emojis, speakable
}
