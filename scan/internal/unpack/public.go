package unpack

// FindHelpers reports which optional external unpackers are installed.
func FindHelpers() map[string]string { return findHelpers("auto") }
