package collect

// Resources is a one-shot host snapshot for the tile header.
type Resources struct {
	CPU, RAM, Disk int
	OK             bool
}
