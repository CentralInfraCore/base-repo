package testpkg

// PublicConstant is a public constant.
const PublicConstant = "hello"

// privateConstant is a private constant.
const privateConstant = "world"

// PublicVar is a public variable.
var PublicVar int

// privateVar is a private variable.
var privateVar int

// PublicStruct is a public type.
type PublicStruct struct {
	// PublicField is a public field.
	PublicField string
	privateField string
}

// privateStruct is a private type.
type privateStruct struct{}

// PublicFunc is a public function.
func PublicFunc(p PublicStruct) {}

// privateFunc is a private function.
func privateFunc() {}
