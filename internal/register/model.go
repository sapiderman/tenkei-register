package register

import "github.com/sapiderman/tenkei-register/internal/types"

// User is an alias for types.User, used throughout the register package.
// This ensures both register and auth packages share the same model definition.
type User = types.User
