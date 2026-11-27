package capabilities

import "encoding/json"

func jsonNum(s string) json.Number { return json.Number(s) }
