package main

import _ "embed"

//go:embed admin_ui/index.html
var adminHTML []byte

//go:embed admin_ui/admin.css
var adminCSS []byte

//go:embed admin_ui/admin.js
var adminJS []byte
