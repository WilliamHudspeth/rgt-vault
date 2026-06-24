# Patch model_test.go
with open("go/internal/tui/model_test.go", "r") as f:
    model_test = f.read()

model_test = model_test.replace(
    "func (f *fakeClient) Rotate(target string) error {\n\treturn f.rotateErr\n}",
    "func (f *fakeClient) Rotate(target string) error {\n\treturn f.rotateErr\n}\n\nfunc (f *fakeClient) GetAuditLog(limit int) ([]AuditEntry, error) {\n\treturn nil, nil\n}",
)

with open("go/internal/tui/model_test.go", "w") as f:
    f.write(model_test)

# Patch extensions_test.go
with open("go/internal/tui/extensions_test.go", "r") as f:
    ext_test = f.read()

ext_test = ext_test.replace(
    "func (f *fakeClientTOTP) Rotate(string) error { return nil }",
    "func (f *fakeClientTOTP) Rotate(string) error { return nil }\nfunc (f *fakeClientTOTP) GetAuditLog(int) ([]AuditEntry, error) { return nil, nil }",
)
ext_test = ext_test.replace(
    "func (f *fakeClientTree) Rotate(string) error { return nil }",
    "func (f *fakeClientTree) Rotate(string) error { return nil }\nfunc (f *fakeClientTree) GetAuditLog(int) ([]AuditEntry, error) { return nil, nil }",
)

with open("go/internal/tui/extensions_test.go", "w") as f:
    f.write(ext_test)

print("Tests patched!")
