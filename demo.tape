Output demo.gif
Set Shell "bash"
Set Width 1200
Set Height 720
Set FontSize 18
Set TypingSpeed 35ms
Set PlaybackSpeed 1.0

Type "clear" Enter
Sleep 500ms
Type "echo 'Orynval Labs — local-first security suite'" Enter
Sleep 1s

Type "./bin/nhi-ghost internal/nhi/testdata | sed -n '1,22p'" Enter
Sleep 3s

Type "clear" Enter
Type "./bin/mcp-drift internal/mcp/testdata | sed -n '1,22p'" Enter
Sleep 3s

Type "clear" Enter
Type "./bin/trust-proof --questions internal/trustproof/testdata/questions.csv --evidence internal/trustproof/testdata/evidence" Enter
Sleep 4s
