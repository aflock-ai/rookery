import CiProvenance.Eval

/-- `ciprov-eval`: one JSON case per stdin line, one JSON result per stdout
line. See `CiProvenance/Eval.lean` for the case shapes. -/
partial def loop (stdin : IO.FS.Stream) (stdout : IO.FS.Stream) : IO Unit := do
  let line ← stdin.getLine
  if line.isEmpty then return
  let trimmed := line.trimAscii.toString
  if !trimmed.isEmpty then
    stdout.putStrLn (CiProvenance.Eval.evalLine trimmed)
    stdout.flush
  loop stdin stdout

def main : IO Unit := do
  loop (← IO.getStdin) (← IO.getStdout)
