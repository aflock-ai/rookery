import CilockEvaluators.Oracle

/-- Read JSON Lines from stdin, print one verdict per line. -/
partial def loop (stdin : IO.FS.Stream) (stdout : IO.FS.Stream) : IO Unit := do
  let line ← stdin.getLine
  if line.isEmpty then return
  let l := line.trimRight
  if !l.isEmpty then
    stdout.putStrLn (CilockEvaluators.Oracle.runCase l)
    stdout.flush
  loop stdin stdout

def main : IO Unit := do
  loop (← IO.getStdin) (← IO.getStdout)
