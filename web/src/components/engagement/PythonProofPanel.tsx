import { useEffect, useState } from 'react'
import { get } from '@/lib/api'
import { copyText } from '@/lib/clipboard'
import { Button } from '@/components/ui/button'

interface RunRow {
  run_id: string
  outcome: string
  script_sha256: string
  script_name: string
  cases: number
  raw_encrypted: boolean
}
interface Runs { runs: RunRow[]; note: string }
interface Artifact { run_id: string; artifact: string; contents: string }

export function PythonProofPanel() {
  const [runs, setRuns] = useState<RunRow[]>([])
  const [selected, setSelected] = useState('')
  const [artifact, setArtifact] = useState<'script'|'validation'>('script')
  const [contents, setContents] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    let live = true
    get<Runs>('/engagement/python-proofs')
      .then(d => { if (live) setRuns(d.runs ?? []) })
      .catch(e => { if (live) setError((e as Error).message) })
    return () => {live = false}
  }, [])
  useEffect(() => {
    if (!selected) {setContents(''); return}
    let live = true
    setBusy(true)
    setContents('')
    setError('')
    get<Artifact>('/engagement/python-proofs?run='+encodeURIComponent(selected)+'&artifact='+artifact)
      .then(d => {if (live) setContents(d.contents)})
      .catch(e => {if (live) setError((e as Error).message)})
      .finally(() => {if (live) setBusy(false)})
    return () => {live = false}
  }, [selected,artifact])

  return (
    <section className="space-y-4">
      <div className="rounded-[var(--radius-lg)] border border-border p-5">
        <h2 className="text-base font-semibold">Python proof scripts and validation</h2>
        <p className="mt-2 text-sm text-muted-foreground">
          Every script is saved exactly as executed. View its SHA-256 digest, case results, and
          sanitized validation here. Complete HTTP requests and responses are stored encrypted
          and are available only through the explicit local triage export command.
        </p>
      </div>
      {runs.length === 0 ? (
        <p className="rounded-lg border border-border p-4 text-sm text-muted-foreground">
          No saved Python proof runs are available for the currently configured engagement.
          Configure an approved proof plan and run <code>python_proof_run</code>.
        </p>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[minmax(12rem,1fr)_minmax(0,2fr)]">
          <div className="space-y-2">
            {runs.map(run => (
              <button type="button" key={run.run_id}
                onClick={() => setSelected(run.run_id)}
                aria-pressed={selected===run.run_id}
                className={'w-full rounded-md border p-3 text-left text-sm transition-colors '+(selected===run.run_id?'border-foreground bg-raised':'border-border hover:bg-raised')}>
                <span className="block font-medium">{run.run_id}</span>
                <span className="mt-1 block text-xs text-muted-foreground">{run.outcome} · {run.cases} cases</span>
                <span className="mt-1 block truncate font-mono text-[10px] text-muted-foreground" title={run.script_sha256}>
                  Python SHA-256: {run.script_sha256}
                </span>
                <span className="mt-1 block text-xs text-muted-foreground">
                  {run.raw_encrypted ? 'Encrypted HTTP proof stored' : 'No encrypted proof available'}
                </span>
              </button>
            ))}
          </div>
          <div className="min-w-0 rounded-md border border-border p-4">
            {!selected ? <p className="text-sm text-muted-foreground">Select a recorded Python run to inspect it.</p> : (
              <>
                <div className="mb-3 flex flex-wrap gap-2">
                  <Button size="sm" variant={artifact==='script'?'default':'outline'} onClick={()=>setArtifact('script')}>
                    Exact Python source
                  </Button>
                  <Button size="sm" variant={artifact==='validation'?'default':'outline'} onClick={()=>setArtifact('validation')}>
                    Proof validation
                  </Button>
                  <Button size="sm" variant="outline" disabled={!contents}
                    onClick={()=>void copyText(contents).then(ok=>{if(ok)setCopied(true)})}>
                    {copied?'Copied':'Copy artifact'}
                  </Button>
                </div>
                {busy ? <p className="text-xs text-muted-foreground">Loading saved artifact…</p> : (
                  <pre className="max-h-[36rem] overflow-auto whitespace-pre-wrap break-words rounded-md bg-raised p-3 text-xs leading-relaxed">
                    <code>{contents}</code>
                  </pre>
                )}
              </>
            )}
          </div>
        </div>
      )}
      {error ? <p role="alert" className="text-sm text-destructive">{error}</p> : null}
    </section>
  )
}
