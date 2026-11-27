import { useEffect, useState } from 'react'
import { get } from '@/lib/api'
import { copyText } from '@/lib/clipboard'
import { Button } from '@/components/ui/button'

interface RunRow {
  run_id: string
  campaign_id?: string
  kind?: 'run' | 'draft'
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
  const [artifact, setArtifact] = useState<'script'|'validation'|'oracle'>('script')
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
  const selectedRow = runs.find(r => ((r.campaign_id ?? '')+':'+r.run_id)===selected)
  useEffect(() => {
    if (!selectedRow) {setContents(''); return}
    let live = true
    setBusy(true)
    setContents('')
    setError('')
    const campaign = selectedRow.campaign_id ? '&campaign='+encodeURIComponent(selectedRow.campaign_id) : ''
    get<Artifact>('/engagement/python-proofs?run='+encodeURIComponent(selectedRow.run_id)+campaign+'&artifact='+artifact)
      .then(d => {if (live) setContents(d.contents)})
      .catch(e => {if (live) setError((e as Error).message)})
      .finally(() => {if (live) setBusy(false)})
    return () => {live = false}
  }, [selected,artifact,runs])

  return (
    <section className="space-y-4">
      <div className="rounded-[var(--radius-lg)] border border-border p-5">
        <h2 className="text-base font-semibold">Python proof scripts and validation</h2>
        <p className="mt-2 text-sm text-muted-foreground">
          Every executed script and proposed draft is preserved. Inspect SHA-256 digests, case results, and
          sanitized validation here. Complete HTTP requests and responses are stored encrypted
          and are available only through the explicit local triage export command.
        </p>
      </div>
      {runs.length === 0 ? (
        <p className="rounded-lg border border-border p-4 text-sm text-muted-foreground">
          No saved Python proof runs are available for the currently configured engagement.
          Configure an approved endpoint inventory and run <code>python_adaptive_proof_run</code> or draft a hypothesis.
        </p>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[minmax(12rem,1fr)_minmax(0,2fr)]">
          <div className="space-y-2">
            {runs.map(run => (
              <button type="button" key={(run.campaign_id ?? '')+':'+run.run_id}
                onClick={() => {setSelected((run.campaign_id ?? '')+':'+run.run_id);setArtifact('script')}}
                aria-pressed={selected===(run.campaign_id ?? '')+':'+run.run_id}
                className={'w-full rounded-md border p-3 text-left text-sm transition-colors '+(selected===run.run_id?'border-foreground bg-raised':'border-border hover:bg-raised')}>
                <span className="block font-medium">{run.run_id}</span>
                {run.campaign_id ? <span className="mt-1 block text-[11px] text-muted-foreground">
                  Campaign: {run.campaign_id} · {run.kind === 'draft' ? 'Unexecuted hypothesis' : 'Captured round'}
                </span> : null}
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
                    {selectedRow?.kind === 'draft' ? 'Hypothesis selection' : 'Proof validation'}
                  </Button>
                  {selectedRow?.kind === 'draft' ? (
                    <Button size="sm" variant={artifact==='oracle'?'default':'outline'} onClick={()=>setArtifact('oracle')}>
                      Offline Python oracle
                    </Button>
                  ) : null}
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
