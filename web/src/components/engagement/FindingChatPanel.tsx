import { useEffect, useRef, useState, type FormEvent } from 'react'
import { get, post } from '@/lib/api'
import { Button } from '@/components/ui/button'

interface Turn {
  role: 'user' | 'assistant'
  text: string
  evidence_sha256?: string
}
interface Transcript {
  session: string
  finding_id: string
  title: string
  status: string
  severity: string
  turns: Turn[]
  note: string
}
export function FindingChatPanel({
  session, findingID, title, onClose,
}: {
  session: string
  findingID: string
  title: string
  onClose: () => void
}) {
  const [transcript, setTranscript] = useState<Transcript | null>(null)
  const [question, setQuestion] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const bottom = useRef<HTMLDivElement | null>(null)
  const path = '/engagement/finding-chat?session=' + encodeURIComponent(session) + '&finding=' + encodeURIComponent(findingID)
  useEffect(() => {
    let active = true
    setTranscript(null)
    setError('')
    get<Transcript>(path)
      .then((d) => { if (active) setTranscript(d) })
      .catch((e) => { if (active) setError((e as Error).message) })
    return () => { active = false }
  }, [path])
  useEffect(() => {
    bottom.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  }, [transcript?.turns.length])

  async function ask(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy || question.trim().length < 2) return
    const text = question.trim()
    setBusy(true)
    setError('')
    try {
      const updated = await post<Transcript>(path, { question: text })
      setTranscript(updated)
      setQuestion('')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <section aria-label={'Finding discussion: ' + title} className="mt-4 rounded-[var(--radius-lg)] border border-border p-4">
      <div className="mb-3 flex items-start justify-between gap-2">
        <div>
          <h3 className="text-sm font-semibold">Discuss finding {findingID}</h3>
          <p className="mt-1 text-xs text-muted-foreground">{title}</p>
        </div>
        <Button size="sm" variant="outline" onClick={onClose} aria-label="Close finding discussion">Close</Button>
      </div>
      <p className="mb-3 text-xs text-muted-foreground">
        Evidence-grounded review. Answers use the recorded finding only and do not verify a vulnerability.
      </p>
      <div role="log" aria-live="polite" aria-relevant="additions" className="max-h-80 space-y-3 overflow-y-auto rounded-md bg-raised p-3">
        {transcript?.turns.length ? transcript.turns.map((turn, i) => (
          <article key={i + '-' + turn.role} className="rounded-md border border-border bg-card p-3 text-sm">
            <p className="mb-1 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
              {turn.role === 'user' ? 'You' : 'Evidence review'}
            </p>
            <p className="whitespace-pre-wrap break-words">{turn.text}</p>
            {turn.evidence_sha256 ? (
              <p className="mt-2 truncate font-mono text-[10px] text-muted-foreground" title={turn.evidence_sha256}>
                Ledger digest: {turn.evidence_sha256.slice(0, 16)}…
              </p>
            ) : null}
          </article>
        )) : <p className="text-xs text-muted-foreground">
          Ask about severity, reproduction evidence, retesting, remediation, or duplicate status.
        </p>}
        <div ref={bottom} />
      </div>
      {error ? <p role="alert" className="mt-2 text-xs text-destructive">{error}</p> : null}
      <form onSubmit={(event) => void ask(event)} className="mt-3 flex flex-col gap-2 sm:flex-row">
        <label className="sr-only" htmlFor="finding-question">Ask about finding</label>
        <input
          id="finding-question"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          maxLength={500}
          disabled={busy}
          placeholder="Ask about evidence or retesting…"
          className="min-w-0 flex-1 rounded-md border border-border bg-card px-3 py-2 text-sm"
        />
        <Button type="submit" size="sm" disabled={busy || question.trim().length < 2}>
          {busy ? 'Reviewing…' : 'Ask'}
        </Button>
      </form>
    </section>
  )
}
