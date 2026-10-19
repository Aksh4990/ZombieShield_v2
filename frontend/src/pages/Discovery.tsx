import { FormEvent, useState } from 'react'
import { runGitDiscovery, runOpenApiDiscovery, runRuntimeLogDiscovery } from '../api'
import type { DiscoveryResponse } from '../types'

interface DiscoveryProps { onComplete: () => Promise<void> }

const baseFields = { organization: 'local-development', service_name: '', host: 'localhost', version: 'unversioned' }

export function Discovery({ onComplete }: DiscoveryProps) {
  const [source, setSource] = useState<'openapi' | 'git' | 'runtime-log'>('openapi')
  const [fields, setFields] = useState(baseFields)
  const [content, setContent] = useState('')
  const [result, setResult] = useState<DiscoveryResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  const runDiscovery = async (event: FormEvent) => {
    event.preventDefault(); setSubmitting(true); setError(null); setResult(null)
    const shared = { ...fields, service_name: fields.service_name || undefined }
    try {
      const response = source === 'openapi'
        ? await runOpenApiDiscovery({ ...shared, document: content })
        : source === 'git'
          ? await runGitDiscovery({ ...shared, repository_path: content })
          : await runRuntimeLogDiscovery({ ...shared, log_content: content })
      setResult(response); await onComplete()
    } catch (requestError) { setError(requestError instanceof Error ? requestError.message : 'Discovery request failed') }
    finally { setSubmitting(false) }
  }

  const label = source === 'openapi' ? 'OpenAPI JSON or YAML document' : source === 'git' ? 'Repository path below discovery-repositories/' : 'HTTP access log content'
  return <section>
    <p className="eyebrow">Ingestion</p><h1>Discovery</h1>
    <form className="discovery-form" onSubmit={runDiscovery}>
      <label>Source<select value={source} onChange={(event) => setSource(event.target.value as typeof source)}><option value="openapi">OpenAPI / Swagger</option><option value="git">Git source directory</option><option value="runtime-log">Runtime log</option></select></label>
      <div className="form-grid">
        {(['organization', 'service_name', 'host', 'version'] as const).map((name) => <label key={name}>{name.replace('_', ' ')}<input required={name !== 'service_name'} value={fields[name]} onChange={(event) => setFields({ ...fields, [name]: event.target.value })} /></label>)}
      </div>
      <label>{label}{source === 'git' ? <input required placeholder="my-service" value={content} onChange={(event) => setContent(event.target.value)} /> : <textarea required rows={10} value={content} onChange={(event) => setContent(event.target.value)} />}</label>
      <button className="submit" disabled={submitting}>{submitting ? 'Discovering…' : 'Run discovery'}</button>
    </form>
    {error && <p className="error" role="alert">{error}</p>}
    {result && <div className="result"><p><strong>{result.source}</strong>: {result.discovered_count} discovered, {result.added_count} added.</p><ul>{result.records.map((record) => <li key={record.id}><code>{record.http_method}</code> {record.endpoint_path} <small>({record.service_name})</small></li>)}</ul></div>}
  </section>
}
