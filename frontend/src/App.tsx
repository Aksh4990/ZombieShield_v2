import { useEffect, useState } from 'react'
import { getApis, getHealth } from './api'
import { Sidebar, type Page } from './components/Sidebar'
import { Dashboard } from './pages/Dashboard'
import { ApiInventory } from './pages/ApiInventory'
import { Discovery } from './pages/Discovery'
import type { ApiInventoryItem } from './types'

export default function App() {
  const [page, setPage] = useState<Page>('dashboard')
  const [apis, setApis] = useState<ApiInventoryItem[]>([])
  const [health, setHealth] = useState('checking')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const refresh = async () => {
    Promise.all([getHealth(), getApis()])
      .then(([healthResponse, apiResponse]) => { setHealth(healthResponse.status); setApis(apiResponse) })
      .catch((requestError: Error) => { setHealth('unavailable'); setError(requestError.message) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { void refresh() }, [])

  return <div className="app-shell"><Sidebar page={page} onNavigate={setPage} /><main>{page === 'dashboard' ? <Dashboard health={health} apis={apis} error={error} /> : page === 'inventory' ? <ApiInventory apis={apis} loading={loading} error={error} /> : <Discovery onComplete={refresh} />}</main></div>
}
