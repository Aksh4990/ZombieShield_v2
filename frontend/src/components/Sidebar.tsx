export type Page = 'dashboard' | 'inventory' | 'discovery'

interface SidebarProps {
  page: Page
  onNavigate: (page: Page) => void
}

export function Sidebar({ page, onNavigate }: SidebarProps) {
  return (
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark">Z</span>ZombieShield</div>
      <nav aria-label="Primary navigation">
        <button className={page === 'dashboard' ? 'nav-link active' : 'nav-link'} onClick={() => onNavigate('dashboard')}>Dashboard</button>
        <button className={page === 'inventory' ? 'nav-link active' : 'nav-link'} onClick={() => onNavigate('inventory')}>API Inventory</button>
        <button className={page === 'discovery' ? 'nav-link active' : 'nav-link'} onClick={() => onNavigate('discovery')}>Discovery</button>
      </nav>
    </aside>
  )
}
