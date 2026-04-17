import { useState, useEffect } from 'react'
import {
  useDashboardStats,
  useDashboardTrends,
  useEnvironments,
  useThreats,
} from '../hooks/useThreats'
import api from '../services/api'
import Filters from './Filters'
import ThreatTable from './ThreatTable'
import ThreatDetail from './ThreatDetail'
import SeverityChart from './Charts/SeverityChart'
import TrendChart from './Charts/TrendChart'

function StatCard({ label, value, sub, color = 'text-gray-900' }) {
  return (
    <div className="bg-white border border-gray-200 rounded-lg p-4">
      <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">{label}</p>
      <p className={`text-3xl font-bold mt-1 ${color}`}>{value ?? '—'}</p>
      {sub && <p className="text-xs text-gray-400 mt-0.5">{sub}</p>}
    </div>
  )
}

const DEFAULT_FILTERS = {
  environment_id: null,
  min_cvss: 0,
  kev_only: false,
  priority_level: null,
}

export default function Dashboard({ onLogout }) {
  const [filters, setFilters] = useState(DEFAULT_FILTERS)
  const [sortBy, setSortBy] = useState('cvss')
  const [page, setPage] = useState(1)
  const [selectedCveId, setSelectedCveId] = useState(null)
  const [currentUser, setCurrentUser] = useState(null)
  const LIMIT = 20

  useEffect(() => {
    api.get('/api/v1/auth/me').then((r) => setCurrentUser(r.data)).catch(() => {})
  }, [])

  // Reset to page 1 when filters or sort changes
  const handleFilterChange = (next) => {
    setFilters(next)
    setPage(1)
  }
  const handleSort = (col) => {
    setSortBy(col)
    setPage(1)
  }

  // Build query params for threats endpoint
  const threatParams = {
    page,
    limit: LIMIT,
    sort_by: sortBy,
    ...(filters.environment_id && { environment_id: filters.environment_id }),
    ...(filters.min_cvss > 0 && { min_cvss: filters.min_cvss }),
    ...(filters.kev_only && { kev_only: true }),
    ...(filters.priority_level && { priority_level: filters.priority_level }),
  }

  const { data: environments = [] } = useEnvironments()
  const { data: threats, isLoading: threatsLoading, isError: threatsError } = useThreats(threatParams)
  const { data: stats } = useDashboardStats(filters.environment_id)
  const { data: trends } = useDashboardTrends(36)

  const criticalCount = stats?.by_priority?.CRITICAL ?? 0

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Nav */}
      <nav className="bg-gray-900 text-white px-6 py-3 flex items-center gap-3 shadow">
        <div className="w-7 h-7 bg-red-600 rounded flex items-center justify-center text-sm font-bold">
          T
        </div>
        <span className="text-lg font-bold tracking-tight">ThreatRadar</span>
        <span className="text-gray-500 text-sm ml-1 hidden sm:inline">· CVE Intelligence Dashboard</span>
        <div className="ml-auto flex items-center gap-3">
          {currentUser && (
            <div className="text-right hidden sm:block">
              <p className="text-sm text-gray-200 leading-none">{currentUser.email}</p>
              <p className="text-xs text-gray-500 mt-0.5 capitalize">{currentUser.role}</p>
            </div>
          )}
          <button
            onClick={onLogout}
            className="text-xs bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded transition-colors"
          >
            Sign out
          </button>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">
        {/* Stat cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            label="Total Threats"
            value={stats?.total_threats?.toLocaleString()}
          />
          <StatCard
            label="Critical"
            value={criticalCount.toLocaleString()}
            color="text-red-600"
          />
          <StatCard
            label="KEV"
            value={stats?.kev_count?.toLocaleString()}
            sub="Actively exploited"
            color="text-orange-600"
          />
          <StatCard
            label="Avg CVSS"
            value={stats?.avg_cvss}
            sub={`Avg EPSS ${((stats?.avg_epss ?? 0) * 100).toFixed(1)}%`}
          />
        </div>

        {/* Charts row */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-white border border-gray-200 rounded-lg p-4">
            <h2 className="text-sm font-semibold text-gray-700 mb-3">
              Threats by Priority
              {filters.environment_id && (
                <span className="text-xs text-blue-600 ml-2 font-normal">
                  ({environments.find((e) => e.id === filters.environment_id)?.name})
                </span>
              )}
            </h2>
            <SeverityChart byPriority={stats?.by_priority ?? {}} />
          </div>
          <div className="bg-white border border-gray-200 rounded-lg p-4">
            <h2 className="text-sm font-semibold text-gray-700 mb-3">
              CVEs Published (Last 12 Months)
            </h2>
            <TrendChart data={trends?.data ?? []} />
          </div>
        </div>

        {/* Filters */}
        <Filters
          filters={filters}
          onFilterChange={handleFilterChange}
          environments={environments}
        />

        {/* Environment context banner */}
        {filters.environment_id && (
          <div className="bg-blue-50 border border-blue-200 rounded-lg px-4 py-2 flex items-center gap-2">
            <span className="text-blue-600 text-sm">
              Threats ranked by composite score for{' '}
              <strong>
                {environments.find((e) => e.id === filters.environment_id)?.name}
              </strong>
            </span>
          </div>
        )}

        {/* Error state */}
        {threatsError && (
          <div className="bg-red-50 border border-red-200 rounded-lg px-4 py-3 text-red-700 text-sm">
            Failed to load threats. Is the backend running at localhost:8000?
          </div>
        )}

        {/* Threat table */}
        <ThreatTable
          threats={threats?.items ?? []}
          total={threats?.total ?? 0}
          page={page}
          limit={LIMIT}
          onPageChange={setPage}
          sortBy={sortBy}
          onSort={handleSort}
          onSelectThreat={setSelectedCveId}
          loading={threatsLoading}
        />
      </main>

      {/* Detail modal */}
      {selectedCveId && (
        <ThreatDetail
          cveId={selectedCveId}
          envId={filters.environment_id}
          onClose={() => setSelectedCveId(null)}
        />
      )}
    </div>
  )
}
