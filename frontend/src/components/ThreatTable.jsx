const PRIORITY_STYLES = {
  CRITICAL: 'bg-red-100 text-red-700 border border-red-300',
  HIGH: 'bg-orange-100 text-orange-700 border border-orange-300',
  MEDIUM: 'bg-yellow-100 text-yellow-700 border border-yellow-300',
  LOW: 'bg-green-100 text-green-700 border border-green-300',
}

function PriorityBadge({ level }) {
  if (!level) return <span className="text-gray-400 text-xs">—</span>
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${PRIORITY_STYLES[level] ?? 'bg-gray-100 text-gray-600'}`}>
      {level}
    </span>
  )
}

function SortIcon({ column, sortBy }) {
  if (sortBy !== column) return <span className="text-gray-300 ml-1">↕</span>
  return <span className="text-blue-600 ml-1">↓</span>
}

function SkeletonRow() {
  return (
    <tr>
      {Array(6).fill(0).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 bg-gray-200 rounded animate-pulse" />
        </td>
      ))}
    </tr>
  )
}

export default function ThreatTable({
  threats = [],
  total = 0,
  page = 1,
  limit = 20,
  onPageChange,
  sortBy,
  onSort,
  onSelectThreat,
  loading = false,
}) {
  const totalPages = Math.ceil(total / limit)

  const col = (label, key, align = 'left') => (
    <th
      className={`px-4 py-3 text-${align} text-xs font-semibold text-gray-500 uppercase tracking-wide cursor-pointer select-none hover:bg-gray-100`}
      onClick={() => onSort(key)}
    >
      {label}
      <SortIcon column={key} sortBy={sortBy} />
    </th>
  )

  return (
    <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              {col('CVE ID', 'cve')}
              {col('CVSS', 'cvss', 'right')}
              {col('EPSS', 'epss', 'right')}
              {col('Score', 'score', 'right')}
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">
                Priority
              </th>
              {col('Published', 'date')}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {loading
              ? Array(8).fill(0).map((_, i) => <SkeletonRow key={i} />)
              : threats.map((t) => (
                  <tr
                    key={t.cve_id}
                    className="hover:bg-blue-50 cursor-pointer transition-colors"
                    onClick={() => onSelectThreat(t.cve_id)}
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-mono text-blue-700 font-medium">
                          {t.cve_id}
                        </span>
                        {(t.in_cisa_kev || t.in_vulncheck_kev) && (
                          <span className="text-xs bg-red-600 text-white px-1 py-0.5 rounded font-bold">
                            KEV
                          </span>
                        )}
                      </div>
                      {t.description && (
                        <p className="text-xs text-gray-400 mt-0.5 truncate max-w-xs">
                          {t.description}
                        </p>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <span className={`text-sm font-semibold ${
                        t.cvss_score >= 9 ? 'text-red-600' :
                        t.cvss_score >= 7 ? 'text-orange-500' :
                        t.cvss_score >= 4 ? 'text-yellow-600' : 'text-green-600'
                      }`}>
                        {t.cvss_score?.toFixed(1) ?? '—'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right text-sm text-gray-600">
                      {t.epss_score != null ? (t.epss_score * 100).toFixed(1) + '%' : '—'}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {t.composite_score != null ? (
                        <span className="text-sm font-semibold text-gray-800">
                          {(t.composite_score * 100).toFixed(0)}
                        </span>
                      ) : (
                        <span className="text-xs text-gray-400">select env</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <PriorityBadge level={t.priority_level} />
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-500 whitespace-nowrap">
                      {t.published_date
                        ? new Date(t.published_date).toLocaleDateString('en-US', {
                            year: 'numeric', month: 'short', day: 'numeric',
                          })
                        : '—'}
                    </td>
                  </tr>
                ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="px-4 py-3 border-t border-gray-100 bg-gray-50">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          {/* Left: summary */}
          <div className="text-sm text-gray-500">
            {(() => {
              const from = total === 0 ? 0 : (page - 1) * limit + 1
              const to = Math.min(page * limit, total)
              return `Showing ${from.toLocaleString()}–${to.toLocaleString()} of ${total.toLocaleString()} threats`
            })()}
            <span className="text-gray-400 ml-2">· page {page} of {totalPages || 1}</span>
          </div>

          {/* Right: page buttons */}
          {totalPages > 1 && (
            <div className="flex items-center gap-1">
              {/* << First */}
              <button
                onClick={() => onPageChange(1)}
                disabled={page <= 1}
                className="px-2 py-1 text-sm border border-gray-300 rounded bg-white hover:bg-gray-100 disabled:opacity-40 disabled:cursor-not-allowed"
                title="First page"
              >
                «
              </button>
              {/* < Prev */}
              <button
                onClick={() => onPageChange(page - 1)}
                disabled={page <= 1}
                className="px-2 py-1 text-sm border border-gray-300 rounded bg-white hover:bg-gray-100 disabled:opacity-40 disabled:cursor-not-allowed"
                title="Previous page"
              >
                ‹
              </button>

              {/* Page number buttons — up to 5, centred around current page */}
              {(() => {
                const half = 2
                let start = Math.max(1, page - half)
                let end = Math.min(totalPages, start + 4)
                // Shift start left if we hit the right edge
                start = Math.max(1, end - 4)
                return Array.from({ length: end - start + 1 }, (_, i) => start + i).map((p) => (
                  <button
                    key={p}
                    onClick={() => onPageChange(p)}
                    className={`min-w-[2rem] px-2 py-1 text-sm border rounded ${
                      p === page
                        ? 'bg-blue-600 border-blue-600 text-white font-semibold'
                        : 'border-gray-300 bg-white hover:bg-gray-100 text-gray-700'
                    }`}
                  >
                    {p}
                  </button>
                ))
              })()}

              {/* > Next */}
              <button
                onClick={() => onPageChange(page + 1)}
                disabled={page >= totalPages}
                className="px-2 py-1 text-sm border border-gray-300 rounded bg-white hover:bg-gray-100 disabled:opacity-40 disabled:cursor-not-allowed"
                title="Next page"
              >
                ›
              </button>
              {/* >> Last */}
              <button
                onClick={() => onPageChange(totalPages)}
                disabled={page >= totalPages}
                className="px-2 py-1 text-sm border border-gray-300 rounded bg-white hover:bg-gray-100 disabled:opacity-40 disabled:cursor-not-allowed"
                title="Last page"
              >
                »
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
