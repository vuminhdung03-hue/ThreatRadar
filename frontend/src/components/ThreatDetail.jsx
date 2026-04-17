import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getThreat } from '../services/api'

const PRIORITY_STYLES = {
  CRITICAL: 'bg-red-100 text-red-700',
  HIGH: 'bg-orange-100 text-orange-700',
  MEDIUM: 'bg-yellow-100 text-yellow-700',
  LOW: 'bg-green-100 text-green-700',
}

function ScoreRow({ label, value, pct = false }) {
  if (value == null) return null
  const display = pct ? (value * 100).toFixed(1) + '%' : value.toFixed(4)
  return (
    <tr className="border-b border-gray-100 last:border-0">
      <td className="py-1.5 text-sm text-gray-600">{label}</td>
      <td className="py-1.5 text-sm font-mono text-right text-gray-800">{display}</td>
    </tr>
  )
}

export default function ThreatDetail({ cveId, envId, onClose }) {
  const { data: threat, isLoading, isError } = useQuery({
    queryKey: ['threat-detail', cveId, envId],
    queryFn: () => getThreat(cveId, envId),
    enabled: !!cveId,
  })

  // Close on Escape
  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50"
      onClick={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-start justify-between p-5 border-b border-gray-100">
          <div>
            <h2 className="text-lg font-bold font-mono text-gray-900">{cveId}</h2>
            {threat?.priority_level && (
              <span className={`text-xs font-semibold px-2 py-0.5 rounded mt-1 inline-block ${PRIORITY_STYLES[threat.priority_level] ?? ''}`}>
                {threat.priority_level}
              </span>
            )}
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 text-2xl leading-none ml-4"
          >
            ×
          </button>
        </div>

        {/* Body */}
        <div className="overflow-y-auto p-5 space-y-5">
          {isLoading && (
            <div className="space-y-3">
              {Array(4).fill(0).map((_, i) => (
                <div key={i} className="h-4 bg-gray-200 rounded animate-pulse" />
              ))}
            </div>
          )}

          {isError && (
            <p className="text-red-600 text-sm">Failed to load CVE details.</p>
          )}

          {threat && (
            <>
              {/* Key metrics */}
              <div className="grid grid-cols-3 gap-3">
                <div className="bg-gray-50 rounded-lg p-3 text-center">
                  <div className={`text-2xl font-bold ${
                    threat.cvss_score >= 9 ? 'text-red-600' :
                    threat.cvss_score >= 7 ? 'text-orange-500' :
                    threat.cvss_score >= 4 ? 'text-yellow-600' : 'text-green-600'
                  }`}>
                    {threat.cvss_score?.toFixed(1) ?? '—'}
                  </div>
                  <div className="text-xs text-gray-500 mt-0.5">CVSS Score</div>
                </div>
                <div className="bg-gray-50 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-blue-600">
                    {threat.epss_score != null
                      ? (threat.epss_score * 100).toFixed(1) + '%'
                      : '—'}
                  </div>
                  <div className="text-xs text-gray-500 mt-0.5">EPSS Probability</div>
                </div>
                <div className="bg-gray-50 rounded-lg p-3 text-center">
                  {threat.composite_score != null ? (
                    <>
                      <div className="text-2xl font-bold text-purple-600">
                        {(threat.composite_score * 100).toFixed(0)}
                      </div>
                      <div className="text-xs text-gray-500 mt-0.5">Composite Score</div>
                    </>
                  ) : (
                    <>
                      <div className="text-lg font-bold text-gray-400">—</div>
                      <div className="text-xs text-gray-400 mt-0.5">Select env for score</div>
                    </>
                  )}
                </div>
              </div>

              {/* KEV flags */}
              {(threat.in_cisa_kev || threat.in_vulncheck_kev) && (
                <div className="flex gap-2 flex-wrap">
                  {threat.in_cisa_kev && (
                    <span className="text-xs bg-red-600 text-white px-2 py-1 rounded font-semibold">
                      CISA KEV — Actively Exploited
                    </span>
                  )}
                  {threat.in_vulncheck_kev && (
                    <span className="text-xs bg-orange-600 text-white px-2 py-1 rounded font-semibold">
                      VulnCheck KEV
                    </span>
                  )}
                </div>
              )}

              {/* Description */}
              {threat.description && (
                <div>
                  <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">
                    Description
                  </h3>
                  <p className="text-sm text-gray-700 leading-relaxed">{threat.description}</p>
                </div>
              )}

              {/* Score breakdown */}
              {threat.score_breakdown && (
                <div>
                  <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
                    Score Breakdown
                  </h3>
                  <table className="w-full">
                    <tbody>
                      <ScoreRow label="CVSS Contribution (×0.35)" value={threat.score_breakdown.cvss_contribution} />
                      <ScoreRow label="EPSS Contribution (×0.35)" value={threat.score_breakdown.epss_contribution} />
                      <ScoreRow label="KEV Bonus (×0.20)" value={threat.score_breakdown.kev_multiplier != null ? threat.score_breakdown.kev_multiplier - 1.0 : null} />
                      <ScoreRow label="Recency (×0.10)" value={threat.score_breakdown.recency_contribution} />
                      <ScoreRow label="Tech Match Multiplier" value={threat.score_breakdown.kev_multiplier} />
                      <tr className="border-t-2 border-gray-300">
                        <td className="py-1.5 text-sm font-semibold text-gray-800">Base Score</td>
                        <td className="py-1.5 text-sm font-mono font-bold text-right text-gray-800">
                          {threat.score_breakdown.base_score?.toFixed(4)}
                        </td>
                      </tr>
                      <tr>
                        <td className="py-1.5 text-sm font-semibold text-purple-700">Final Score</td>
                        <td className="py-1.5 text-sm font-mono font-bold text-right text-purple-700">
                          {threat.score_breakdown.final_score?.toFixed(4)}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              )}

              {/* CVSS Vector */}
              {threat.cvss_vector && (
                <div>
                  <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">
                    CVSS Vector
                  </h3>
                  <code className="text-xs bg-gray-100 px-2 py-1 rounded font-mono text-gray-700 break-all">
                    {threat.cvss_vector}
                  </code>
                </div>
              )}

              {/* Affected Products */}
              {threat.affected_products?.length > 0 && (
                <div>
                  <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
                    Affected Products
                  </h3>
                  <div className="flex flex-wrap gap-1.5">
                    {threat.affected_products.map((p) => (
                      <span key={p} className="text-xs bg-gray-100 text-gray-700 px-2 py-0.5 rounded font-mono">
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Published */}
              {threat.published_date && (
                <p className="text-xs text-gray-400">
                  Published:{' '}
                  {new Date(threat.published_date).toLocaleDateString('en-US', {
                    year: 'numeric', month: 'long', day: 'numeric',
                  })}
                </p>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
