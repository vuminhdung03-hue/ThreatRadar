export default function Filters({ filters, onFilterChange, environments = [] }) {
  const set = (key, value) => onFilterChange({ ...filters, [key]: value })

  return (
    <div className="bg-white border border-gray-200 rounded-lg p-4">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Environment switcher — most prominent */}
        <div className="sm:col-span-2 lg:col-span-1">
          <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">
            Environment
          </label>
          <select
            className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={filters.environment_id ?? ''}
            onChange={(e) =>
              set('environment_id', e.target.value ? Number(e.target.value) : null)
            }
          >
            <option value="">All (no scoring)</option>
            {environments.map((env) => (
              <option key={env.id} value={env.id}>
                {env.name}
              </option>
            ))}
          </select>
        </div>

        {/* Min CVSS */}
        <div>
          <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">
            Min CVSS: <span className="text-blue-600">{filters.min_cvss ?? 0}</span>
          </label>
          <input
            type="range"
            min="0"
            max="10"
            step="0.5"
            className="w-full accent-blue-600"
            value={filters.min_cvss ?? 0}
            onChange={(e) => set('min_cvss', Number(e.target.value))}
          />
          <div className="flex justify-between text-xs text-gray-400 mt-0.5">
            <span>0</span><span>10</span>
          </div>
        </div>

        {/* Priority filter */}
        <div>
          <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">
            Priority
          </label>
          <select
            className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={filters.priority_level ?? ''}
            onChange={(e) => set('priority_level', e.target.value || null)}
          >
            <option value="">All</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
        </div>

        {/* KEV toggle */}
        <div className="flex flex-col justify-center">
          <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
            KEV Only
          </label>
          <button
            onClick={() => set('kev_only', !filters.kev_only)}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 ${
              filters.kev_only ? 'bg-red-600' : 'bg-gray-300'
            }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
                filters.kev_only ? 'translate-x-6' : 'translate-x-1'
              }`}
            />
          </button>
          {filters.kev_only && (
            <span className="text-xs text-red-600 mt-1">CISA/VulnCheck KEV</span>
          )}
        </div>
      </div>
    </div>
  )
}
