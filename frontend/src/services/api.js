import axios from 'axios'

const api = axios.create({
  baseURL: 'http://localhost:8000',
  timeout: 15000,
})

// Attach JWT to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// On 401, clear token and redirect to login
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      // Only redirect if this wasn't the login request itself
      if (!err.config.url.includes('/auth/login')) {
        localStorage.removeItem('token')
        window.location.href = '/'
      }
    }
    return Promise.reject(err)
  }
)

export const getThreats = (params) =>
  api.get('/api/v1/threats', { params }).then((r) => r.data)

export const getThreat = (cveId, envId) =>
  api
    .get(`/api/v1/threats/${cveId}`, { params: envId ? { environment_id: envId } : {} })
    .then((r) => r.data)

export const getEnvironments = () =>
  api.get('/api/v1/environments').then((r) => r.data)

export const getDashboardStats = (envId) =>
  api
    .get('/api/v1/dashboard/stats', { params: envId ? { environment_id: envId } : {} })
    .then((r) => r.data)

export const getDashboardTrends = (months = 12) =>
  api.get('/api/v1/dashboard/trends', { params: { months } }).then((r) => r.data)

export default api
