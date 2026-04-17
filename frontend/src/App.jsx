import { useState } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Dashboard from './components/Dashboard'
import Login from './pages/Login'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem('token'))

  const handleLogin = (newToken) => {
    setToken(newToken)
    // Reset React Query cache so stale unauthed data is cleared
    queryClient.clear()
  }

  const handleLogout = () => {
    localStorage.removeItem('token')
    setToken(null)
    queryClient.clear()
  }

  if (!token) {
    return <Login onLogin={handleLogin} />
  }

  return (
    <QueryClientProvider client={queryClient}>
      <Dashboard onLogout={handleLogout} />
    </QueryClientProvider>
  )
}
