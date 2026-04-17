import { useQuery } from '@tanstack/react-query'
import {
  getDashboardStats,
  getDashboardTrends,
  getEnvironments,
  getThreats,
} from '../services/api'

export function useEnvironments() {
  return useQuery({
    queryKey: ['environments'],
    queryFn: getEnvironments,
    staleTime: 10 * 60 * 1000,
  })
}

export function useThreats(params) {
  return useQuery({
    queryKey: ['threats', params],
    queryFn: () => getThreats(params),
    keepPreviousData: true,
  })
}

export function useDashboardStats(envId) {
  return useQuery({
    queryKey: ['dashboard-stats', envId],
    queryFn: () => getDashboardStats(envId),
  })
}

export function useDashboardTrends(months = 12) {
  return useQuery({
    queryKey: ['dashboard-trends', months],
    queryFn: () => getDashboardTrends(months),
    staleTime: 30 * 60 * 1000,
  })
}
