import type { ApiInventoryItem, DiscoveryResponse, ModelEvaluationResponse, RemediationResponse, RiskAssessmentRunResponse } from './types'

const baseUrl = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'

async function request<T>(path: string): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`)
  if (!response.ok) {
    throw new Error(`Request failed with status ${response.status}`)
  }
  return response.json() as Promise<T>
}

async function post<T>(path: string, body: object): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  })
  if (!response.ok) {
    const detail = await response.json().catch(() => null) as { detail?: string } | null
    throw new Error(detail?.detail ?? `Request failed with status ${response.status}`)
  }
  return response.json() as Promise<T>
}

export const getHealth = () => request<{ status: string }>('/health')
export const getApis = () => request<ApiInventoryItem[]>('/apis')
export const runOpenApiDiscovery = (body: object) => post<DiscoveryResponse>('/discovery/openapi', body)
export const runGitDiscovery = (body: object) => post<DiscoveryResponse>('/discovery/git', body)
export const runRuntimeLogDiscovery = (body: object) => post<DiscoveryResponse>('/discovery/runtime-log', body)
export const runClassification = () => post<{ active: number; deprecated: number; zombie: number; decommissioned: number }>('/classification/run', {})
export const runRiskAssessments = () => post<RiskAssessmentRunResponse>('/risk/assessments/run', {})
export const getModelEvaluation = () => request<ModelEvaluationResponse>('/risk/models/evaluate')
export const getApiRecommendations = (apiId: string) => request<RemediationResponse>(`/apis/${apiId}/recommendations`)
