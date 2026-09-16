import type { RegistryStaticPage } from './navigation.ts'

/** Outline meanings shared by the Registry shell and empty states. */
export type RegistryIconName = RegistryStaticPage | 'brand' | 'info' | 'emptyNodes'
  | 'environment' | 'warning' | 'arrowRight' | 'email' | 'lock' | 'eye' | 'eyeOff' | 'documentation'

const paths: Record<RegistryIconName, string> = {
  overview: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
  members: 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M16 3a4 4 0 0 1 0 8M22 21v-2a4 4 0 0 0-3-3.87M13 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0',
  nodes: 'M21 5c0 2.2-4 4-9 4S3 7.2 3 5s4-4 9-4 9 1.8 9 4ZM3 5v14c0 2.2 4 4 9 4s9-1.8 9-4V5M3 12c0 2.2 4 4 9 4s9-1.8 9-4',
  emptyNodes: 'M2 1h20a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1ZM2 8h20a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1ZM2 15h20a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1v-4a1 1 0 0 1 1-1ZM4 4h4M4 11h4M4 18h4M20 4a.7.7 0 1 1-1.4 0 .7.7 0 0 1 1.4 0M20 11a.7.7 0 1 1-1.4 0 .7.7 0 0 1 1.4 0M20 18a.7.7 0 1 1-1.4 0 .7.7 0 0 1 1.4 0M12 21v2M8 23h8',
  disclosures: 'M4 3h14a2 2 0 0 1 2 2v16l-5-4H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2ZM6 7h10M6 11h6',
  branches: 'M4 3h5v5H4zM16 3h5v5h-5zM16 16h5v5h-5zM6.5 8v7a3.5 3.5 0 0 0 3.5 3.5h6M9 5.5h7',
  audit: 'M12 2l9 4v6c0 5-9 10-9 10S3 17 3 12V6ZM8 12l3 3 5-6',
  settings: 'M10 2h4l1 3 3 1 3-1 2 4-2 2v3l2 2-2 4-3-1-3 1-1 3h-4l-1-3-3-1-3 1-2-4 2-2v-3l-2-2 2-4 3 1 3-1ZM16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0',
  signIn: 'M14 3h6v18h-6M3 12h12M10 7l5 5-5 5',
  signUp: 'M15 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M8.5 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM19 8v6M16 11h6',
  newOrganization: 'M3 21V7l9-5 9 5v14M9 21v-6h6v6M7 9h2M15 9h2M7 13h2M15 13h2',
  binding: 'M5 3h14v13H5zM9 21h6M12 16v5M9 9l2 2 4-4',
  notFound: 'M9 9l6 6M15 9l-6 6M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0',
  brand: 'M12 5v4M12 15v4M5 12h4M15 12h4M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0M14 3a2 2 0 1 1-4 0 2 2 0 0 1 4 0M14 21a2 2 0 1 1-4 0 2 2 0 0 1 4 0M5 12a2 2 0 1 1-4 0 2 2 0 0 1 4 0M23 12a2 2 0 1 1-4 0 2 2 0 0 1 4 0',
  info: 'M12 11v6M12 7h.01M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0',
  environment: 'M4 5h16v6H4zM4 13h16v6H4zM7 8h.01M7 16h.01M11 8h6M11 16h6',
  warning: 'M10.3 3.7 2.2 18a2 2 0 0 0 1.8 3h16a2 2 0 0 0 1.8-3L13.7 3.7a2 2 0 0 0-3.4 0ZM12 9v4M12 17h.01',
  arrowRight: 'M5 12h14M13 6l6 6-6 6',
  email: 'M3 5h18v14H3zM3 6l9 7 9-7',
  lock: 'M5 11h14v10H5zM8 11V8a4 4 0 0 1 8 0v3M12 15v2',
  eye: 'M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12ZM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6',
  eyeOff: 'M3 3l18 18M10.6 6.2A11 11 0 0 1 12 6c6.5 0 10 6 10 6a17 17 0 0 1-2.1 2.8M6.2 6.2C3.5 8 2 12 2 12s3.5 6 10 6a11 11 0 0 0 3.3-.5M10.7 10.7a2 2 0 0 0 2.6 2.6',
  documentation: 'M4 4.5A2.5 2.5 0 0 1 6.5 2H11v18H6.5A2.5 2.5 0 0 0 4 22ZM20 4.5A2.5 2.5 0 0 0 17.5 2H13v18h4.5A2.5 2.5 0 0 1 20 22Z',
}

/** Render an inert, consistently stroked icon; nearby localized text owns its meaning. */
export function RegistryIcon({ name, size = 20 }: { name: RegistryIconName; size?: number }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name]} /></svg>
}
