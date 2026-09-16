import z from '@deepseek-ai/schemastery'

/** Explicit Registry browser presentation flags safe to publish in the boot manifest. */
export interface Config {
  /** Show the non-production identity warning for an intentionally composed local test runtime. */
  readonly localTestIdentityBanner: boolean
  /** Initial visual preference for a fresh standalone Registry browser runtime. */
  readonly defaultTheme: 'system' | 'light' | 'dark'
}

/** Local test identity labeling is opt-in and absent from ordinary Registry clients. */
export const Config: z<Partial<Config>, Config> = z.object({
  localTestIdentityBanner: z.boolean().default(false),
  defaultTheme: z.union(['system', 'light', 'dark']).default('system'),
})
