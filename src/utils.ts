/* eslint-disable no-console */
import {env} from 'process'
import * as core from '@actions/core'

export enum LogLevel {
  Info = 'Info',
  Warn = 'Warn',
  Error = 'Error'
}

export function log(message: string, level = LogLevel.Info): void {
  if (env.GITHUB_ACTIONS === 'true') {
    switch (level) {
      case LogLevel.Info: {
        core.info(message)
        break
      }
      case LogLevel.Warn: {
        core.warning(message)
        break
      }
      case LogLevel.Error: {
        core.error(message)
        break
      }
    }
  } else {
    switch (level) {
      case LogLevel.Info: {
        console.info(message)
        break
      }
      case LogLevel.Warn: {
        console.warn(message)
        break
      }
      case LogLevel.Error: {
        console.error(message)
        break
      }
    }
  }
}

/**
 * Normalize a CWE ID by removing leading zeros
 * @param cweId - The CWE ID string (e.g., "099", "020", "89")
 * @returns The normalized CWE ID string (e.g., "99", "20", "89") or null if invalid
 */
export function normalizeCweId(cweId: string): string | null {
  const parsedCweId = parseInt(cweId, 10)
  if (Number.isNaN(parsedCweId)) {
    return null
  }
  return String(parsedCweId)
}
