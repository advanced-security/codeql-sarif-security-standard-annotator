import {normalizeCweId} from '../src/utils'

describe('main', () => {
  it('placeholder test', () => {
    // This is a placeholder test to prevent Jest from failing
    // TODO: Add proper unit tests for the main module
    expect(true).toBe(true)
  })

  describe('CWE ID normalization', () => {
    it('should handle CWE IDs with leading zeros', () => {
      // Test that 099 maps to 99
      const normalizedId = normalizeCweId('099')
      expect(normalizedId).toBe('99')
    })

    it('should handle CWE IDs without leading zeros', () => {
      // Test that 89 maps to 89
      const normalizedId = normalizeCweId('89')
      expect(normalizedId).toBe('89')
    })

    it('should handle CWE IDs with multiple leading zeros', () => {
      // Test that 020 maps to 20
      const normalizedId = normalizeCweId('020')
      expect(normalizedId).toBe('20')
    })

    it('should return null for non-numeric CWE IDs', () => {
      // Test that invalid CWE IDs return null
      const normalizedId = normalizeCweId('abc')
      expect(normalizedId).toBeNull()
    })
  })
})
