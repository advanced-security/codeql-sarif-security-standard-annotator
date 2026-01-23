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

    it('should return null for empty strings', () => {
      // Test that empty strings return null
      const normalizedId = normalizeCweId('')
      expect(normalizedId).toBeNull()
    })

    it('should return null for strings with only spaces', () => {
      // Test that strings with only spaces return null
      const normalizedId = normalizeCweId('   ')
      expect(normalizedId).toBeNull()
    })

    it('should handle strings with leading/trailing spaces', () => {
      // Test that strings with spaces are parsed correctly
      const normalizedId = normalizeCweId('  99  ')
      expect(normalizedId).toBe('99')
    })

    it('should return null for negative numbers', () => {
      // Test that negative numbers return null (CWE IDs should be positive)
      const normalizedId = normalizeCweId('-99')
      expect(normalizedId).toBeNull()
    })

    it('should handle strings with mixed alphanumeric characters (parseInt is lenient)', () => {
      // Test that mixed alphanumeric strings are parsed leniently
      // parseInt stops at first non-numeric character, so '99abc' becomes 99
      // This is acceptable for our use case as malformed tags would be rare
      const normalizedId = normalizeCweId('99abc')
      expect(normalizedId).toBe('99')
    })

    it('should handle zero', () => {
      // Test that zero is handled correctly
      const normalizedId = normalizeCweId('0')
      expect(normalizedId).toBe('0')
    })

    it('should handle zero with leading zeros', () => {
      // Test that zero with leading zeros is handled correctly
      const normalizedId = normalizeCweId('000')
      expect(normalizedId).toBe('0')
    })
  })
})
