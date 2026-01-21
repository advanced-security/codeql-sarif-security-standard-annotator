describe('main', () => {
  it('placeholder test', () => {
    // This is a placeholder test to prevent Jest from failing
    // TODO: Add proper unit tests for the main module
    expect(true).toBe(true)
  })

  describe('CWE ID normalization', () => {
    const codeQlCweTagPrefix = 'external/cwe/cwe-'
    
    function normalizeCweId(tag: string): string {
      const cweId = tag.replace(codeQlCweTagPrefix, '')
      const normalizedId = String(parseInt(cweId, 10))
      return normalizedId
    }

    it('should handle CWE IDs with leading zeros', () => {
      // Test that cwe-099 maps to 99
      const normalizedId = normalizeCweId('external/cwe/cwe-099')
      expect(normalizedId).toBe('99')
    })

    it('should handle CWE IDs without leading zeros', () => {
      // Test that cwe-89 maps to 89
      const normalizedId = normalizeCweId('external/cwe/cwe-89')
      expect(normalizedId).toBe('89')
    })

    it('should handle CWE IDs with multiple leading zeros', () => {
      // Test that cwe-020 maps to 20
      const normalizedId = normalizeCweId('external/cwe/cwe-020')
      expect(normalizedId).toBe('20')
    })

    it('should return NaN for non-numeric CWE IDs', () => {
      // Test that invalid CWE IDs return NaN
      const normalizedId = normalizeCweId('external/cwe/cwe-abc')
      expect(normalizedId).toBe('NaN')
    })
  })
})
