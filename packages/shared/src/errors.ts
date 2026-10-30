export class AIndigoError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly statusCode: number = 500,
    public readonly details?: unknown
  ) {
    super(message);
    this.name = 'AIndigoError';
  }
}

export class BudgetExhaustedError extends AIndigoError {
  constructor(department: string, budget: number) {
    super(
      'BUDGET_EXHAUSTED',
      `Monthly budget cap of $${budget.toFixed(2)} reached for department [${department}].`,
      429
    );
  }
}

export class DlpViolationBlockedError extends AIndigoError {
  constructor(violations: string[]) {
    super(
      'DLP_PROMPT_BLOCKED',
      `Prompt rejected: Contains prohibited enterprise secrets/PII: ${violations.join(', ')}`,
      400,
      { violations }
    );
  }
}

export class UnauthorizedVirtualKeyError extends AIndigoError {
  constructor() {
    super('INVALID_VIRTUAL_KEY', 'Invalid, revoked, or malformed AIndigo Virtual Key.', 401);
  }
}
