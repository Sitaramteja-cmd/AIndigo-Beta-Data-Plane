export class AIndigoError extends Error {
    code;
    statusCode;
    details;
    constructor(code, message, statusCode = 500, details) {
        super(message);
        this.code = code;
        this.statusCode = statusCode;
        this.details = details;
        this.name = 'AIndigoError';
    }
}
export class BudgetExhaustedError extends AIndigoError {
    constructor(department, budget) {
        super('BUDGET_EXHAUSTED', `Monthly budget cap of $${budget.toFixed(2)} reached for department [${department}].`, 429);
    }
}
export class DlpViolationBlockedError extends AIndigoError {
    constructor(violations) {
        super('DLP_PROMPT_BLOCKED', `Prompt rejected: Contains prohibited enterprise secrets/PII: ${violations.join(', ')}`, 400, { violations });
    }
}
export class UnauthorizedVirtualKeyError extends AIndigoError {
    constructor() {
        super('INVALID_VIRTUAL_KEY', 'Invalid, revoked, or malformed AIndigo Virtual Key.', 401);
    }
}
//# sourceMappingURL=errors.js.map