export declare class AIndigoError extends Error {
    readonly code: string;
    readonly statusCode: number;
    readonly details?: unknown | undefined;
    constructor(code: string, message: string, statusCode?: number, details?: unknown | undefined);
}
export declare class BudgetExhaustedError extends AIndigoError {
    constructor(department: string, budget: number);
}
export declare class DlpViolationBlockedError extends AIndigoError {
    constructor(violations: string[]);
}
export declare class UnauthorizedVirtualKeyError extends AIndigoError {
    constructor();
}
//# sourceMappingURL=errors.d.ts.map