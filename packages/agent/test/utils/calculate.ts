import { type Static, Type } from "@sinclair/typebox";
import type { AgentTool, AgentToolResult } from "../../src/types.js";

export interface CalculateResult extends AgentToolResult<undefined> {
	content: Array<{ type: "text"; text: string }>;
	details: undefined;
}

export function calculate(expression: string): CalculateResult {
	try {
		// Validate that expression only contains safe math characters
		if (!/^[\d\s+\-*/().,%^]+$/.test(expression)) {
			throw new Error(`Invalid characters in expression: ${expression}`);
		}
		const result = new Function(`"use strict"; return (${expression})`)();
		return { content: [{ type: "text", text: `${expression} = ${result}` }], details: undefined };
	} catch (e: any) {
		throw new Error(e.message || String(e));
	}
}

const calculateSchema = Type.Object({
	expression: Type.String({ description: "The mathematical expression to evaluate" }),
});

type CalculateParams = Static<typeof calculateSchema>;

export const calculateTool: AgentTool<typeof calculateSchema, undefined> = {
	label: "Calculator",
	name: "calculate",
	description: "Evaluate mathematical expressions",
	parameters: calculateSchema,
	execute: async (_toolCallId: string, args: CalculateParams) => {
		return calculate(args.expression);
	},
};
