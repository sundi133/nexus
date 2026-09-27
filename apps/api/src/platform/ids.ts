import { uuidv7 } from "uuidv7";

/** Time-ordered identifiers: IDs double as stable, index-friendly pagination cursors. */
export const newId = (): string => uuidv7();
