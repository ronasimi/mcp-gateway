export const objectSchema = (description, properties = {}, required = []) => ({
  type: 'object',
  description,
  properties,
  required,
  additionalProperties: false,
});

export const stringSchema = (description, extra = {}) => ({ type: 'string', description, ...extra });
export const integerSchema = (description, minimum, maximum, extra = {}) => ({ type: 'integer', description, minimum, maximum, ...extra });
export const numberSchema = (description, extra = {}) => ({ type: 'number', description, ...extra });
export const booleanSchema = description => ({ type: 'boolean', description });
export const arraySchema = (description, items, extra = {}) => ({ type: 'array', description, items, ...extra });
export const openObjectSchema = description => ({ type: 'object', description, additionalProperties: true });

export const toolSchema = (name, description, properties = {}, required = []) => ({
  name,
  description,
  inputSchema: objectSchema(description, properties, required),
});
