import fs from 'node:fs';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';

const read = name => JSON.parse(fs.readFileSync(new URL(`../contracts/${name}.json`, import.meta.url), 'utf8'));
const migrations = read('migration-map');
const ajv = new Ajv({allErrors:true, strict:false, coerceTypes:false, useDefaults:false, removeAdditional:false, validateFormats:true});
addFormats(ajv);

/** Publish canonical contracts while keeping execution and policy in domain handlers. */
export function adaptToolContracts(domain, legacyTools, legacyCall, legacyValidate) {
  const published = read(`${domain}-tools`);
  const entries = migrations.filter(item => item.server === domain);
  const byOld = new Map(entries.map(item => [item.old_name, item]));
  const byNew = new Map(entries.map(item => [item.new_name, item]));
  const originals = new Map(legacyTools.map(tool => [tool.name, tool]));
  if (byOld.size !== entries.length || byNew.size !== entries.length || originals.size !== legacyTools.length)
    throw new Error(`Duplicate tool contract or handler: ${domain}`);
  for (const tool of published) {
    if (!byNew.has(tool.name)) throw new Error(`Contract has no migration: ${domain}.${tool.name}`);
  }
  if (published.length !== entries.length) throw new Error(`Contract/migration count mismatch: ${domain}`);
  for (const item of entries) {
    if (!originals.has(item.old_name)) throw new Error(`Contract has no handler: ${domain}.${item.old_name}`);
  }
  const tools = [...published, ...legacyTools.filter(tool => !byOld.has(tool.name))];
  const validators = new Map(tools.map(tool => [tool.name, ajv.compile(tool.inputSchema)]));
  const toolNames = new Set(tools.map(tool => tool.name));

  function canonicalize(name, args) {
    // Only old names are aliases. New names always use the published parameters.
    const entry = byOld.get(name);
    if (!entry || entry.new_name === name) return {name,args};
    if (args === null || typeof args !== 'object' || Array.isArray(args)) return {name:entry.new_name,args};
    const normalized = {...args};
    for (const [oldKey,newKey] of Object.entries(entry.parameter_renames)) {
      if (!Object.hasOwn(normalized,oldKey)) continue;
      if (Object.hasOwn(normalized,newKey)) throw new Error(`arguments/${newKey}: do not supply both old and new parameters`);
      let value = normalized[oldKey];
      if (entry.value_transforms?.[newKey]?.operation === 'json_stringify') {
        try { value = JSON.parse(value); } catch { throw new Error(`arguments/${oldKey}: expected encoded JSON object`); }
      }
      normalized[newKey] = value;
      delete normalized[oldKey];
    }
    return {name:entry.new_name,args:normalized};
  }

  function toLegacy(name,args) {
    const entry = byNew.get(name);
    if (!entry) return {name,args};
    const translated = {...args};
    for (const [oldKey,newKey] of Object.entries(entry.parameter_renames)) {
      if (!Object.hasOwn(translated,newKey)) continue;
      translated[oldKey] = entry.value_transforms?.[newKey]?.operation === 'json_stringify'
        ? JSON.stringify(translated[newKey]) : translated[newKey];
      delete translated[newKey];
    }
    return {name:entry.old_name,args:translated};
  }

  return {
    tools,
    canonicalize,
    async validateCall(tool,args,name) {
      if (!toolNames.has(name)) throw new Error(`unknown tool: ${name}`);
      const validate = validators.get(name);
      if (!validate(args)) {
        const details = (validate.errors || []).slice(0,4).map(error =>
          `arguments${error.instancePath || ''}: ${error.message}${error.params?.missingProperty ? ` (${error.params.missingProperty})` : ''}${error.params?.additionalProperty ? ` (${error.params.additionalProperty})` : ''}`);
        throw new Error(details.join('; ').slice(0,1200));
      }
      if (legacyValidate) {
        const original = toLegacy(name,args);
        await legacyValidate(originals.get(original.name),original.args,original.name);
      }
    },
    callTool(name,args) {
      const original = toLegacy(name,args);
      return legacyCall(original.name,original.args);
    },
  };
}
