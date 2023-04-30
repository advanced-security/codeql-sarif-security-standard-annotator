require('./sourcemap-register.js');/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 3109:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
/* eslint-disable no-console */
const path_1 = __nccwpck_require__(1017);
const process_1 = __nccwpck_require__(7282);
const yargs_1 = __importDefault(__nccwpck_require__(8822));
const helpers_1 = __nccwpck_require__(6658);
const fs_1 = __nccwpck_require__(7147);
const core = __importStar(__nccwpck_require__(2186));
const xmldom_1 = __nccwpck_require__(9213);
const xpath = __importStar(__nccwpck_require__(5319));
const jsonpath_plus_1 = __nccwpck_require__(4697);
let sarifFilePath;
let cweFilePath;
let cweIdXpath;
let securityStandardTag;
let outputFilePath;
let sarifResults;
let cweXml;
const defaultCweFilePath = (0, path_1.resolve)((0, path_1.dirname)(process.argv[1]), '..//security-standards/owasp-top10-2021.xml');
const defaultCweFileXmlNs = { cwe: 'http://cwe.mitre.org/cwe-6' };
const defaulCweIdXpath = '/cwe:Weakness_Catalog/cwe:Weaknesses/cwe:Weakness/@ID';
const codeQlTagsJsonPath = '$.runs[*].tool.extensions[*].rules[*].properties.tags';
const codeQlCweTagPrefix = 'external/cwe/cwe-';
const defaultSecurityStandardTag = 'owasp-top10-2021';
// Parse Actions or CLI inputs
if (process_1.env.GITHUB_ACTIONS === 'true') {
    sarifFilePath = (0, path_1.resolve)(core.getInput('sarifFile'));
    cweFilePath = (0, path_1.resolve)(core.getInput('cweFile') || defaultCweFilePath);
    cweIdXpath = core.getInput('cweIdXpath') || defaulCweIdXpath;
    securityStandardTag = core.getInput('securityStandardTag') || defaultSecurityStandardTag;
    outputFilePath = (0, path_1.resolve)(core.getInput('outputFile') || sarifFilePath);
}
else {
    const argv = (0, yargs_1.default)((0, helpers_1.hideBin)(process.argv))
        .options({
        sarifFile: { type: 'string', demandOption: true },
        cweFile: { type: 'string' },
        cweIdXpath: { type: 'string' },
        securityStandardTag: { type: 'string' },
        outputFile: { type: 'string' }
    })
        .parseSync();
    sarifFilePath = (0, path_1.resolve)(argv.sarifFile);
    cweFilePath = (0, path_1.resolve)(argv.cweFile || defaultCweFilePath);
    cweIdXpath = argv.cweIdXpath || defaulCweIdXpath;
    securityStandardTag = argv.securityStandardTag || defaultSecurityStandardTag;
    outputFilePath = (0, path_1.resolve)(argv.outputFile || sarifFilePath);
}
console.log(`Using ${sarifFilePath} for SARIF file`);
console.log(`Using ${cweFilePath} for CWE file`);
console.log(`Using ${outputFilePath} for output file`);
// Load SARIF file
try {
    sarifResults = JSON.parse((0, fs_1.readFileSync)(sarifFilePath, 'utf8'));
}
catch (err) {
    core.setFailed(`Unable to load SARIF file: ${err}`);
    process.exit(1);
}
// Load security standard CWE XML file
try {
    cweXml = new xmldom_1.DOMParser().parseFromString((0, fs_1.readFileSync)(cweFilePath, 'utf8'));
}
catch (err) {
    core.setFailed(`Unable to load CWE file: ${err}`);
    process.exit(1);
}
const select = xpath.useNamespaces(defaultCweFileXmlNs);
// Can't use instanceof Attr type to filter as Attr is not defined in the Node runtime and not exposed by xmldom
const cweIdAttributes = select(cweIdXpath, cweXml).filter((x) => Object.getPrototypeOf(x).constructor.name === 'Attr');
const cweIdArray = cweIdAttributes.map(attribute => attribute.value);
// Add tag to SARIF file
(0, jsonpath_plus_1.JSONPath)({
    path: codeQlTagsJsonPath,
    json: sarifResults,
    callback: (tags) => {
        for (const tag of tags) {
            if (tag.startsWith(codeQlCweTagPrefix)) {
                const cweId = tag.replace(codeQlCweTagPrefix, '');
                if (cweIdArray.includes(cweId)) {
                    tags.push(securityStandardTag);
                    return;
                }
            }
        }
    }
});
// Output SARIF file with tag added
try {
    (0, fs_1.writeFileSync)(outputFilePath, JSON.stringify(sarifResults));
}
catch (err) {
    core.setFailed(`Unable to write SARIF file: ${err}`);
    process.exit(1);
}
//# sourceMappingURL=main.js.map

/***/ }),

/***/ 7351:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.issue = exports.issueCommand = void 0;
const os = __importStar(__nccwpck_require__(2037));
const utils_1 = __nccwpck_require__(5278);
/**
 * Commands
 *
 * Command Format:
 *   ::name key=value,key=value::message
 *
 * Examples:
 *   ::warning::This is the message
 *   ::set-env name=MY_VAR::some value
 */
function issueCommand(command, properties, message) {
    const cmd = new Command(command, properties, message);
    process.stdout.write(cmd.toString() + os.EOL);
}
exports.issueCommand = issueCommand;
function issue(name, message = '') {
    issueCommand(name, {}, message);
}
exports.issue = issue;
const CMD_STRING = '::';
class Command {
    constructor(command, properties, message) {
        if (!command) {
            command = 'missing.command';
        }
        this.command = command;
        this.properties = properties;
        this.message = message;
    }
    toString() {
        let cmdStr = CMD_STRING + this.command;
        if (this.properties && Object.keys(this.properties).length > 0) {
            cmdStr += ' ';
            let first = true;
            for (const key in this.properties) {
                if (this.properties.hasOwnProperty(key)) {
                    const val = this.properties[key];
                    if (val) {
                        if (first) {
                            first = false;
                        }
                        else {
                            cmdStr += ',';
                        }
                        cmdStr += `${key}=${escapeProperty(val)}`;
                    }
                }
            }
        }
        cmdStr += `${CMD_STRING}${escapeData(this.message)}`;
        return cmdStr;
    }
}
function escapeData(s) {
    return utils_1.toCommandValue(s)
        .replace(/%/g, '%25')
        .replace(/\r/g, '%0D')
        .replace(/\n/g, '%0A');
}
function escapeProperty(s) {
    return utils_1.toCommandValue(s)
        .replace(/%/g, '%25')
        .replace(/\r/g, '%0D')
        .replace(/\n/g, '%0A')
        .replace(/:/g, '%3A')
        .replace(/,/g, '%2C');
}
//# sourceMappingURL=command.js.map

/***/ }),

/***/ 2186:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getIDToken = exports.getState = exports.saveState = exports.group = exports.endGroup = exports.startGroup = exports.info = exports.notice = exports.warning = exports.error = exports.debug = exports.isDebug = exports.setFailed = exports.setCommandEcho = exports.setOutput = exports.getBooleanInput = exports.getMultilineInput = exports.getInput = exports.addPath = exports.setSecret = exports.exportVariable = exports.ExitCode = void 0;
const command_1 = __nccwpck_require__(7351);
const file_command_1 = __nccwpck_require__(717);
const utils_1 = __nccwpck_require__(5278);
const os = __importStar(__nccwpck_require__(2037));
const path = __importStar(__nccwpck_require__(1017));
const oidc_utils_1 = __nccwpck_require__(8041);
/**
 * The code to exit an action
 */
var ExitCode;
(function (ExitCode) {
    /**
     * A code indicating that the action was successful
     */
    ExitCode[ExitCode["Success"] = 0] = "Success";
    /**
     * A code indicating that the action was a failure
     */
    ExitCode[ExitCode["Failure"] = 1] = "Failure";
})(ExitCode = exports.ExitCode || (exports.ExitCode = {}));
//-----------------------------------------------------------------------
// Variables
//-----------------------------------------------------------------------
/**
 * Sets env variable for this action and future actions in the job
 * @param name the name of the variable to set
 * @param val the value of the variable. Non-string values will be converted to a string via JSON.stringify
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function exportVariable(name, val) {
    const convertedVal = utils_1.toCommandValue(val);
    process.env[name] = convertedVal;
    const filePath = process.env['GITHUB_ENV'] || '';
    if (filePath) {
        return file_command_1.issueFileCommand('ENV', file_command_1.prepareKeyValueMessage(name, val));
    }
    command_1.issueCommand('set-env', { name }, convertedVal);
}
exports.exportVariable = exportVariable;
/**
 * Registers a secret which will get masked from logs
 * @param secret value of the secret
 */
function setSecret(secret) {
    command_1.issueCommand('add-mask', {}, secret);
}
exports.setSecret = setSecret;
/**
 * Prepends inputPath to the PATH (for this action and future actions)
 * @param inputPath
 */
function addPath(inputPath) {
    const filePath = process.env['GITHUB_PATH'] || '';
    if (filePath) {
        file_command_1.issueFileCommand('PATH', inputPath);
    }
    else {
        command_1.issueCommand('add-path', {}, inputPath);
    }
    process.env['PATH'] = `${inputPath}${path.delimiter}${process.env['PATH']}`;
}
exports.addPath = addPath;
/**
 * Gets the value of an input.
 * Unless trimWhitespace is set to false in InputOptions, the value is also trimmed.
 * Returns an empty string if the value is not defined.
 *
 * @param     name     name of the input to get
 * @param     options  optional. See InputOptions.
 * @returns   string
 */
function getInput(name, options) {
    const val = process.env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`] || '';
    if (options && options.required && !val) {
        throw new Error(`Input required and not supplied: ${name}`);
    }
    if (options && options.trimWhitespace === false) {
        return val;
    }
    return val.trim();
}
exports.getInput = getInput;
/**
 * Gets the values of an multiline input.  Each value is also trimmed.
 *
 * @param     name     name of the input to get
 * @param     options  optional. See InputOptions.
 * @returns   string[]
 *
 */
function getMultilineInput(name, options) {
    const inputs = getInput(name, options)
        .split('\n')
        .filter(x => x !== '');
    if (options && options.trimWhitespace === false) {
        return inputs;
    }
    return inputs.map(input => input.trim());
}
exports.getMultilineInput = getMultilineInput;
/**
 * Gets the input value of the boolean type in the YAML 1.2 "core schema" specification.
 * Support boolean input list: `true | True | TRUE | false | False | FALSE` .
 * The return value is also in boolean type.
 * ref: https://yaml.org/spec/1.2/spec.html#id2804923
 *
 * @param     name     name of the input to get
 * @param     options  optional. See InputOptions.
 * @returns   boolean
 */
function getBooleanInput(name, options) {
    const trueValue = ['true', 'True', 'TRUE'];
    const falseValue = ['false', 'False', 'FALSE'];
    const val = getInput(name, options);
    if (trueValue.includes(val))
        return true;
    if (falseValue.includes(val))
        return false;
    throw new TypeError(`Input does not meet YAML 1.2 "Core Schema" specification: ${name}\n` +
        `Support boolean input list: \`true | True | TRUE | false | False | FALSE\``);
}
exports.getBooleanInput = getBooleanInput;
/**
 * Sets the value of an output.
 *
 * @param     name     name of the output to set
 * @param     value    value to store. Non-string values will be converted to a string via JSON.stringify
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function setOutput(name, value) {
    const filePath = process.env['GITHUB_OUTPUT'] || '';
    if (filePath) {
        return file_command_1.issueFileCommand('OUTPUT', file_command_1.prepareKeyValueMessage(name, value));
    }
    process.stdout.write(os.EOL);
    command_1.issueCommand('set-output', { name }, utils_1.toCommandValue(value));
}
exports.setOutput = setOutput;
/**
 * Enables or disables the echoing of commands into stdout for the rest of the step.
 * Echoing is disabled by default if ACTIONS_STEP_DEBUG is not set.
 *
 */
function setCommandEcho(enabled) {
    command_1.issue('echo', enabled ? 'on' : 'off');
}
exports.setCommandEcho = setCommandEcho;
//-----------------------------------------------------------------------
// Results
//-----------------------------------------------------------------------
/**
 * Sets the action status to failed.
 * When the action exits it will be with an exit code of 1
 * @param message add error issue message
 */
function setFailed(message) {
    process.exitCode = ExitCode.Failure;
    error(message);
}
exports.setFailed = setFailed;
//-----------------------------------------------------------------------
// Logging Commands
//-----------------------------------------------------------------------
/**
 * Gets whether Actions Step Debug is on or not
 */
function isDebug() {
    return process.env['RUNNER_DEBUG'] === '1';
}
exports.isDebug = isDebug;
/**
 * Writes debug message to user log
 * @param message debug message
 */
function debug(message) {
    command_1.issueCommand('debug', {}, message);
}
exports.debug = debug;
/**
 * Adds an error issue
 * @param message error issue message. Errors will be converted to string via toString()
 * @param properties optional properties to add to the annotation.
 */
function error(message, properties = {}) {
    command_1.issueCommand('error', utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
}
exports.error = error;
/**
 * Adds a warning issue
 * @param message warning issue message. Errors will be converted to string via toString()
 * @param properties optional properties to add to the annotation.
 */
function warning(message, properties = {}) {
    command_1.issueCommand('warning', utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
}
exports.warning = warning;
/**
 * Adds a notice issue
 * @param message notice issue message. Errors will be converted to string via toString()
 * @param properties optional properties to add to the annotation.
 */
function notice(message, properties = {}) {
    command_1.issueCommand('notice', utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
}
exports.notice = notice;
/**
 * Writes info to log with console.log.
 * @param message info message
 */
function info(message) {
    process.stdout.write(message + os.EOL);
}
exports.info = info;
/**
 * Begin an output group.
 *
 * Output until the next `groupEnd` will be foldable in this group
 *
 * @param name The name of the output group
 */
function startGroup(name) {
    command_1.issue('group', name);
}
exports.startGroup = startGroup;
/**
 * End an output group.
 */
function endGroup() {
    command_1.issue('endgroup');
}
exports.endGroup = endGroup;
/**
 * Wrap an asynchronous function call in a group.
 *
 * Returns the same type as the function itself.
 *
 * @param name The name of the group
 * @param fn The function to wrap in the group
 */
function group(name, fn) {
    return __awaiter(this, void 0, void 0, function* () {
        startGroup(name);
        let result;
        try {
            result = yield fn();
        }
        finally {
            endGroup();
        }
        return result;
    });
}
exports.group = group;
//-----------------------------------------------------------------------
// Wrapper action state
//-----------------------------------------------------------------------
/**
 * Saves state for current action, the state can only be retrieved by this action's post job execution.
 *
 * @param     name     name of the state to store
 * @param     value    value to store. Non-string values will be converted to a string via JSON.stringify
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function saveState(name, value) {
    const filePath = process.env['GITHUB_STATE'] || '';
    if (filePath) {
        return file_command_1.issueFileCommand('STATE', file_command_1.prepareKeyValueMessage(name, value));
    }
    command_1.issueCommand('save-state', { name }, utils_1.toCommandValue(value));
}
exports.saveState = saveState;
/**
 * Gets the value of an state set by this action's main execution.
 *
 * @param     name     name of the state to get
 * @returns   string
 */
function getState(name) {
    return process.env[`STATE_${name}`] || '';
}
exports.getState = getState;
function getIDToken(aud) {
    return __awaiter(this, void 0, void 0, function* () {
        return yield oidc_utils_1.OidcClient.getIDToken(aud);
    });
}
exports.getIDToken = getIDToken;
/**
 * Summary exports
 */
var summary_1 = __nccwpck_require__(1327);
Object.defineProperty(exports, "summary", ({ enumerable: true, get: function () { return summary_1.summary; } }));
/**
 * @deprecated use core.summary
 */
var summary_2 = __nccwpck_require__(1327);
Object.defineProperty(exports, "markdownSummary", ({ enumerable: true, get: function () { return summary_2.markdownSummary; } }));
/**
 * Path exports
 */
var path_utils_1 = __nccwpck_require__(2981);
Object.defineProperty(exports, "toPosixPath", ({ enumerable: true, get: function () { return path_utils_1.toPosixPath; } }));
Object.defineProperty(exports, "toWin32Path", ({ enumerable: true, get: function () { return path_utils_1.toWin32Path; } }));
Object.defineProperty(exports, "toPlatformPath", ({ enumerable: true, get: function () { return path_utils_1.toPlatformPath; } }));
//# sourceMappingURL=core.js.map

/***/ }),

/***/ 717:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

// For internal use, subject to change.
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.prepareKeyValueMessage = exports.issueFileCommand = void 0;
// We use any as a valid input type
/* eslint-disable @typescript-eslint/no-explicit-any */
const fs = __importStar(__nccwpck_require__(7147));
const os = __importStar(__nccwpck_require__(2037));
const uuid_1 = __nccwpck_require__(5840);
const utils_1 = __nccwpck_require__(5278);
function issueFileCommand(command, message) {
    const filePath = process.env[`GITHUB_${command}`];
    if (!filePath) {
        throw new Error(`Unable to find environment variable for file command ${command}`);
    }
    if (!fs.existsSync(filePath)) {
        throw new Error(`Missing file at path: ${filePath}`);
    }
    fs.appendFileSync(filePath, `${utils_1.toCommandValue(message)}${os.EOL}`, {
        encoding: 'utf8'
    });
}
exports.issueFileCommand = issueFileCommand;
function prepareKeyValueMessage(key, value) {
    const delimiter = `ghadelimiter_${uuid_1.v4()}`;
    const convertedValue = utils_1.toCommandValue(value);
    // These should realistically never happen, but just in case someone finds a
    // way to exploit uuid generation let's not allow keys or values that contain
    // the delimiter.
    if (key.includes(delimiter)) {
        throw new Error(`Unexpected input: name should not contain the delimiter "${delimiter}"`);
    }
    if (convertedValue.includes(delimiter)) {
        throw new Error(`Unexpected input: value should not contain the delimiter "${delimiter}"`);
    }
    return `${key}<<${delimiter}${os.EOL}${convertedValue}${os.EOL}${delimiter}`;
}
exports.prepareKeyValueMessage = prepareKeyValueMessage;
//# sourceMappingURL=file-command.js.map

/***/ }),

/***/ 8041:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.OidcClient = void 0;
const http_client_1 = __nccwpck_require__(6255);
const auth_1 = __nccwpck_require__(5526);
const core_1 = __nccwpck_require__(2186);
class OidcClient {
    static createHttpClient(allowRetry = true, maxRetry = 10) {
        const requestOptions = {
            allowRetries: allowRetry,
            maxRetries: maxRetry
        };
        return new http_client_1.HttpClient('actions/oidc-client', [new auth_1.BearerCredentialHandler(OidcClient.getRequestToken())], requestOptions);
    }
    static getRequestToken() {
        const token = process.env['ACTIONS_ID_TOKEN_REQUEST_TOKEN'];
        if (!token) {
            throw new Error('Unable to get ACTIONS_ID_TOKEN_REQUEST_TOKEN env variable');
        }
        return token;
    }
    static getIDTokenUrl() {
        const runtimeUrl = process.env['ACTIONS_ID_TOKEN_REQUEST_URL'];
        if (!runtimeUrl) {
            throw new Error('Unable to get ACTIONS_ID_TOKEN_REQUEST_URL env variable');
        }
        return runtimeUrl;
    }
    static getCall(id_token_url) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const httpclient = OidcClient.createHttpClient();
            const res = yield httpclient
                .getJson(id_token_url)
                .catch(error => {
                throw new Error(`Failed to get ID Token. \n 
        Error Code : ${error.statusCode}\n 
        Error Message: ${error.result.message}`);
            });
            const id_token = (_a = res.result) === null || _a === void 0 ? void 0 : _a.value;
            if (!id_token) {
                throw new Error('Response json body do not have ID Token field');
            }
            return id_token;
        });
    }
    static getIDToken(audience) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                // New ID Token is requested from action service
                let id_token_url = OidcClient.getIDTokenUrl();
                if (audience) {
                    const encodedAudience = encodeURIComponent(audience);
                    id_token_url = `${id_token_url}&audience=${encodedAudience}`;
                }
                core_1.debug(`ID token url is ${id_token_url}`);
                const id_token = yield OidcClient.getCall(id_token_url);
                core_1.setSecret(id_token);
                return id_token;
            }
            catch (error) {
                throw new Error(`Error message: ${error.message}`);
            }
        });
    }
}
exports.OidcClient = OidcClient;
//# sourceMappingURL=oidc-utils.js.map

/***/ }),

/***/ 2981:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.toPlatformPath = exports.toWin32Path = exports.toPosixPath = void 0;
const path = __importStar(__nccwpck_require__(1017));
/**
 * toPosixPath converts the given path to the posix form. On Windows, \\ will be
 * replaced with /.
 *
 * @param pth. Path to transform.
 * @return string Posix path.
 */
function toPosixPath(pth) {
    return pth.replace(/[\\]/g, '/');
}
exports.toPosixPath = toPosixPath;
/**
 * toWin32Path converts the given path to the win32 form. On Linux, / will be
 * replaced with \\.
 *
 * @param pth. Path to transform.
 * @return string Win32 path.
 */
function toWin32Path(pth) {
    return pth.replace(/[/]/g, '\\');
}
exports.toWin32Path = toWin32Path;
/**
 * toPlatformPath converts the given path to a platform-specific path. It does
 * this by replacing instances of / and \ with the platform-specific path
 * separator.
 *
 * @param pth The path to platformize.
 * @return string The platform-specific path.
 */
function toPlatformPath(pth) {
    return pth.replace(/[/\\]/g, path.sep);
}
exports.toPlatformPath = toPlatformPath;
//# sourceMappingURL=path-utils.js.map

/***/ }),

/***/ 1327:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.summary = exports.markdownSummary = exports.SUMMARY_DOCS_URL = exports.SUMMARY_ENV_VAR = void 0;
const os_1 = __nccwpck_require__(2037);
const fs_1 = __nccwpck_require__(7147);
const { access, appendFile, writeFile } = fs_1.promises;
exports.SUMMARY_ENV_VAR = 'GITHUB_STEP_SUMMARY';
exports.SUMMARY_DOCS_URL = 'https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions#adding-a-job-summary';
class Summary {
    constructor() {
        this._buffer = '';
    }
    /**
     * Finds the summary file path from the environment, rejects if env var is not found or file does not exist
     * Also checks r/w permissions.
     *
     * @returns step summary file path
     */
    filePath() {
        return __awaiter(this, void 0, void 0, function* () {
            if (this._filePath) {
                return this._filePath;
            }
            const pathFromEnv = process.env[exports.SUMMARY_ENV_VAR];
            if (!pathFromEnv) {
                throw new Error(`Unable to find environment variable for $${exports.SUMMARY_ENV_VAR}. Check if your runtime environment supports job summaries.`);
            }
            try {
                yield access(pathFromEnv, fs_1.constants.R_OK | fs_1.constants.W_OK);
            }
            catch (_a) {
                throw new Error(`Unable to access summary file: '${pathFromEnv}'. Check if the file has correct read/write permissions.`);
            }
            this._filePath = pathFromEnv;
            return this._filePath;
        });
    }
    /**
     * Wraps content in an HTML tag, adding any HTML attributes
     *
     * @param {string} tag HTML tag to wrap
     * @param {string | null} content content within the tag
     * @param {[attribute: string]: string} attrs key-value list of HTML attributes to add
     *
     * @returns {string} content wrapped in HTML element
     */
    wrap(tag, content, attrs = {}) {
        const htmlAttrs = Object.entries(attrs)
            .map(([key, value]) => ` ${key}="${value}"`)
            .join('');
        if (!content) {
            return `<${tag}${htmlAttrs}>`;
        }
        return `<${tag}${htmlAttrs}>${content}</${tag}>`;
    }
    /**
     * Writes text in the buffer to the summary buffer file and empties buffer. Will append by default.
     *
     * @param {SummaryWriteOptions} [options] (optional) options for write operation
     *
     * @returns {Promise<Summary>} summary instance
     */
    write(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const overwrite = !!(options === null || options === void 0 ? void 0 : options.overwrite);
            const filePath = yield this.filePath();
            const writeFunc = overwrite ? writeFile : appendFile;
            yield writeFunc(filePath, this._buffer, { encoding: 'utf8' });
            return this.emptyBuffer();
        });
    }
    /**
     * Clears the summary buffer and wipes the summary file
     *
     * @returns {Summary} summary instance
     */
    clear() {
        return __awaiter(this, void 0, void 0, function* () {
            return this.emptyBuffer().write({ overwrite: true });
        });
    }
    /**
     * Returns the current summary buffer as a string
     *
     * @returns {string} string of summary buffer
     */
    stringify() {
        return this._buffer;
    }
    /**
     * If the summary buffer is empty
     *
     * @returns {boolen} true if the buffer is empty
     */
    isEmptyBuffer() {
        return this._buffer.length === 0;
    }
    /**
     * Resets the summary buffer without writing to summary file
     *
     * @returns {Summary} summary instance
     */
    emptyBuffer() {
        this._buffer = '';
        return this;
    }
    /**
     * Adds raw text to the summary buffer
     *
     * @param {string} text content to add
     * @param {boolean} [addEOL=false] (optional) append an EOL to the raw text (default: false)
     *
     * @returns {Summary} summary instance
     */
    addRaw(text, addEOL = false) {
        this._buffer += text;
        return addEOL ? this.addEOL() : this;
    }
    /**
     * Adds the operating system-specific end-of-line marker to the buffer
     *
     * @returns {Summary} summary instance
     */
    addEOL() {
        return this.addRaw(os_1.EOL);
    }
    /**
     * Adds an HTML codeblock to the summary buffer
     *
     * @param {string} code content to render within fenced code block
     * @param {string} lang (optional) language to syntax highlight code
     *
     * @returns {Summary} summary instance
     */
    addCodeBlock(code, lang) {
        const attrs = Object.assign({}, (lang && { lang }));
        const element = this.wrap('pre', this.wrap('code', code), attrs);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML list to the summary buffer
     *
     * @param {string[]} items list of items to render
     * @param {boolean} [ordered=false] (optional) if the rendered list should be ordered or not (default: false)
     *
     * @returns {Summary} summary instance
     */
    addList(items, ordered = false) {
        const tag = ordered ? 'ol' : 'ul';
        const listItems = items.map(item => this.wrap('li', item)).join('');
        const element = this.wrap(tag, listItems);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML table to the summary buffer
     *
     * @param {SummaryTableCell[]} rows table rows
     *
     * @returns {Summary} summary instance
     */
    addTable(rows) {
        const tableBody = rows
            .map(row => {
            const cells = row
                .map(cell => {
                if (typeof cell === 'string') {
                    return this.wrap('td', cell);
                }
                const { header, data, colspan, rowspan } = cell;
                const tag = header ? 'th' : 'td';
                const attrs = Object.assign(Object.assign({}, (colspan && { colspan })), (rowspan && { rowspan }));
                return this.wrap(tag, data, attrs);
            })
                .join('');
            return this.wrap('tr', cells);
        })
            .join('');
        const element = this.wrap('table', tableBody);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds a collapsable HTML details element to the summary buffer
     *
     * @param {string} label text for the closed state
     * @param {string} content collapsable content
     *
     * @returns {Summary} summary instance
     */
    addDetails(label, content) {
        const element = this.wrap('details', this.wrap('summary', label) + content);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML image tag to the summary buffer
     *
     * @param {string} src path to the image you to embed
     * @param {string} alt text description of the image
     * @param {SummaryImageOptions} options (optional) addition image attributes
     *
     * @returns {Summary} summary instance
     */
    addImage(src, alt, options) {
        const { width, height } = options || {};
        const attrs = Object.assign(Object.assign({}, (width && { width })), (height && { height }));
        const element = this.wrap('img', null, Object.assign({ src, alt }, attrs));
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML section heading element
     *
     * @param {string} text heading text
     * @param {number | string} [level=1] (optional) the heading level, default: 1
     *
     * @returns {Summary} summary instance
     */
    addHeading(text, level) {
        const tag = `h${level}`;
        const allowedTag = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'].includes(tag)
            ? tag
            : 'h1';
        const element = this.wrap(allowedTag, text);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML thematic break (<hr>) to the summary buffer
     *
     * @returns {Summary} summary instance
     */
    addSeparator() {
        const element = this.wrap('hr', null);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML line break (<br>) to the summary buffer
     *
     * @returns {Summary} summary instance
     */
    addBreak() {
        const element = this.wrap('br', null);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML blockquote to the summary buffer
     *
     * @param {string} text quote text
     * @param {string} cite (optional) citation url
     *
     * @returns {Summary} summary instance
     */
    addQuote(text, cite) {
        const attrs = Object.assign({}, (cite && { cite }));
        const element = this.wrap('blockquote', text, attrs);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML anchor tag to the summary buffer
     *
     * @param {string} text link text/content
     * @param {string} href hyperlink
     *
     * @returns {Summary} summary instance
     */
    addLink(text, href) {
        const element = this.wrap('a', text, { href });
        return this.addRaw(element).addEOL();
    }
}
const _summary = new Summary();
/**
 * @deprecated use `core.summary`
 */
exports.markdownSummary = _summary;
exports.summary = _summary;
//# sourceMappingURL=summary.js.map

/***/ }),

/***/ 5278:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

// We use any as a valid input type
/* eslint-disable @typescript-eslint/no-explicit-any */
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.toCommandProperties = exports.toCommandValue = void 0;
/**
 * Sanitizes an input into a string so it can be passed into issueCommand safely
 * @param input input to sanitize into a string
 */
function toCommandValue(input) {
    if (input === null || input === undefined) {
        return '';
    }
    else if (typeof input === 'string' || input instanceof String) {
        return input;
    }
    return JSON.stringify(input);
}
exports.toCommandValue = toCommandValue;
/**
 *
 * @param annotationProperties
 * @returns The command properties to send with the actual annotation command
 * See IssueCommandProperties: https://github.com/actions/runner/blob/main/src/Runner.Worker/ActionCommandManager.cs#L646
 */
function toCommandProperties(annotationProperties) {
    if (!Object.keys(annotationProperties).length) {
        return {};
    }
    return {
        title: annotationProperties.title,
        file: annotationProperties.file,
        line: annotationProperties.startLine,
        endLine: annotationProperties.endLine,
        col: annotationProperties.startColumn,
        endColumn: annotationProperties.endColumn
    };
}
exports.toCommandProperties = toCommandProperties;
//# sourceMappingURL=utils.js.map

/***/ }),

/***/ 5526:
/***/ (function(__unused_webpack_module, exports) {

"use strict";

var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.PersonalAccessTokenCredentialHandler = exports.BearerCredentialHandler = exports.BasicCredentialHandler = void 0;
class BasicCredentialHandler {
    constructor(username, password) {
        this.username = username;
        this.password = password;
    }
    prepareRequest(options) {
        if (!options.headers) {
            throw Error('The request has no headers');
        }
        options.headers['Authorization'] = `Basic ${Buffer.from(`${this.username}:${this.password}`).toString('base64')}`;
    }
    // This handler cannot handle 401
    canHandleAuthentication() {
        return false;
    }
    handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error('not implemented');
        });
    }
}
exports.BasicCredentialHandler = BasicCredentialHandler;
class BearerCredentialHandler {
    constructor(token) {
        this.token = token;
    }
    // currently implements pre-authorization
    // TODO: support preAuth = false where it hooks on 401
    prepareRequest(options) {
        if (!options.headers) {
            throw Error('The request has no headers');
        }
        options.headers['Authorization'] = `Bearer ${this.token}`;
    }
    // This handler cannot handle 401
    canHandleAuthentication() {
        return false;
    }
    handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error('not implemented');
        });
    }
}
exports.BearerCredentialHandler = BearerCredentialHandler;
class PersonalAccessTokenCredentialHandler {
    constructor(token) {
        this.token = token;
    }
    // currently implements pre-authorization
    // TODO: support preAuth = false where it hooks on 401
    prepareRequest(options) {
        if (!options.headers) {
            throw Error('The request has no headers');
        }
        options.headers['Authorization'] = `Basic ${Buffer.from(`PAT:${this.token}`).toString('base64')}`;
    }
    // This handler cannot handle 401
    canHandleAuthentication() {
        return false;
    }
    handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error('not implemented');
        });
    }
}
exports.PersonalAccessTokenCredentialHandler = PersonalAccessTokenCredentialHandler;
//# sourceMappingURL=auth.js.map

/***/ }),

/***/ 6255:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

/* eslint-disable @typescript-eslint/no-explicit-any */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.HttpClient = exports.isHttps = exports.HttpClientResponse = exports.HttpClientError = exports.getProxyUrl = exports.MediaTypes = exports.Headers = exports.HttpCodes = void 0;
const http = __importStar(__nccwpck_require__(3685));
const https = __importStar(__nccwpck_require__(5687));
const pm = __importStar(__nccwpck_require__(9835));
const tunnel = __importStar(__nccwpck_require__(4294));
var HttpCodes;
(function (HttpCodes) {
    HttpCodes[HttpCodes["OK"] = 200] = "OK";
    HttpCodes[HttpCodes["MultipleChoices"] = 300] = "MultipleChoices";
    HttpCodes[HttpCodes["MovedPermanently"] = 301] = "MovedPermanently";
    HttpCodes[HttpCodes["ResourceMoved"] = 302] = "ResourceMoved";
    HttpCodes[HttpCodes["SeeOther"] = 303] = "SeeOther";
    HttpCodes[HttpCodes["NotModified"] = 304] = "NotModified";
    HttpCodes[HttpCodes["UseProxy"] = 305] = "UseProxy";
    HttpCodes[HttpCodes["SwitchProxy"] = 306] = "SwitchProxy";
    HttpCodes[HttpCodes["TemporaryRedirect"] = 307] = "TemporaryRedirect";
    HttpCodes[HttpCodes["PermanentRedirect"] = 308] = "PermanentRedirect";
    HttpCodes[HttpCodes["BadRequest"] = 400] = "BadRequest";
    HttpCodes[HttpCodes["Unauthorized"] = 401] = "Unauthorized";
    HttpCodes[HttpCodes["PaymentRequired"] = 402] = "PaymentRequired";
    HttpCodes[HttpCodes["Forbidden"] = 403] = "Forbidden";
    HttpCodes[HttpCodes["NotFound"] = 404] = "NotFound";
    HttpCodes[HttpCodes["MethodNotAllowed"] = 405] = "MethodNotAllowed";
    HttpCodes[HttpCodes["NotAcceptable"] = 406] = "NotAcceptable";
    HttpCodes[HttpCodes["ProxyAuthenticationRequired"] = 407] = "ProxyAuthenticationRequired";
    HttpCodes[HttpCodes["RequestTimeout"] = 408] = "RequestTimeout";
    HttpCodes[HttpCodes["Conflict"] = 409] = "Conflict";
    HttpCodes[HttpCodes["Gone"] = 410] = "Gone";
    HttpCodes[HttpCodes["TooManyRequests"] = 429] = "TooManyRequests";
    HttpCodes[HttpCodes["InternalServerError"] = 500] = "InternalServerError";
    HttpCodes[HttpCodes["NotImplemented"] = 501] = "NotImplemented";
    HttpCodes[HttpCodes["BadGateway"] = 502] = "BadGateway";
    HttpCodes[HttpCodes["ServiceUnavailable"] = 503] = "ServiceUnavailable";
    HttpCodes[HttpCodes["GatewayTimeout"] = 504] = "GatewayTimeout";
})(HttpCodes = exports.HttpCodes || (exports.HttpCodes = {}));
var Headers;
(function (Headers) {
    Headers["Accept"] = "accept";
    Headers["ContentType"] = "content-type";
})(Headers = exports.Headers || (exports.Headers = {}));
var MediaTypes;
(function (MediaTypes) {
    MediaTypes["ApplicationJson"] = "application/json";
})(MediaTypes = exports.MediaTypes || (exports.MediaTypes = {}));
/**
 * Returns the proxy URL, depending upon the supplied url and proxy environment variables.
 * @param serverUrl  The server URL where the request will be sent. For example, https://api.github.com
 */
function getProxyUrl(serverUrl) {
    const proxyUrl = pm.getProxyUrl(new URL(serverUrl));
    return proxyUrl ? proxyUrl.href : '';
}
exports.getProxyUrl = getProxyUrl;
const HttpRedirectCodes = [
    HttpCodes.MovedPermanently,
    HttpCodes.ResourceMoved,
    HttpCodes.SeeOther,
    HttpCodes.TemporaryRedirect,
    HttpCodes.PermanentRedirect
];
const HttpResponseRetryCodes = [
    HttpCodes.BadGateway,
    HttpCodes.ServiceUnavailable,
    HttpCodes.GatewayTimeout
];
const RetryableHttpVerbs = ['OPTIONS', 'GET', 'DELETE', 'HEAD'];
const ExponentialBackoffCeiling = 10;
const ExponentialBackoffTimeSlice = 5;
class HttpClientError extends Error {
    constructor(message, statusCode) {
        super(message);
        this.name = 'HttpClientError';
        this.statusCode = statusCode;
        Object.setPrototypeOf(this, HttpClientError.prototype);
    }
}
exports.HttpClientError = HttpClientError;
class HttpClientResponse {
    constructor(message) {
        this.message = message;
    }
    readBody() {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve) => __awaiter(this, void 0, void 0, function* () {
                let output = Buffer.alloc(0);
                this.message.on('data', (chunk) => {
                    output = Buffer.concat([output, chunk]);
                });
                this.message.on('end', () => {
                    resolve(output.toString());
                });
            }));
        });
    }
}
exports.HttpClientResponse = HttpClientResponse;
function isHttps(requestUrl) {
    const parsedUrl = new URL(requestUrl);
    return parsedUrl.protocol === 'https:';
}
exports.isHttps = isHttps;
class HttpClient {
    constructor(userAgent, handlers, requestOptions) {
        this._ignoreSslError = false;
        this._allowRedirects = true;
        this._allowRedirectDowngrade = false;
        this._maxRedirects = 50;
        this._allowRetries = false;
        this._maxRetries = 1;
        this._keepAlive = false;
        this._disposed = false;
        this.userAgent = userAgent;
        this.handlers = handlers || [];
        this.requestOptions = requestOptions;
        if (requestOptions) {
            if (requestOptions.ignoreSslError != null) {
                this._ignoreSslError = requestOptions.ignoreSslError;
            }
            this._socketTimeout = requestOptions.socketTimeout;
            if (requestOptions.allowRedirects != null) {
                this._allowRedirects = requestOptions.allowRedirects;
            }
            if (requestOptions.allowRedirectDowngrade != null) {
                this._allowRedirectDowngrade = requestOptions.allowRedirectDowngrade;
            }
            if (requestOptions.maxRedirects != null) {
                this._maxRedirects = Math.max(requestOptions.maxRedirects, 0);
            }
            if (requestOptions.keepAlive != null) {
                this._keepAlive = requestOptions.keepAlive;
            }
            if (requestOptions.allowRetries != null) {
                this._allowRetries = requestOptions.allowRetries;
            }
            if (requestOptions.maxRetries != null) {
                this._maxRetries = requestOptions.maxRetries;
            }
        }
    }
    options(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('OPTIONS', requestUrl, null, additionalHeaders || {});
        });
    }
    get(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('GET', requestUrl, null, additionalHeaders || {});
        });
    }
    del(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('DELETE', requestUrl, null, additionalHeaders || {});
        });
    }
    post(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('POST', requestUrl, data, additionalHeaders || {});
        });
    }
    patch(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('PATCH', requestUrl, data, additionalHeaders || {});
        });
    }
    put(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('PUT', requestUrl, data, additionalHeaders || {});
        });
    }
    head(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('HEAD', requestUrl, null, additionalHeaders || {});
        });
    }
    sendStream(verb, requestUrl, stream, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request(verb, requestUrl, stream, additionalHeaders);
        });
    }
    /**
     * Gets a typed object from an endpoint
     * Be aware that not found returns a null.  Other errors (4xx, 5xx) reject the promise
     */
    getJson(requestUrl, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
            const res = yield this.get(requestUrl, additionalHeaders);
            return this._processResponse(res, this.requestOptions);
        });
    }
    postJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const data = JSON.stringify(obj, null, 2);
            additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
            additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
            const res = yield this.post(requestUrl, data, additionalHeaders);
            return this._processResponse(res, this.requestOptions);
        });
    }
    putJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const data = JSON.stringify(obj, null, 2);
            additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
            additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
            const res = yield this.put(requestUrl, data, additionalHeaders);
            return this._processResponse(res, this.requestOptions);
        });
    }
    patchJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const data = JSON.stringify(obj, null, 2);
            additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
            additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
            const res = yield this.patch(requestUrl, data, additionalHeaders);
            return this._processResponse(res, this.requestOptions);
        });
    }
    /**
     * Makes a raw http request.
     * All other methods such as get, post, patch, and request ultimately call this.
     * Prefer get, del, post and patch
     */
    request(verb, requestUrl, data, headers) {
        return __awaiter(this, void 0, void 0, function* () {
            if (this._disposed) {
                throw new Error('Client has already been disposed.');
            }
            const parsedUrl = new URL(requestUrl);
            let info = this._prepareRequest(verb, parsedUrl, headers);
            // Only perform retries on reads since writes may not be idempotent.
            const maxTries = this._allowRetries && RetryableHttpVerbs.includes(verb)
                ? this._maxRetries + 1
                : 1;
            let numTries = 0;
            let response;
            do {
                response = yield this.requestRaw(info, data);
                // Check if it's an authentication challenge
                if (response &&
                    response.message &&
                    response.message.statusCode === HttpCodes.Unauthorized) {
                    let authenticationHandler;
                    for (const handler of this.handlers) {
                        if (handler.canHandleAuthentication(response)) {
                            authenticationHandler = handler;
                            break;
                        }
                    }
                    if (authenticationHandler) {
                        return authenticationHandler.handleAuthentication(this, info, data);
                    }
                    else {
                        // We have received an unauthorized response but have no handlers to handle it.
                        // Let the response return to the caller.
                        return response;
                    }
                }
                let redirectsRemaining = this._maxRedirects;
                while (response.message.statusCode &&
                    HttpRedirectCodes.includes(response.message.statusCode) &&
                    this._allowRedirects &&
                    redirectsRemaining > 0) {
                    const redirectUrl = response.message.headers['location'];
                    if (!redirectUrl) {
                        // if there's no location to redirect to, we won't
                        break;
                    }
                    const parsedRedirectUrl = new URL(redirectUrl);
                    if (parsedUrl.protocol === 'https:' &&
                        parsedUrl.protocol !== parsedRedirectUrl.protocol &&
                        !this._allowRedirectDowngrade) {
                        throw new Error('Redirect from HTTPS to HTTP protocol. This downgrade is not allowed for security reasons. If you want to allow this behavior, set the allowRedirectDowngrade option to true.');
                    }
                    // we need to finish reading the response before reassigning response
                    // which will leak the open socket.
                    yield response.readBody();
                    // strip authorization header if redirected to a different hostname
                    if (parsedRedirectUrl.hostname !== parsedUrl.hostname) {
                        for (const header in headers) {
                            // header names are case insensitive
                            if (header.toLowerCase() === 'authorization') {
                                delete headers[header];
                            }
                        }
                    }
                    // let's make the request with the new redirectUrl
                    info = this._prepareRequest(verb, parsedRedirectUrl, headers);
                    response = yield this.requestRaw(info, data);
                    redirectsRemaining--;
                }
                if (!response.message.statusCode ||
                    !HttpResponseRetryCodes.includes(response.message.statusCode)) {
                    // If not a retry code, return immediately instead of retrying
                    return response;
                }
                numTries += 1;
                if (numTries < maxTries) {
                    yield response.readBody();
                    yield this._performExponentialBackoff(numTries);
                }
            } while (numTries < maxTries);
            return response;
        });
    }
    /**
     * Needs to be called if keepAlive is set to true in request options.
     */
    dispose() {
        if (this._agent) {
            this._agent.destroy();
        }
        this._disposed = true;
    }
    /**
     * Raw request.
     * @param info
     * @param data
     */
    requestRaw(info, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => {
                function callbackForResult(err, res) {
                    if (err) {
                        reject(err);
                    }
                    else if (!res) {
                        // If `err` is not passed, then `res` must be passed.
                        reject(new Error('Unknown error'));
                    }
                    else {
                        resolve(res);
                    }
                }
                this.requestRawWithCallback(info, data, callbackForResult);
            });
        });
    }
    /**
     * Raw request with callback.
     * @param info
     * @param data
     * @param onResult
     */
    requestRawWithCallback(info, data, onResult) {
        if (typeof data === 'string') {
            if (!info.options.headers) {
                info.options.headers = {};
            }
            info.options.headers['Content-Length'] = Buffer.byteLength(data, 'utf8');
        }
        let callbackCalled = false;
        function handleResult(err, res) {
            if (!callbackCalled) {
                callbackCalled = true;
                onResult(err, res);
            }
        }
        const req = info.httpModule.request(info.options, (msg) => {
            const res = new HttpClientResponse(msg);
            handleResult(undefined, res);
        });
        let socket;
        req.on('socket', sock => {
            socket = sock;
        });
        // If we ever get disconnected, we want the socket to timeout eventually
        req.setTimeout(this._socketTimeout || 3 * 60000, () => {
            if (socket) {
                socket.end();
            }
            handleResult(new Error(`Request timeout: ${info.options.path}`));
        });
        req.on('error', function (err) {
            // err has statusCode property
            // res should have headers
            handleResult(err);
        });
        if (data && typeof data === 'string') {
            req.write(data, 'utf8');
        }
        if (data && typeof data !== 'string') {
            data.on('close', function () {
                req.end();
            });
            data.pipe(req);
        }
        else {
            req.end();
        }
    }
    /**
     * Gets an http agent. This function is useful when you need an http agent that handles
     * routing through a proxy server - depending upon the url and proxy environment variables.
     * @param serverUrl  The server URL where the request will be sent. For example, https://api.github.com
     */
    getAgent(serverUrl) {
        const parsedUrl = new URL(serverUrl);
        return this._getAgent(parsedUrl);
    }
    _prepareRequest(method, requestUrl, headers) {
        const info = {};
        info.parsedUrl = requestUrl;
        const usingSsl = info.parsedUrl.protocol === 'https:';
        info.httpModule = usingSsl ? https : http;
        const defaultPort = usingSsl ? 443 : 80;
        info.options = {};
        info.options.host = info.parsedUrl.hostname;
        info.options.port = info.parsedUrl.port
            ? parseInt(info.parsedUrl.port)
            : defaultPort;
        info.options.path =
            (info.parsedUrl.pathname || '') + (info.parsedUrl.search || '');
        info.options.method = method;
        info.options.headers = this._mergeHeaders(headers);
        if (this.userAgent != null) {
            info.options.headers['user-agent'] = this.userAgent;
        }
        info.options.agent = this._getAgent(info.parsedUrl);
        // gives handlers an opportunity to participate
        if (this.handlers) {
            for (const handler of this.handlers) {
                handler.prepareRequest(info.options);
            }
        }
        return info;
    }
    _mergeHeaders(headers) {
        if (this.requestOptions && this.requestOptions.headers) {
            return Object.assign({}, lowercaseKeys(this.requestOptions.headers), lowercaseKeys(headers || {}));
        }
        return lowercaseKeys(headers || {});
    }
    _getExistingOrDefaultHeader(additionalHeaders, header, _default) {
        let clientHeader;
        if (this.requestOptions && this.requestOptions.headers) {
            clientHeader = lowercaseKeys(this.requestOptions.headers)[header];
        }
        return additionalHeaders[header] || clientHeader || _default;
    }
    _getAgent(parsedUrl) {
        let agent;
        const proxyUrl = pm.getProxyUrl(parsedUrl);
        const useProxy = proxyUrl && proxyUrl.hostname;
        if (this._keepAlive && useProxy) {
            agent = this._proxyAgent;
        }
        if (this._keepAlive && !useProxy) {
            agent = this._agent;
        }
        // if agent is already assigned use that agent.
        if (agent) {
            return agent;
        }
        const usingSsl = parsedUrl.protocol === 'https:';
        let maxSockets = 100;
        if (this.requestOptions) {
            maxSockets = this.requestOptions.maxSockets || http.globalAgent.maxSockets;
        }
        // This is `useProxy` again, but we need to check `proxyURl` directly for TypeScripts's flow analysis.
        if (proxyUrl && proxyUrl.hostname) {
            const agentOptions = {
                maxSockets,
                keepAlive: this._keepAlive,
                proxy: Object.assign(Object.assign({}, ((proxyUrl.username || proxyUrl.password) && {
                    proxyAuth: `${proxyUrl.username}:${proxyUrl.password}`
                })), { host: proxyUrl.hostname, port: proxyUrl.port })
            };
            let tunnelAgent;
            const overHttps = proxyUrl.protocol === 'https:';
            if (usingSsl) {
                tunnelAgent = overHttps ? tunnel.httpsOverHttps : tunnel.httpsOverHttp;
            }
            else {
                tunnelAgent = overHttps ? tunnel.httpOverHttps : tunnel.httpOverHttp;
            }
            agent = tunnelAgent(agentOptions);
            this._proxyAgent = agent;
        }
        // if reusing agent across request and tunneling agent isn't assigned create a new agent
        if (this._keepAlive && !agent) {
            const options = { keepAlive: this._keepAlive, maxSockets };
            agent = usingSsl ? new https.Agent(options) : new http.Agent(options);
            this._agent = agent;
        }
        // if not using private agent and tunnel agent isn't setup then use global agent
        if (!agent) {
            agent = usingSsl ? https.globalAgent : http.globalAgent;
        }
        if (usingSsl && this._ignoreSslError) {
            // we don't want to set NODE_TLS_REJECT_UNAUTHORIZED=0 since that will affect request for entire process
            // http.RequestOptions doesn't expose a way to modify RequestOptions.agent.options
            // we have to cast it to any and change it directly
            agent.options = Object.assign(agent.options || {}, {
                rejectUnauthorized: false
            });
        }
        return agent;
    }
    _performExponentialBackoff(retryNumber) {
        return __awaiter(this, void 0, void 0, function* () {
            retryNumber = Math.min(ExponentialBackoffCeiling, retryNumber);
            const ms = ExponentialBackoffTimeSlice * Math.pow(2, retryNumber);
            return new Promise(resolve => setTimeout(() => resolve(), ms));
        });
    }
    _processResponse(res, options) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                const statusCode = res.message.statusCode || 0;
                const response = {
                    statusCode,
                    result: null,
                    headers: {}
                };
                // not found leads to null obj returned
                if (statusCode === HttpCodes.NotFound) {
                    resolve(response);
                }
                // get the result from the body
                function dateTimeDeserializer(key, value) {
                    if (typeof value === 'string') {
                        const a = new Date(value);
                        if (!isNaN(a.valueOf())) {
                            return a;
                        }
                    }
                    return value;
                }
                let obj;
                let contents;
                try {
                    contents = yield res.readBody();
                    if (contents && contents.length > 0) {
                        if (options && options.deserializeDates) {
                            obj = JSON.parse(contents, dateTimeDeserializer);
                        }
                        else {
                            obj = JSON.parse(contents);
                        }
                        response.result = obj;
                    }
                    response.headers = res.message.headers;
                }
                catch (err) {
                    // Invalid resource (contents not json);  leaving result obj null
                }
                // note that 3xx redirects are handled by the http layer.
                if (statusCode > 299) {
                    let msg;
                    // if exception/error in body, attempt to get better error
                    if (obj && obj.message) {
                        msg = obj.message;
                    }
                    else if (contents && contents.length > 0) {
                        // it may be the case that the exception is in the body message as string
                        msg = contents;
                    }
                    else {
                        msg = `Failed request: (${statusCode})`;
                    }
                    const err = new HttpClientError(msg, statusCode);
                    err.result = response.result;
                    reject(err);
                }
                else {
                    resolve(response);
                }
            }));
        });
    }
}
exports.HttpClient = HttpClient;
const lowercaseKeys = (obj) => Object.keys(obj).reduce((c, k) => ((c[k.toLowerCase()] = obj[k]), c), {});
//# sourceMappingURL=index.js.map

/***/ }),

/***/ 9835:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.checkBypass = exports.getProxyUrl = void 0;
function getProxyUrl(reqUrl) {
    const usingSsl = reqUrl.protocol === 'https:';
    if (checkBypass(reqUrl)) {
        return undefined;
    }
    const proxyVar = (() => {
        if (usingSsl) {
            return process.env['https_proxy'] || process.env['HTTPS_PROXY'];
        }
        else {
            return process.env['http_proxy'] || process.env['HTTP_PROXY'];
        }
    })();
    if (proxyVar) {
        return new URL(proxyVar);
    }
    else {
        return undefined;
    }
}
exports.getProxyUrl = getProxyUrl;
function checkBypass(reqUrl) {
    if (!reqUrl.hostname) {
        return false;
    }
    const noProxy = process.env['no_proxy'] || process.env['NO_PROXY'] || '';
    if (!noProxy) {
        return false;
    }
    // Determine the request port
    let reqPort;
    if (reqUrl.port) {
        reqPort = Number(reqUrl.port);
    }
    else if (reqUrl.protocol === 'http:') {
        reqPort = 80;
    }
    else if (reqUrl.protocol === 'https:') {
        reqPort = 443;
    }
    // Format the request hostname and hostname with port
    const upperReqHosts = [reqUrl.hostname.toUpperCase()];
    if (typeof reqPort === 'number') {
        upperReqHosts.push(`${upperReqHosts[0]}:${reqPort}`);
    }
    // Compare request host against noproxy
    for (const upperNoProxyItem of noProxy
        .split(',')
        .map(x => x.trim().toUpperCase())
        .filter(x => x)) {
        if (upperReqHosts.some(x => x === upperNoProxyItem)) {
            return true;
        }
    }
    return false;
}
exports.checkBypass = checkBypass;
//# sourceMappingURL=proxy.js.map

/***/ }),

/***/ 9756:
/***/ ((__unused_webpack_module, exports) => {

"use strict";


/**
 * Ponyfill for `Array.prototype.find` which is only available in ES6 runtimes.
 *
 * Works with anything that has a `length` property and index access properties, including NodeList.
 *
 * @template {unknown} T
 * @param {Array<T> | ({length:number, [number]: T})} list
 * @param {function (item: T, index: number, list:Array<T> | ({length:number, [number]: T})):boolean} predicate
 * @param {Partial<Pick<ArrayConstructor['prototype'], 'find'>>?} ac `Array.prototype` by default,
 * 				allows injecting a custom implementation in tests
 * @returns {T | undefined}
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/find
 * @see https://tc39.es/ecma262/multipage/indexed-collections.html#sec-array.prototype.find
 */
function find(list, predicate, ac) {
	if (ac === undefined) {
		ac = Array.prototype;
	}
	if (list && typeof ac.find === 'function') {
		return ac.find.call(list, predicate);
	}
	for (var i = 0; i < list.length; i++) {
		if (Object.prototype.hasOwnProperty.call(list, i)) {
			var item = list[i];
			if (predicate.call(undefined, item, i, list)) {
				return item;
			}
		}
	}
}

/**
 * "Shallow freezes" an object to render it immutable.
 * Uses `Object.freeze` if available,
 * otherwise the immutability is only in the type.
 *
 * Is used to create "enum like" objects.
 *
 * @template T
 * @param {T} object the object to freeze
 * @param {Pick<ObjectConstructor, 'freeze'> = Object} oc `Object` by default,
 * 				allows to inject custom object constructor for tests
 * @returns {Readonly<T>}
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/freeze
 */
function freeze(object, oc) {
	if (oc === undefined) {
		oc = Object
	}
	return oc && typeof oc.freeze === 'function' ? oc.freeze(object) : object
}

/**
 * Since we can not rely on `Object.assign` we provide a simplified version
 * that is sufficient for our needs.
 *
 * @param {Object} target
 * @param {Object | null | undefined} source
 *
 * @returns {Object} target
 * @throws TypeError if target is not an object
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/assign
 * @see https://tc39.es/ecma262/multipage/fundamental-objects.html#sec-object.assign
 */
function assign(target, source) {
	if (target === null || typeof target !== 'object') {
		throw new TypeError('target is not an object')
	}
	for (var key in source) {
		if (Object.prototype.hasOwnProperty.call(source, key)) {
			target[key] = source[key]
		}
	}
	return target
}

/**
 * All mime types that are allowed as input to `DOMParser.parseFromString`
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/DOMParser/parseFromString#Argument02 MDN
 * @see https://html.spec.whatwg.org/multipage/dynamic-markup-insertion.html#domparsersupportedtype WHATWG HTML Spec
 * @see DOMParser.prototype.parseFromString
 */
var MIME_TYPE = freeze({
	/**
	 * `text/html`, the only mime type that triggers treating an XML document as HTML.
	 *
	 * @see DOMParser.SupportedType.isHTML
	 * @see https://www.iana.org/assignments/media-types/text/html IANA MimeType registration
	 * @see https://en.wikipedia.org/wiki/HTML Wikipedia
	 * @see https://developer.mozilla.org/en-US/docs/Web/API/DOMParser/parseFromString MDN
	 * @see https://html.spec.whatwg.org/multipage/dynamic-markup-insertion.html#dom-domparser-parsefromstring WHATWG HTML Spec
	 */
	HTML: 'text/html',

	/**
	 * Helper method to check a mime type if it indicates an HTML document
	 *
	 * @param {string} [value]
	 * @returns {boolean}
	 *
	 * @see https://www.iana.org/assignments/media-types/text/html IANA MimeType registration
	 * @see https://en.wikipedia.org/wiki/HTML Wikipedia
	 * @see https://developer.mozilla.org/en-US/docs/Web/API/DOMParser/parseFromString MDN
	 * @see https://html.spec.whatwg.org/multipage/dynamic-markup-insertion.html#dom-domparser-parsefromstring 	 */
	isHTML: function (value) {
		return value === MIME_TYPE.HTML
	},

	/**
	 * `application/xml`, the standard mime type for XML documents.
	 *
	 * @see https://www.iana.org/assignments/media-types/application/xml IANA MimeType registration
	 * @see https://tools.ietf.org/html/rfc7303#section-9.1 RFC 7303
	 * @see https://en.wikipedia.org/wiki/XML_and_MIME Wikipedia
	 */
	XML_APPLICATION: 'application/xml',

	/**
	 * `text/html`, an alias for `application/xml`.
	 *
	 * @see https://tools.ietf.org/html/rfc7303#section-9.2 RFC 7303
	 * @see https://www.iana.org/assignments/media-types/text/xml IANA MimeType registration
	 * @see https://en.wikipedia.org/wiki/XML_and_MIME Wikipedia
	 */
	XML_TEXT: 'text/xml',

	/**
	 * `application/xhtml+xml`, indicates an XML document that has the default HTML namespace,
	 * but is parsed as an XML document.
	 *
	 * @see https://www.iana.org/assignments/media-types/application/xhtml+xml IANA MimeType registration
	 * @see https://dom.spec.whatwg.org/#dom-domimplementation-createdocument WHATWG DOM Spec
	 * @see https://en.wikipedia.org/wiki/XHTML Wikipedia
	 */
	XML_XHTML_APPLICATION: 'application/xhtml+xml',

	/**
	 * `image/svg+xml`,
	 *
	 * @see https://www.iana.org/assignments/media-types/image/svg+xml IANA MimeType registration
	 * @see https://www.w3.org/TR/SVG11/ W3C SVG 1.1
	 * @see https://en.wikipedia.org/wiki/Scalable_Vector_Graphics Wikipedia
	 */
	XML_SVG_IMAGE: 'image/svg+xml',
})

/**
 * Namespaces that are used in this code base.
 *
 * @see http://www.w3.org/TR/REC-xml-names
 */
var NAMESPACE = freeze({
	/**
	 * The XHTML namespace.
	 *
	 * @see http://www.w3.org/1999/xhtml
	 */
	HTML: 'http://www.w3.org/1999/xhtml',

	/**
	 * Checks if `uri` equals `NAMESPACE.HTML`.
	 *
	 * @param {string} [uri]
	 *
	 * @see NAMESPACE.HTML
	 */
	isHTML: function (uri) {
		return uri === NAMESPACE.HTML
	},

	/**
	 * The SVG namespace.
	 *
	 * @see http://www.w3.org/2000/svg
	 */
	SVG: 'http://www.w3.org/2000/svg',

	/**
	 * The `xml:` namespace.
	 *
	 * @see http://www.w3.org/XML/1998/namespace
	 */
	XML: 'http://www.w3.org/XML/1998/namespace',

	/**
	 * The `xmlns:` namespace
	 *
	 * @see https://www.w3.org/2000/xmlns/
	 */
	XMLNS: 'http://www.w3.org/2000/xmlns/',
})

exports.assign = assign;
exports.find = find;
exports.freeze = freeze;
exports.MIME_TYPE = MIME_TYPE;
exports.NAMESPACE = NAMESPACE;


/***/ }),

/***/ 5072:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

var __webpack_unused_export__;
var conventions = __nccwpck_require__(9756);
var dom = __nccwpck_require__(1389)
var entities = __nccwpck_require__(8508);
var sax = __nccwpck_require__(6058);

var DOMImplementation = dom.DOMImplementation;

var NAMESPACE = conventions.NAMESPACE;

var ParseError = sax.ParseError;
var XMLReader = sax.XMLReader;

/**
 * Normalizes line ending according to https://www.w3.org/TR/xml11/#sec-line-ends:
 *
 * > XML parsed entities are often stored in computer files which,
 * > for editing convenience, are organized into lines.
 * > These lines are typically separated by some combination
 * > of the characters CARRIAGE RETURN (#xD) and LINE FEED (#xA).
 * >
 * > To simplify the tasks of applications, the XML processor must behave
 * > as if it normalized all line breaks in external parsed entities (including the document entity)
 * > on input, before parsing, by translating all of the following to a single #xA character:
 * >
 * > 1. the two-character sequence #xD #xA
 * > 2. the two-character sequence #xD #x85
 * > 3. the single character #x85
 * > 4. the single character #x2028
 * > 5. any #xD character that is not immediately followed by #xA or #x85.
 *
 * @param {string} input
 * @returns {string}
 */
function normalizeLineEndings(input) {
	return input
		.replace(/\r[\n\u0085]/g, '\n')
		.replace(/[\r\u0085\u2028]/g, '\n')
}

/**
 * @typedef Locator
 * @property {number} [columnNumber]
 * @property {number} [lineNumber]
 */

/**
 * @typedef DOMParserOptions
 * @property {DOMHandler} [domBuilder]
 * @property {Function} [errorHandler]
 * @property {(string) => string} [normalizeLineEndings] used to replace line endings before parsing
 * 						defaults to `normalizeLineEndings`
 * @property {Locator} [locator]
 * @property {Record<string, string>} [xmlns]
 *
 * @see normalizeLineEndings
 */

/**
 * The DOMParser interface provides the ability to parse XML or HTML source code
 * from a string into a DOM `Document`.
 *
 * _xmldom is different from the spec in that it allows an `options` parameter,
 * to override the default behavior._
 *
 * @param {DOMParserOptions} [options]
 * @constructor
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/DOMParser
 * @see https://html.spec.whatwg.org/multipage/dynamic-markup-insertion.html#dom-parsing-and-serialization
 */
function DOMParser(options){
	this.options = options ||{locator:{}};
}

DOMParser.prototype.parseFromString = function(source,mimeType){
	var options = this.options;
	var sax =  new XMLReader();
	var domBuilder = options.domBuilder || new DOMHandler();//contentHandler and LexicalHandler
	var errorHandler = options.errorHandler;
	var locator = options.locator;
	var defaultNSMap = options.xmlns||{};
	var isHTML = /\/x?html?$/.test(mimeType);//mimeType.toLowerCase().indexOf('html') > -1;
  	var entityMap = isHTML ? entities.HTML_ENTITIES : entities.XML_ENTITIES;
	if(locator){
		domBuilder.setDocumentLocator(locator)
	}

	sax.errorHandler = buildErrorHandler(errorHandler,domBuilder,locator);
	sax.domBuilder = options.domBuilder || domBuilder;
	if(isHTML){
		defaultNSMap[''] = NAMESPACE.HTML;
	}
	defaultNSMap.xml = defaultNSMap.xml || NAMESPACE.XML;
	var normalize = options.normalizeLineEndings || normalizeLineEndings;
	if (source && typeof source === 'string') {
		sax.parse(
			normalize(source),
			defaultNSMap,
			entityMap
		)
	} else {
		sax.errorHandler.error('invalid doc source')
	}
	return domBuilder.doc;
}
function buildErrorHandler(errorImpl,domBuilder,locator){
	if(!errorImpl){
		if(domBuilder instanceof DOMHandler){
			return domBuilder;
		}
		errorImpl = domBuilder ;
	}
	var errorHandler = {}
	var isCallback = errorImpl instanceof Function;
	locator = locator||{}
	function build(key){
		var fn = errorImpl[key];
		if(!fn && isCallback){
			fn = errorImpl.length == 2?function(msg){errorImpl(key,msg)}:errorImpl;
		}
		errorHandler[key] = fn && function(msg){
			fn('[xmldom '+key+']\t'+msg+_locator(locator));
		}||function(){};
	}
	build('warning');
	build('error');
	build('fatalError');
	return errorHandler;
}

//console.log('#\n\n\n\n\n\n\n####')
/**
 * +ContentHandler+ErrorHandler
 * +LexicalHandler+EntityResolver2
 * -DeclHandler-DTDHandler
 *
 * DefaultHandler:EntityResolver, DTDHandler, ContentHandler, ErrorHandler
 * DefaultHandler2:DefaultHandler,LexicalHandler, DeclHandler, EntityResolver2
 * @link http://www.saxproject.org/apidoc/org/xml/sax/helpers/DefaultHandler.html
 */
function DOMHandler() {
    this.cdata = false;
}
function position(locator,node){
	node.lineNumber = locator.lineNumber;
	node.columnNumber = locator.columnNumber;
}
/**
 * @see org.xml.sax.ContentHandler#startDocument
 * @link http://www.saxproject.org/apidoc/org/xml/sax/ContentHandler.html
 */
DOMHandler.prototype = {
	startDocument : function() {
    	this.doc = new DOMImplementation().createDocument(null, null, null);
    	if (this.locator) {
        	this.doc.documentURI = this.locator.systemId;
    	}
	},
	startElement:function(namespaceURI, localName, qName, attrs) {
		var doc = this.doc;
	    var el = doc.createElementNS(namespaceURI, qName||localName);
	    var len = attrs.length;
	    appendElement(this, el);
	    this.currentElement = el;

		this.locator && position(this.locator,el)
	    for (var i = 0 ; i < len; i++) {
	        var namespaceURI = attrs.getURI(i);
	        var value = attrs.getValue(i);
	        var qName = attrs.getQName(i);
			var attr = doc.createAttributeNS(namespaceURI, qName);
			this.locator &&position(attrs.getLocator(i),attr);
			attr.value = attr.nodeValue = value;
			el.setAttributeNode(attr)
	    }
	},
	endElement:function(namespaceURI, localName, qName) {
		var current = this.currentElement
		var tagName = current.tagName;
		this.currentElement = current.parentNode;
	},
	startPrefixMapping:function(prefix, uri) {
	},
	endPrefixMapping:function(prefix) {
	},
	processingInstruction:function(target, data) {
	    var ins = this.doc.createProcessingInstruction(target, data);
	    this.locator && position(this.locator,ins)
	    appendElement(this, ins);
	},
	ignorableWhitespace:function(ch, start, length) {
	},
	characters:function(chars, start, length) {
		chars = _toString.apply(this,arguments)
		//console.log(chars)
		if(chars){
			if (this.cdata) {
				var charNode = this.doc.createCDATASection(chars);
			} else {
				var charNode = this.doc.createTextNode(chars);
			}
			if(this.currentElement){
				this.currentElement.appendChild(charNode);
			}else if(/^\s*$/.test(chars)){
				this.doc.appendChild(charNode);
				//process xml
			}
			this.locator && position(this.locator,charNode)
		}
	},
	skippedEntity:function(name) {
	},
	endDocument:function() {
		this.doc.normalize();
	},
	setDocumentLocator:function (locator) {
	    if(this.locator = locator){// && !('lineNumber' in locator)){
	    	locator.lineNumber = 0;
	    }
	},
	//LexicalHandler
	comment:function(chars, start, length) {
		chars = _toString.apply(this,arguments)
	    var comm = this.doc.createComment(chars);
	    this.locator && position(this.locator,comm)
	    appendElement(this, comm);
	},

	startCDATA:function() {
	    //used in characters() methods
	    this.cdata = true;
	},
	endCDATA:function() {
	    this.cdata = false;
	},

	startDTD:function(name, publicId, systemId) {
		var impl = this.doc.implementation;
	    if (impl && impl.createDocumentType) {
	        var dt = impl.createDocumentType(name, publicId, systemId);
	        this.locator && position(this.locator,dt)
	        appendElement(this, dt);
					this.doc.doctype = dt;
	    }
	},
	/**
	 * @see org.xml.sax.ErrorHandler
	 * @link http://www.saxproject.org/apidoc/org/xml/sax/ErrorHandler.html
	 */
	warning:function(error) {
		console.warn('[xmldom warning]\t'+error,_locator(this.locator));
	},
	error:function(error) {
		console.error('[xmldom error]\t'+error,_locator(this.locator));
	},
	fatalError:function(error) {
		throw new ParseError(error, this.locator);
	}
}
function _locator(l){
	if(l){
		return '\n@'+(l.systemId ||'')+'#[line:'+l.lineNumber+',col:'+l.columnNumber+']'
	}
}
function _toString(chars,start,length){
	if(typeof chars == 'string'){
		return chars.substr(start,length)
	}else{//java sax connect width xmldom on rhino(what about: "? && !(chars instanceof String)")
		if(chars.length >= start+length || start){
			return new java.lang.String(chars,start,length)+'';
		}
		return chars;
	}
}

/*
 * @link http://www.saxproject.org/apidoc/org/xml/sax/ext/LexicalHandler.html
 * used method of org.xml.sax.ext.LexicalHandler:
 *  #comment(chars, start, length)
 *  #startCDATA()
 *  #endCDATA()
 *  #startDTD(name, publicId, systemId)
 *
 *
 * IGNORED method of org.xml.sax.ext.LexicalHandler:
 *  #endDTD()
 *  #startEntity(name)
 *  #endEntity(name)
 *
 *
 * @link http://www.saxproject.org/apidoc/org/xml/sax/ext/DeclHandler.html
 * IGNORED method of org.xml.sax.ext.DeclHandler
 * 	#attributeDecl(eName, aName, type, mode, value)
 *  #elementDecl(name, model)
 *  #externalEntityDecl(name, publicId, systemId)
 *  #internalEntityDecl(name, value)
 * @link http://www.saxproject.org/apidoc/org/xml/sax/ext/EntityResolver2.html
 * IGNORED method of org.xml.sax.EntityResolver2
 *  #resolveEntity(String name,String publicId,String baseURI,String systemId)
 *  #resolveEntity(publicId, systemId)
 *  #getExternalSubset(name, baseURI)
 * @link http://www.saxproject.org/apidoc/org/xml/sax/DTDHandler.html
 * IGNORED method of org.xml.sax.DTDHandler
 *  #notationDecl(name, publicId, systemId) {};
 *  #unparsedEntityDecl(name, publicId, systemId, notationName) {};
 */
"endDTD,startEntity,endEntity,attributeDecl,elementDecl,externalEntityDecl,internalEntityDecl,resolveEntity,getExternalSubset,notationDecl,unparsedEntityDecl".replace(/\w+/g,function(key){
	DOMHandler.prototype[key] = function(){return null}
})

/* Private static helpers treated below as private instance methods, so don't need to add these to the public API; we might use a Relator to also get rid of non-standard public properties */
function appendElement (hander,node) {
    if (!hander.currentElement) {
        hander.doc.appendChild(node);
    } else {
        hander.currentElement.appendChild(node);
    }
}//appendChild and setAttributeNS are preformance key

__webpack_unused_export__ = DOMHandler;
__webpack_unused_export__ = normalizeLineEndings;
exports.DOMParser = DOMParser;


/***/ }),

/***/ 1389:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

var conventions = __nccwpck_require__(9756);

var find = conventions.find;
var NAMESPACE = conventions.NAMESPACE;

/**
 * A prerequisite for `[].filter`, to drop elements that are empty
 * @param {string} input
 * @returns {boolean}
 */
function notEmptyString (input) {
	return input !== ''
}
/**
 * @see https://infra.spec.whatwg.org/#split-on-ascii-whitespace
 * @see https://infra.spec.whatwg.org/#ascii-whitespace
 *
 * @param {string} input
 * @returns {string[]} (can be empty)
 */
function splitOnASCIIWhitespace(input) {
	// U+0009 TAB, U+000A LF, U+000C FF, U+000D CR, U+0020 SPACE
	return input ? input.split(/[\t\n\f\r ]+/).filter(notEmptyString) : []
}

/**
 * Adds element as a key to current if it is not already present.
 *
 * @param {Record<string, boolean | undefined>} current
 * @param {string} element
 * @returns {Record<string, boolean | undefined>}
 */
function orderedSetReducer (current, element) {
	if (!current.hasOwnProperty(element)) {
		current[element] = true;
	}
	return current;
}

/**
 * @see https://infra.spec.whatwg.org/#ordered-set
 * @param {string} input
 * @returns {string[]}
 */
function toOrderedSet(input) {
	if (!input) return [];
	var list = splitOnASCIIWhitespace(input);
	return Object.keys(list.reduce(orderedSetReducer, {}))
}

/**
 * Uses `list.indexOf` to implement something like `Array.prototype.includes`,
 * which we can not rely on being available.
 *
 * @param {any[]} list
 * @returns {function(any): boolean}
 */
function arrayIncludes (list) {
	return function(element) {
		return list && list.indexOf(element) !== -1;
	}
}

function copy(src,dest){
	for(var p in src){
		if (Object.prototype.hasOwnProperty.call(src, p)) {
			dest[p] = src[p];
		}
	}
}

/**
^\w+\.prototype\.([_\w]+)\s*=\s*((?:.*\{\s*?[\r\n][\s\S]*?^})|\S.*?(?=[;\r\n]));?
^\w+\.prototype\.([_\w]+)\s*=\s*(\S.*?(?=[;\r\n]));?
 */
function _extends(Class,Super){
	var pt = Class.prototype;
	if(!(pt instanceof Super)){
		function t(){};
		t.prototype = Super.prototype;
		t = new t();
		copy(pt,t);
		Class.prototype = pt = t;
	}
	if(pt.constructor != Class){
		if(typeof Class != 'function'){
			console.error("unknown Class:"+Class)
		}
		pt.constructor = Class
	}
}

// Node Types
var NodeType = {}
var ELEMENT_NODE                = NodeType.ELEMENT_NODE                = 1;
var ATTRIBUTE_NODE              = NodeType.ATTRIBUTE_NODE              = 2;
var TEXT_NODE                   = NodeType.TEXT_NODE                   = 3;
var CDATA_SECTION_NODE          = NodeType.CDATA_SECTION_NODE          = 4;
var ENTITY_REFERENCE_NODE       = NodeType.ENTITY_REFERENCE_NODE       = 5;
var ENTITY_NODE                 = NodeType.ENTITY_NODE                 = 6;
var PROCESSING_INSTRUCTION_NODE = NodeType.PROCESSING_INSTRUCTION_NODE = 7;
var COMMENT_NODE                = NodeType.COMMENT_NODE                = 8;
var DOCUMENT_NODE               = NodeType.DOCUMENT_NODE               = 9;
var DOCUMENT_TYPE_NODE          = NodeType.DOCUMENT_TYPE_NODE          = 10;
var DOCUMENT_FRAGMENT_NODE      = NodeType.DOCUMENT_FRAGMENT_NODE      = 11;
var NOTATION_NODE               = NodeType.NOTATION_NODE               = 12;

// ExceptionCode
var ExceptionCode = {}
var ExceptionMessage = {};
var INDEX_SIZE_ERR              = ExceptionCode.INDEX_SIZE_ERR              = ((ExceptionMessage[1]="Index size error"),1);
var DOMSTRING_SIZE_ERR          = ExceptionCode.DOMSTRING_SIZE_ERR          = ((ExceptionMessage[2]="DOMString size error"),2);
var HIERARCHY_REQUEST_ERR       = ExceptionCode.HIERARCHY_REQUEST_ERR       = ((ExceptionMessage[3]="Hierarchy request error"),3);
var WRONG_DOCUMENT_ERR          = ExceptionCode.WRONG_DOCUMENT_ERR          = ((ExceptionMessage[4]="Wrong document"),4);
var INVALID_CHARACTER_ERR       = ExceptionCode.INVALID_CHARACTER_ERR       = ((ExceptionMessage[5]="Invalid character"),5);
var NO_DATA_ALLOWED_ERR         = ExceptionCode.NO_DATA_ALLOWED_ERR         = ((ExceptionMessage[6]="No data allowed"),6);
var NO_MODIFICATION_ALLOWED_ERR = ExceptionCode.NO_MODIFICATION_ALLOWED_ERR = ((ExceptionMessage[7]="No modification allowed"),7);
var NOT_FOUND_ERR               = ExceptionCode.NOT_FOUND_ERR               = ((ExceptionMessage[8]="Not found"),8);
var NOT_SUPPORTED_ERR           = ExceptionCode.NOT_SUPPORTED_ERR           = ((ExceptionMessage[9]="Not supported"),9);
var INUSE_ATTRIBUTE_ERR         = ExceptionCode.INUSE_ATTRIBUTE_ERR         = ((ExceptionMessage[10]="Attribute in use"),10);
//level2
var INVALID_STATE_ERR        	= ExceptionCode.INVALID_STATE_ERR        	= ((ExceptionMessage[11]="Invalid state"),11);
var SYNTAX_ERR               	= ExceptionCode.SYNTAX_ERR               	= ((ExceptionMessage[12]="Syntax error"),12);
var INVALID_MODIFICATION_ERR 	= ExceptionCode.INVALID_MODIFICATION_ERR 	= ((ExceptionMessage[13]="Invalid modification"),13);
var NAMESPACE_ERR            	= ExceptionCode.NAMESPACE_ERR           	= ((ExceptionMessage[14]="Invalid namespace"),14);
var INVALID_ACCESS_ERR       	= ExceptionCode.INVALID_ACCESS_ERR      	= ((ExceptionMessage[15]="Invalid access"),15);

/**
 * DOM Level 2
 * Object DOMException
 * @see http://www.w3.org/TR/2000/REC-DOM-Level-2-Core-20001113/ecma-script-binding.html
 * @see http://www.w3.org/TR/REC-DOM-Level-1/ecma-script-language-binding.html
 */
function DOMException(code, message) {
	if(message instanceof Error){
		var error = message;
	}else{
		error = this;
		Error.call(this, ExceptionMessage[code]);
		this.message = ExceptionMessage[code];
		if(Error.captureStackTrace) Error.captureStackTrace(this, DOMException);
	}
	error.code = code;
	if(message) this.message = this.message + ": " + message;
	return error;
};
DOMException.prototype = Error.prototype;
copy(ExceptionCode,DOMException)

/**
 * @see http://www.w3.org/TR/2000/REC-DOM-Level-2-Core-20001113/core.html#ID-536297177
 * The NodeList interface provides the abstraction of an ordered collection of nodes, without defining or constraining how this collection is implemented. NodeList objects in the DOM are live.
 * The items in the NodeList are accessible via an integral index, starting from 0.
 */
function NodeList() {
};
NodeList.prototype = {
	/**
	 * The number of nodes in the list. The range of valid child node indices is 0 to length-1 inclusive.
	 * @standard level1
	 */
	length:0,
	/**
	 * Returns the indexth item in the collection. If index is greater than or equal to the number of nodes in the list, this returns null.
	 * @standard level1
	 * @param index  unsigned long
	 *   Index into the collection.
	 * @return Node
	 * 	The node at the indexth position in the NodeList, or null if that is not a valid index.
	 */
	item: function(index) {
		return this[index] || null;
	},
	toString:function(isHTML,nodeFilter){
		for(var buf = [], i = 0;i<this.length;i++){
			serializeToString(this[i],buf,isHTML,nodeFilter);
		}
		return buf.join('');
	},
	/**
	 * @private
	 * @param {function (Node):boolean} predicate
	 * @returns {Node[]}
	 */
	filter: function (predicate) {
		return Array.prototype.filter.call(this, predicate);
	},
	/**
	 * @private
	 * @param {Node} item
	 * @returns {number}
	 */
	indexOf: function (item) {
		return Array.prototype.indexOf.call(this, item);
	},
};

function LiveNodeList(node,refresh){
	this._node = node;
	this._refresh = refresh
	_updateLiveList(this);
}
function _updateLiveList(list){
	var inc = list._node._inc || list._node.ownerDocument._inc;
	if(list._inc != inc){
		var ls = list._refresh(list._node);
		//console.log(ls.length)
		__set__(list,'length',ls.length);
		copy(ls,list);
		list._inc = inc;
	}
}
LiveNodeList.prototype.item = function(i){
	_updateLiveList(this);
	return this[i];
}

_extends(LiveNodeList,NodeList);

/**
 * Objects implementing the NamedNodeMap interface are used
 * to represent collections of nodes that can be accessed by name.
 * Note that NamedNodeMap does not inherit from NodeList;
 * NamedNodeMaps are not maintained in any particular order.
 * Objects contained in an object implementing NamedNodeMap may also be accessed by an ordinal index,
 * but this is simply to allow convenient enumeration of the contents of a NamedNodeMap,
 * and does not imply that the DOM specifies an order to these Nodes.
 * NamedNodeMap objects in the DOM are live.
 * used for attributes or DocumentType entities
 */
function NamedNodeMap() {
};

function _findNodeIndex(list,node){
	var i = list.length;
	while(i--){
		if(list[i] === node){return i}
	}
}

function _addNamedNode(el,list,newAttr,oldAttr){
	if(oldAttr){
		list[_findNodeIndex(list,oldAttr)] = newAttr;
	}else{
		list[list.length++] = newAttr;
	}
	if(el){
		newAttr.ownerElement = el;
		var doc = el.ownerDocument;
		if(doc){
			oldAttr && _onRemoveAttribute(doc,el,oldAttr);
			_onAddAttribute(doc,el,newAttr);
		}
	}
}
function _removeNamedNode(el,list,attr){
	//console.log('remove attr:'+attr)
	var i = _findNodeIndex(list,attr);
	if(i>=0){
		var lastIndex = list.length-1
		while(i<lastIndex){
			list[i] = list[++i]
		}
		list.length = lastIndex;
		if(el){
			var doc = el.ownerDocument;
			if(doc){
				_onRemoveAttribute(doc,el,attr);
				attr.ownerElement = null;
			}
		}
	}else{
		throw new DOMException(NOT_FOUND_ERR,new Error(el.tagName+'@'+attr))
	}
}
NamedNodeMap.prototype = {
	length:0,
	item:NodeList.prototype.item,
	getNamedItem: function(key) {
//		if(key.indexOf(':')>0 || key == 'xmlns'){
//			return null;
//		}
		//console.log()
		var i = this.length;
		while(i--){
			var attr = this[i];
			//console.log(attr.nodeName,key)
			if(attr.nodeName == key){
				return attr;
			}
		}
	},
	setNamedItem: function(attr) {
		var el = attr.ownerElement;
		if(el && el!=this._ownerElement){
			throw new DOMException(INUSE_ATTRIBUTE_ERR);
		}
		var oldAttr = this.getNamedItem(attr.nodeName);
		_addNamedNode(this._ownerElement,this,attr,oldAttr);
		return oldAttr;
	},
	/* returns Node */
	setNamedItemNS: function(attr) {// raises: WRONG_DOCUMENT_ERR,NO_MODIFICATION_ALLOWED_ERR,INUSE_ATTRIBUTE_ERR
		var el = attr.ownerElement, oldAttr;
		if(el && el!=this._ownerElement){
			throw new DOMException(INUSE_ATTRIBUTE_ERR);
		}
		oldAttr = this.getNamedItemNS(attr.namespaceURI,attr.localName);
		_addNamedNode(this._ownerElement,this,attr,oldAttr);
		return oldAttr;
	},

	/* returns Node */
	removeNamedItem: function(key) {
		var attr = this.getNamedItem(key);
		_removeNamedNode(this._ownerElement,this,attr);
		return attr;


	},// raises: NOT_FOUND_ERR,NO_MODIFICATION_ALLOWED_ERR

	//for level2
	removeNamedItemNS:function(namespaceURI,localName){
		var attr = this.getNamedItemNS(namespaceURI,localName);
		_removeNamedNode(this._ownerElement,this,attr);
		return attr;
	},
	getNamedItemNS: function(namespaceURI, localName) {
		var i = this.length;
		while(i--){
			var node = this[i];
			if(node.localName == localName && node.namespaceURI == namespaceURI){
				return node;
			}
		}
		return null;
	}
};

/**
 * The DOMImplementation interface represents an object providing methods
 * which are not dependent on any particular document.
 * Such an object is returned by the `Document.implementation` property.
 *
 * __The individual methods describe the differences compared to the specs.__
 *
 * @constructor
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/DOMImplementation MDN
 * @see https://www.w3.org/TR/REC-DOM-Level-1/level-one-core.html#ID-102161490 DOM Level 1 Core (Initial)
 * @see https://www.w3.org/TR/DOM-Level-2-Core/core.html#ID-102161490 DOM Level 2 Core
 * @see https://www.w3.org/TR/DOM-Level-3-Core/core.html#ID-102161490 DOM Level 3 Core
 * @see https://dom.spec.whatwg.org/#domimplementation DOM Living Standard
 */
function DOMImplementation() {
}

DOMImplementation.prototype = {
	/**
	 * The DOMImplementation.hasFeature() method returns a Boolean flag indicating if a given feature is supported.
	 * The different implementations fairly diverged in what kind of features were reported.
	 * The latest version of the spec settled to force this method to always return true, where the functionality was accurate and in use.
	 *
	 * @deprecated It is deprecated and modern browsers return true in all cases.
	 *
	 * @param {string} feature
	 * @param {string} [version]
	 * @returns {boolean} always true
	 *
	 * @see https://developer.mozilla.org/en-US/docs/Web/API/DOMImplementation/hasFeature MDN
	 * @see https://www.w3.org/TR/REC-DOM-Level-1/level-one-core.html#ID-5CED94D7 DOM Level 1 Core
	 * @see https://dom.spec.whatwg.org/#dom-domimplementation-hasfeature DOM Living Standard
	 */
	hasFeature: function(feature, version) {
			return true;
	},
	/**
	 * Creates an XML Document object of the specified type with its document element.
	 *
	 * __It behaves slightly different from the description in the living standard__:
	 * - There is no interface/class `XMLDocument`, it returns a `Document` instance.
	 * - `contentType`, `encoding`, `mode`, `origin`, `url` fields are currently not declared.
	 * - this implementation is not validating names or qualified names
	 *   (when parsing XML strings, the SAX parser takes care of that)
	 *
	 * @param {string|null} namespaceURI
	 * @param {string} qualifiedName
	 * @param {DocumentType=null} doctype
	 * @returns {Document}
	 *
	 * @see https://developer.mozilla.org/en-US/docs/Web/API/DOMImplementation/createDocument MDN
	 * @see https://www.w3.org/TR/DOM-Level-2-Core/core.html#Level-2-Core-DOM-createDocument DOM Level 2 Core (initial)
	 * @see https://dom.spec.whatwg.org/#dom-domimplementation-createdocument  DOM Level 2 Core
	 *
	 * @see https://dom.spec.whatwg.org/#validate-and-extract DOM: Validate and extract
	 * @see https://www.w3.org/TR/xml/#NT-NameStartChar XML Spec: Names
	 * @see https://www.w3.org/TR/xml-names/#ns-qualnames XML Namespaces: Qualified names
	 */
	createDocument: function(namespaceURI,  qualifiedName, doctype){
		var doc = new Document();
		doc.implementation = this;
		doc.childNodes = new NodeList();
		doc.doctype = doctype || null;
		if (doctype){
			doc.appendChild(doctype);
		}
		if (qualifiedName){
			var root = doc.createElementNS(namespaceURI, qualifiedName);
			doc.appendChild(root);
		}
		return doc;
	},
	/**
	 * Returns a doctype, with the given `qualifiedName`, `publicId`, and `systemId`.
	 *
	 * __This behavior is slightly different from the in the specs__:
	 * - this implementation is not validating names or qualified names
	 *   (when parsing XML strings, the SAX parser takes care of that)
	 *
	 * @param {string} qualifiedName
	 * @param {string} [publicId]
	 * @param {string} [systemId]
	 * @returns {DocumentType} which can either be used with `DOMImplementation.createDocument` upon document creation
	 * 				  or can be put into the document via methods like `Node.insertBefore()` or `Node.replaceChild()`
	 *
	 * @see https://developer.mozilla.org/en-US/docs/Web/API/DOMImplementation/createDocumentType MDN
	 * @see https://www.w3.org/TR/DOM-Level-2-Core/core.html#Level-2-Core-DOM-createDocType DOM Level 2 Core
	 * @see https://dom.spec.whatwg.org/#dom-domimplementation-createdocumenttype DOM Living Standard
	 *
	 * @see https://dom.spec.whatwg.org/#validate-and-extract DOM: Validate and extract
	 * @see https://www.w3.org/TR/xml/#NT-NameStartChar XML Spec: Names
	 * @see https://www.w3.org/TR/xml-names/#ns-qualnames XML Namespaces: Qualified names
	 */
	createDocumentType: function(qualifiedName, publicId, systemId){
		var node = new DocumentType();
		node.name = qualifiedName;
		node.nodeName = qualifiedName;
		node.publicId = publicId || '';
		node.systemId = systemId || '';

		return node;
	}
};


/**
 * @see http://www.w3.org/TR/2000/REC-DOM-Level-2-Core-20001113/core.html#ID-1950641247
 */

function Node() {
};

Node.prototype = {
	firstChild : null,
	lastChild : null,
	previousSibling : null,
	nextSibling : null,
	attributes : null,
	parentNode : null,
	childNodes : null,
	ownerDocument : null,
	nodeValue : null,
	namespaceURI : null,
	prefix : null,
	localName : null,
	// Modified in DOM Level 2:
	insertBefore:function(newChild, refChild){//raises
		return _insertBefore(this,newChild,refChild);
	},
	replaceChild:function(newChild, oldChild){//raises
		_insertBefore(this, newChild,oldChild, assertPreReplacementValidityInDocument);
		if(oldChild){
			this.removeChild(oldChild);
		}
	},
	removeChild:function(oldChild){
		return _removeChild(this,oldChild);
	},
	appendChild:function(newChild){
		return this.insertBefore(newChild,null);
	},
	hasChildNodes:function(){
		return this.firstChild != null;
	},
	cloneNode:function(deep){
		return cloneNode(this.ownerDocument||this,this,deep);
	},
	// Modified in DOM Level 2:
	normalize:function(){
		var child = this.firstChild;
		while(child){
			var next = child.nextSibling;
			if(next && next.nodeType == TEXT_NODE && child.nodeType == TEXT_NODE){
				this.removeChild(next);
				child.appendData(next.data);
			}else{
				child.normalize();
				child = next;
			}
		}
	},
  	// Introduced in DOM Level 2:
	isSupported:function(feature, version){
		return this.ownerDocument.implementation.hasFeature(feature,version);
	},
    // Introduced in DOM Level 2:
    hasAttributes:function(){
    	return this.attributes.length>0;
    },
	/**
	 * Look up the prefix associated to the given namespace URI, starting from this node.
	 * **The default namespace declarations are ignored by this method.**
	 * See Namespace Prefix Lookup for details on the algorithm used by this method.
	 *
	 * _Note: The implementation seems to be incomplete when compared to the algorithm described in the specs._
	 *
	 * @param {string | null} namespaceURI
	 * @returns {string | null}
	 * @see https://www.w3.org/TR/DOM-Level-3-Core/core.html#Node3-lookupNamespacePrefix
	 * @see https://www.w3.org/TR/DOM-Level-3-Core/namespaces-algorithms.html#lookupNamespacePrefixAlgo
	 * @see https://dom.spec.whatwg.org/#dom-node-lookupprefix
	 * @see https://github.com/xmldom/xmldom/issues/322
	 */
    lookupPrefix:function(namespaceURI){
    	var el = this;
    	while(el){
    		var map = el._nsMap;
    		//console.dir(map)
    		if(map){
    			for(var n in map){
						if (Object.prototype.hasOwnProperty.call(map, n) && map[n] === namespaceURI) {
							return n;
						}
    			}
    		}
    		el = el.nodeType == ATTRIBUTE_NODE?el.ownerDocument : el.parentNode;
    	}
    	return null;
    },
    // Introduced in DOM Level 3:
    lookupNamespaceURI:function(prefix){
    	var el = this;
    	while(el){
    		var map = el._nsMap;
    		//console.dir(map)
    		if(map){
    			if(Object.prototype.hasOwnProperty.call(map, prefix)){
    				return map[prefix] ;
    			}
    		}
    		el = el.nodeType == ATTRIBUTE_NODE?el.ownerDocument : el.parentNode;
    	}
    	return null;
    },
    // Introduced in DOM Level 3:
    isDefaultNamespace:function(namespaceURI){
    	var prefix = this.lookupPrefix(namespaceURI);
    	return prefix == null;
    }
};


function _xmlEncoder(c){
	return c == '<' && '&lt;' ||
         c == '>' && '&gt;' ||
         c == '&' && '&amp;' ||
         c == '"' && '&quot;' ||
         '&#'+c.charCodeAt()+';'
}


copy(NodeType,Node);
copy(NodeType,Node.prototype);

/**
 * @param callback return true for continue,false for break
 * @return boolean true: break visit;
 */
function _visitNode(node,callback){
	if(callback(node)){
		return true;
	}
	if(node = node.firstChild){
		do{
			if(_visitNode(node,callback)){return true}
        }while(node=node.nextSibling)
    }
}



function Document(){
	this.ownerDocument = this;
}

function _onAddAttribute(doc,el,newAttr){
	doc && doc._inc++;
	var ns = newAttr.namespaceURI ;
	if(ns === NAMESPACE.XMLNS){
		//update namespace
		el._nsMap[newAttr.prefix?newAttr.localName:''] = newAttr.value
	}
}

function _onRemoveAttribute(doc,el,newAttr,remove){
	doc && doc._inc++;
	var ns = newAttr.namespaceURI ;
	if(ns === NAMESPACE.XMLNS){
		//update namespace
		delete el._nsMap[newAttr.prefix?newAttr.localName:'']
	}
}

/**
 * Updates `el.childNodes`, updating the indexed items and it's `length`.
 * Passing `newChild` means it will be appended.
 * Otherwise it's assumed that an item has been removed,
 * and `el.firstNode` and it's `.nextSibling` are used
 * to walk the current list of child nodes.
 *
 * @param {Document} doc
 * @param {Node} el
 * @param {Node} [newChild]
 * @private
 */
function _onUpdateChild (doc, el, newChild) {
	if(doc && doc._inc){
		doc._inc++;
		//update childNodes
		var cs = el.childNodes;
		if (newChild) {
			cs[cs.length++] = newChild;
		} else {
			var child = el.firstChild;
			var i = 0;
			while (child) {
				cs[i++] = child;
				child = child.nextSibling;
			}
			cs.length = i;
			delete cs[cs.length];
		}
	}
}

/**
 * Removes the connections between `parentNode` and `child`
 * and any existing `child.previousSibling` or `child.nextSibling`.
 *
 * @see https://github.com/xmldom/xmldom/issues/135
 * @see https://github.com/xmldom/xmldom/issues/145
 *
 * @param {Node} parentNode
 * @param {Node} child
 * @returns {Node} the child that was removed.
 * @private
 */
function _removeChild (parentNode, child) {
	var previous = child.previousSibling;
	var next = child.nextSibling;
	if (previous) {
		previous.nextSibling = next;
	} else {
		parentNode.firstChild = next;
	}
	if (next) {
		next.previousSibling = previous;
	} else {
		parentNode.lastChild = previous;
	}
	child.parentNode = null;
	child.previousSibling = null;
	child.nextSibling = null;
	_onUpdateChild(parentNode.ownerDocument, parentNode);
	return child;
}

/**
 * Returns `true` if `node` can be a parent for insertion.
 * @param {Node} node
 * @returns {boolean}
 */
function hasValidParentNodeType(node) {
	return (
		node &&
		(node.nodeType === Node.DOCUMENT_NODE || node.nodeType === Node.DOCUMENT_FRAGMENT_NODE || node.nodeType === Node.ELEMENT_NODE)
	);
}

/**
 * Returns `true` if `node` can be inserted according to it's `nodeType`.
 * @param {Node} node
 * @returns {boolean}
 */
function hasInsertableNodeType(node) {
	return (
		node &&
		(isElementNode(node) ||
			isTextNode(node) ||
			isDocTypeNode(node) ||
			node.nodeType === Node.DOCUMENT_FRAGMENT_NODE ||
			node.nodeType === Node.COMMENT_NODE ||
			node.nodeType === Node.PROCESSING_INSTRUCTION_NODE)
	);
}

/**
 * Returns true if `node` is a DOCTYPE node
 * @param {Node} node
 * @returns {boolean}
 */
function isDocTypeNode(node) {
	return node && node.nodeType === Node.DOCUMENT_TYPE_NODE;
}

/**
 * Returns true if the node is an element
 * @param {Node} node
 * @returns {boolean}
 */
function isElementNode(node) {
	return node && node.nodeType === Node.ELEMENT_NODE;
}
/**
 * Returns true if `node` is a text node
 * @param {Node} node
 * @returns {boolean}
 */
function isTextNode(node) {
	return node && node.nodeType === Node.TEXT_NODE;
}

/**
 * Check if en element node can be inserted before `child`, or at the end if child is falsy,
 * according to the presence and position of a doctype node on the same level.
 *
 * @param {Document} doc The document node
 * @param {Node} child the node that would become the nextSibling if the element would be inserted
 * @returns {boolean} `true` if an element can be inserted before child
 * @private
 * https://dom.spec.whatwg.org/#concept-node-ensure-pre-insertion-validity
 */
function isElementInsertionPossible(doc, child) {
	var parentChildNodes = doc.childNodes || [];
	if (find(parentChildNodes, isElementNode) || isDocTypeNode(child)) {
		return false;
	}
	var docTypeNode = find(parentChildNodes, isDocTypeNode);
	return !(child && docTypeNode && parentChildNodes.indexOf(docTypeNode) > parentChildNodes.indexOf(child));
}

/**
 * Check if en element node can be inserted before `child`, or at the end if child is falsy,
 * according to the presence and position of a doctype node on the same level.
 *
 * @param {Node} doc The document node
 * @param {Node} child the node that would become the nextSibling if the element would be inserted
 * @returns {boolean} `true` if an element can be inserted before child
 * @private
 * https://dom.spec.whatwg.org/#concept-node-ensure-pre-insertion-validity
 */
function isElementReplacementPossible(doc, child) {
	var parentChildNodes = doc.childNodes || [];

	function hasElementChildThatIsNotChild(node) {
		return isElementNode(node) && node !== child;
	}

	if (find(parentChildNodes, hasElementChildThatIsNotChild)) {
		return false;
	}
	var docTypeNode = find(parentChildNodes, isDocTypeNode);
	return !(child && docTypeNode && parentChildNodes.indexOf(docTypeNode) > parentChildNodes.indexOf(child));
}

/**
 * @private
 * Steps 1-5 of the checks before inserting and before replacing a child are the same.
 *
 * @param {Node} parent the parent node to insert `node` into
 * @param {Node} node the node to insert
 * @param {Node=} child the node that should become the `nextSibling` of `node`
 * @returns {Node}
 * @throws DOMException for several node combinations that would create a DOM that is not well-formed.
 * @throws DOMException if `child` is provided but is not a child of `parent`.
 * @see https://dom.spec.whatwg.org/#concept-node-ensure-pre-insertion-validity
 * @see https://dom.spec.whatwg.org/#concept-node-replace
 */
function assertPreInsertionValidity1to5(parent, node, child) {
	// 1. If `parent` is not a Document, DocumentFragment, or Element node, then throw a "HierarchyRequestError" DOMException.
	if (!hasValidParentNodeType(parent)) {
		throw new DOMException(HIERARCHY_REQUEST_ERR, 'Unexpected parent node type ' + parent.nodeType);
	}
	// 2. If `node` is a host-including inclusive ancestor of `parent`, then throw a "HierarchyRequestError" DOMException.
	// not implemented!
	// 3. If `child` is non-null and its parent is not `parent`, then throw a "NotFoundError" DOMException.
	if (child && child.parentNode !== parent) {
		throw new DOMException(NOT_FOUND_ERR, 'child not in parent');
	}
	if (
		// 4. If `node` is not a DocumentFragment, DocumentType, Element, or CharacterData node, then throw a "HierarchyRequestError" DOMException.
		!hasInsertableNodeType(node) ||
		// 5. If either `node` is a Text node and `parent` is a document,
		// the sax parser currently adds top level text nodes, this will be fixed in 0.9.0
		// || (node.nodeType === Node.TEXT_NODE && parent.nodeType === Node.DOCUMENT_NODE)
		// or `node` is a doctype and `parent` is not a document, then throw a "HierarchyRequestError" DOMException.
		(isDocTypeNode(node) && parent.nodeType !== Node.DOCUMENT_NODE)
	) {
		throw new DOMException(
			HIERARCHY_REQUEST_ERR,
			'Unexpected node type ' + node.nodeType + ' for parent node type ' + parent.nodeType
		);
	}
}

/**
 * @private
 * Step 6 of the checks before inserting and before replacing a child are different.
 *
 * @param {Document} parent the parent node to insert `node` into
 * @param {Node} node the node to insert
 * @param {Node | undefined} child the node that should become the `nextSibling` of `node`
 * @returns {Node}
 * @throws DOMException for several node combinations that would create a DOM that is not well-formed.
 * @throws DOMException if `child` is provided but is not a child of `parent`.
 * @see https://dom.spec.whatwg.org/#concept-node-ensure-pre-insertion-validity
 * @see https://dom.spec.whatwg.org/#concept-node-replace
 */
function assertPreInsertionValidityInDocument(parent, node, child) {
	var parentChildNodes = parent.childNodes || [];
	var nodeChildNodes = node.childNodes || [];

	// DocumentFragment
	if (node.nodeType === Node.DOCUMENT_FRAGMENT_NODE) {
		var nodeChildElements = nodeChildNodes.filter(isElementNode);
		// If node has more than one element child or has a Text node child.
		if (nodeChildElements.length > 1 || find(nodeChildNodes, isTextNode)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'More than one element or text in fragment');
		}
		// Otherwise, if `node` has one element child and either `parent` has an element child,
		// `child` is a doctype, or `child` is non-null and a doctype is following `child`.
		if (nodeChildElements.length === 1 && !isElementInsertionPossible(parent, child)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'Element in fragment can not be inserted before doctype');
		}
	}
	// Element
	if (isElementNode(node)) {
		// `parent` has an element child, `child` is a doctype,
		// or `child` is non-null and a doctype is following `child`.
		if (!isElementInsertionPossible(parent, child)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'Only one element can be added and only after doctype');
		}
	}
	// DocumentType
	if (isDocTypeNode(node)) {
		// `parent` has a doctype child,
		if (find(parentChildNodes, isDocTypeNode)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'Only one doctype is allowed');
		}
		var parentElementChild = find(parentChildNodes, isElementNode);
		// `child` is non-null and an element is preceding `child`,
		if (child && parentChildNodes.indexOf(parentElementChild) < parentChildNodes.indexOf(child)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'Doctype can only be inserted before an element');
		}
		// or `child` is null and `parent` has an element child.
		if (!child && parentElementChild) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'Doctype can not be appended since element is present');
		}
	}
}

/**
 * @private
 * Step 6 of the checks before inserting and before replacing a child are different.
 *
 * @param {Document} parent the parent node to insert `node` into
 * @param {Node} node the node to insert
 * @param {Node | undefined} child the node that should become the `nextSibling` of `node`
 * @returns {Node}
 * @throws DOMException for several node combinations that would create a DOM that is not well-formed.
 * @throws DOMException if `child` is provided but is not a child of `parent`.
 * @see https://dom.spec.whatwg.org/#concept-node-ensure-pre-insertion-validity
 * @see https://dom.spec.whatwg.org/#concept-node-replace
 */
function assertPreReplacementValidityInDocument(parent, node, child) {
	var parentChildNodes = parent.childNodes || [];
	var nodeChildNodes = node.childNodes || [];

	// DocumentFragment
	if (node.nodeType === Node.DOCUMENT_FRAGMENT_NODE) {
		var nodeChildElements = nodeChildNodes.filter(isElementNode);
		// If `node` has more than one element child or has a Text node child.
		if (nodeChildElements.length > 1 || find(nodeChildNodes, isTextNode)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'More than one element or text in fragment');
		}
		// Otherwise, if `node` has one element child and either `parent` has an element child that is not `child` or a doctype is following `child`.
		if (nodeChildElements.length === 1 && !isElementReplacementPossible(parent, child)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'Element in fragment can not be inserted before doctype');
		}
	}
	// Element
	if (isElementNode(node)) {
		// `parent` has an element child that is not `child` or a doctype is following `child`.
		if (!isElementReplacementPossible(parent, child)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'Only one element can be added and only after doctype');
		}
	}
	// DocumentType
	if (isDocTypeNode(node)) {
		function hasDoctypeChildThatIsNotChild(node) {
			return isDocTypeNode(node) && node !== child;
		}

		// `parent` has a doctype child that is not `child`,
		if (find(parentChildNodes, hasDoctypeChildThatIsNotChild)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'Only one doctype is allowed');
		}
		var parentElementChild = find(parentChildNodes, isElementNode);
		// or an element is preceding `child`.
		if (child && parentChildNodes.indexOf(parentElementChild) < parentChildNodes.indexOf(child)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'Doctype can only be inserted before an element');
		}
	}
}

/**
 * @private
 * @param {Node} parent the parent node to insert `node` into
 * @param {Node} node the node to insert
 * @param {Node=} child the node that should become the `nextSibling` of `node`
 * @returns {Node}
 * @throws DOMException for several node combinations that would create a DOM that is not well-formed.
 * @throws DOMException if `child` is provided but is not a child of `parent`.
 * @see https://dom.spec.whatwg.org/#concept-node-ensure-pre-insertion-validity
 */
function _insertBefore(parent, node, child, _inDocumentAssertion) {
	// To ensure pre-insertion validity of a node into a parent before a child, run these steps:
	assertPreInsertionValidity1to5(parent, node, child);

	// If parent is a document, and any of the statements below, switched on the interface node implements,
	// are true, then throw a "HierarchyRequestError" DOMException.
	if (parent.nodeType === Node.DOCUMENT_NODE) {
		(_inDocumentAssertion || assertPreInsertionValidityInDocument)(parent, node, child);
	}

	var cp = node.parentNode;
	if(cp){
		cp.removeChild(node);//remove and update
	}
	if(node.nodeType === DOCUMENT_FRAGMENT_NODE){
		var newFirst = node.firstChild;
		if (newFirst == null) {
			return node;
		}
		var newLast = node.lastChild;
	}else{
		newFirst = newLast = node;
	}
	var pre = child ? child.previousSibling : parent.lastChild;

	newFirst.previousSibling = pre;
	newLast.nextSibling = child;


	if(pre){
		pre.nextSibling = newFirst;
	}else{
		parent.firstChild = newFirst;
	}
	if(child == null){
		parent.lastChild = newLast;
	}else{
		child.previousSibling = newLast;
	}
	do{
		newFirst.parentNode = parent;
	}while(newFirst !== newLast && (newFirst= newFirst.nextSibling))
	_onUpdateChild(parent.ownerDocument||parent, parent);
	//console.log(parent.lastChild.nextSibling == null)
	if (node.nodeType == DOCUMENT_FRAGMENT_NODE) {
		node.firstChild = node.lastChild = null;
	}
	return node;
}

/**
 * Appends `newChild` to `parentNode`.
 * If `newChild` is already connected to a `parentNode` it is first removed from it.
 *
 * @see https://github.com/xmldom/xmldom/issues/135
 * @see https://github.com/xmldom/xmldom/issues/145
 * @param {Node} parentNode
 * @param {Node} newChild
 * @returns {Node}
 * @private
 */
function _appendSingleChild (parentNode, newChild) {
	if (newChild.parentNode) {
		newChild.parentNode.removeChild(newChild);
	}
	newChild.parentNode = parentNode;
	newChild.previousSibling = parentNode.lastChild;
	newChild.nextSibling = null;
	if (newChild.previousSibling) {
		newChild.previousSibling.nextSibling = newChild;
	} else {
		parentNode.firstChild = newChild;
	}
	parentNode.lastChild = newChild;
	_onUpdateChild(parentNode.ownerDocument, parentNode, newChild);
	return newChild;
}

Document.prototype = {
	//implementation : null,
	nodeName :  '#document',
	nodeType :  DOCUMENT_NODE,
	/**
	 * The DocumentType node of the document.
	 *
	 * @readonly
	 * @type DocumentType
	 */
	doctype :  null,
	documentElement :  null,
	_inc : 1,

	insertBefore :  function(newChild, refChild){//raises
		if(newChild.nodeType == DOCUMENT_FRAGMENT_NODE){
			var child = newChild.firstChild;
			while(child){
				var next = child.nextSibling;
				this.insertBefore(child,refChild);
				child = next;
			}
			return newChild;
		}
		_insertBefore(this, newChild, refChild);
		newChild.ownerDocument = this;
		if (this.documentElement === null && newChild.nodeType === ELEMENT_NODE) {
			this.documentElement = newChild;
		}

		return newChild;
	},
	removeChild :  function(oldChild){
		if(this.documentElement == oldChild){
			this.documentElement = null;
		}
		return _removeChild(this,oldChild);
	},
	replaceChild: function (newChild, oldChild) {
		//raises
		_insertBefore(this, newChild, oldChild, assertPreReplacementValidityInDocument);
		newChild.ownerDocument = this;
		if (oldChild) {
			this.removeChild(oldChild);
		}
		if (isElementNode(newChild)) {
			this.documentElement = newChild;
		}
	},
	// Introduced in DOM Level 2:
	importNode : function(importedNode,deep){
		return importNode(this,importedNode,deep);
	},
	// Introduced in DOM Level 2:
	getElementById :	function(id){
		var rtv = null;
		_visitNode(this.documentElement,function(node){
			if(node.nodeType == ELEMENT_NODE){
				if(node.getAttribute('id') == id){
					rtv = node;
					return true;
				}
			}
		})
		return rtv;
	},

	/**
	 * The `getElementsByClassName` method of `Document` interface returns an array-like object
	 * of all child elements which have **all** of the given class name(s).
	 *
	 * Returns an empty list if `classeNames` is an empty string or only contains HTML white space characters.
	 *
	 *
	 * Warning: This is a live LiveNodeList.
	 * Changes in the DOM will reflect in the array as the changes occur.
	 * If an element selected by this array no longer qualifies for the selector,
	 * it will automatically be removed. Be aware of this for iteration purposes.
	 *
	 * @param {string} classNames is a string representing the class name(s) to match; multiple class names are separated by (ASCII-)whitespace
	 *
	 * @see https://developer.mozilla.org/en-US/docs/Web/API/Document/getElementsByClassName
	 * @see https://dom.spec.whatwg.org/#concept-getelementsbyclassname
	 */
	getElementsByClassName: function(classNames) {
		var classNamesSet = toOrderedSet(classNames)
		return new LiveNodeList(this, function(base) {
			var ls = [];
			if (classNamesSet.length > 0) {
				_visitNode(base.documentElement, function(node) {
					if(node !== base && node.nodeType === ELEMENT_NODE) {
						var nodeClassNames = node.getAttribute('class')
						// can be null if the attribute does not exist
						if (nodeClassNames) {
							// before splitting and iterating just compare them for the most common case
							var matches = classNames === nodeClassNames;
							if (!matches) {
								var nodeClassNamesSet = toOrderedSet(nodeClassNames)
								matches = classNamesSet.every(arrayIncludes(nodeClassNamesSet))
							}
							if(matches) {
								ls.push(node);
							}
						}
					}
				});
			}
			return ls;
		});
	},

	//document factory method:
	createElement :	function(tagName){
		var node = new Element();
		node.ownerDocument = this;
		node.nodeName = tagName;
		node.tagName = tagName;
		node.localName = tagName;
		node.childNodes = new NodeList();
		var attrs	= node.attributes = new NamedNodeMap();
		attrs._ownerElement = node;
		return node;
	},
	createDocumentFragment :	function(){
		var node = new DocumentFragment();
		node.ownerDocument = this;
		node.childNodes = new NodeList();
		return node;
	},
	createTextNode :	function(data){
		var node = new Text();
		node.ownerDocument = this;
		node.appendData(data)
		return node;
	},
	createComment :	function(data){
		var node = new Comment();
		node.ownerDocument = this;
		node.appendData(data)
		return node;
	},
	createCDATASection :	function(data){
		var node = new CDATASection();
		node.ownerDocument = this;
		node.appendData(data)
		return node;
	},
	createProcessingInstruction :	function(target,data){
		var node = new ProcessingInstruction();
		node.ownerDocument = this;
		node.tagName = node.target = target;
		node.nodeValue= node.data = data;
		return node;
	},
	createAttribute :	function(name){
		var node = new Attr();
		node.ownerDocument	= this;
		node.name = name;
		node.nodeName	= name;
		node.localName = name;
		node.specified = true;
		return node;
	},
	createEntityReference :	function(name){
		var node = new EntityReference();
		node.ownerDocument	= this;
		node.nodeName	= name;
		return node;
	},
	// Introduced in DOM Level 2:
	createElementNS :	function(namespaceURI,qualifiedName){
		var node = new Element();
		var pl = qualifiedName.split(':');
		var attrs	= node.attributes = new NamedNodeMap();
		node.childNodes = new NodeList();
		node.ownerDocument = this;
		node.nodeName = qualifiedName;
		node.tagName = qualifiedName;
		node.namespaceURI = namespaceURI;
		if(pl.length == 2){
			node.prefix = pl[0];
			node.localName = pl[1];
		}else{
			//el.prefix = null;
			node.localName = qualifiedName;
		}
		attrs._ownerElement = node;
		return node;
	},
	// Introduced in DOM Level 2:
	createAttributeNS :	function(namespaceURI,qualifiedName){
		var node = new Attr();
		var pl = qualifiedName.split(':');
		node.ownerDocument = this;
		node.nodeName = qualifiedName;
		node.name = qualifiedName;
		node.namespaceURI = namespaceURI;
		node.specified = true;
		if(pl.length == 2){
			node.prefix = pl[0];
			node.localName = pl[1];
		}else{
			//el.prefix = null;
			node.localName = qualifiedName;
		}
		return node;
	}
};
_extends(Document,Node);


function Element() {
	this._nsMap = {};
};
Element.prototype = {
	nodeType : ELEMENT_NODE,
	hasAttribute : function(name){
		return this.getAttributeNode(name)!=null;
	},
	getAttribute : function(name){
		var attr = this.getAttributeNode(name);
		return attr && attr.value || '';
	},
	getAttributeNode : function(name){
		return this.attributes.getNamedItem(name);
	},
	setAttribute : function(name, value){
		var attr = this.ownerDocument.createAttribute(name);
		attr.value = attr.nodeValue = "" + value;
		this.setAttributeNode(attr)
	},
	removeAttribute : function(name){
		var attr = this.getAttributeNode(name)
		attr && this.removeAttributeNode(attr);
	},

	//four real opeartion method
	appendChild:function(newChild){
		if(newChild.nodeType === DOCUMENT_FRAGMENT_NODE){
			return this.insertBefore(newChild,null);
		}else{
			return _appendSingleChild(this,newChild);
		}
	},
	setAttributeNode : function(newAttr){
		return this.attributes.setNamedItem(newAttr);
	},
	setAttributeNodeNS : function(newAttr){
		return this.attributes.setNamedItemNS(newAttr);
	},
	removeAttributeNode : function(oldAttr){
		//console.log(this == oldAttr.ownerElement)
		return this.attributes.removeNamedItem(oldAttr.nodeName);
	},
	//get real attribute name,and remove it by removeAttributeNode
	removeAttributeNS : function(namespaceURI, localName){
		var old = this.getAttributeNodeNS(namespaceURI, localName);
		old && this.removeAttributeNode(old);
	},

	hasAttributeNS : function(namespaceURI, localName){
		return this.getAttributeNodeNS(namespaceURI, localName)!=null;
	},
	getAttributeNS : function(namespaceURI, localName){
		var attr = this.getAttributeNodeNS(namespaceURI, localName);
		return attr && attr.value || '';
	},
	setAttributeNS : function(namespaceURI, qualifiedName, value){
		var attr = this.ownerDocument.createAttributeNS(namespaceURI, qualifiedName);
		attr.value = attr.nodeValue = "" + value;
		this.setAttributeNode(attr)
	},
	getAttributeNodeNS : function(namespaceURI, localName){
		return this.attributes.getNamedItemNS(namespaceURI, localName);
	},

	getElementsByTagName : function(tagName){
		return new LiveNodeList(this,function(base){
			var ls = [];
			_visitNode(base,function(node){
				if(node !== base && node.nodeType == ELEMENT_NODE && (tagName === '*' || node.tagName == tagName)){
					ls.push(node);
				}
			});
			return ls;
		});
	},
	getElementsByTagNameNS : function(namespaceURI, localName){
		return new LiveNodeList(this,function(base){
			var ls = [];
			_visitNode(base,function(node){
				if(node !== base && node.nodeType === ELEMENT_NODE && (namespaceURI === '*' || node.namespaceURI === namespaceURI) && (localName === '*' || node.localName == localName)){
					ls.push(node);
				}
			});
			return ls;

		});
	}
};
Document.prototype.getElementsByTagName = Element.prototype.getElementsByTagName;
Document.prototype.getElementsByTagNameNS = Element.prototype.getElementsByTagNameNS;


_extends(Element,Node);
function Attr() {
};
Attr.prototype.nodeType = ATTRIBUTE_NODE;
_extends(Attr,Node);


function CharacterData() {
};
CharacterData.prototype = {
	data : '',
	substringData : function(offset, count) {
		return this.data.substring(offset, offset+count);
	},
	appendData: function(text) {
		text = this.data+text;
		this.nodeValue = this.data = text;
		this.length = text.length;
	},
	insertData: function(offset,text) {
		this.replaceData(offset,0,text);

	},
	appendChild:function(newChild){
		throw new Error(ExceptionMessage[HIERARCHY_REQUEST_ERR])
	},
	deleteData: function(offset, count) {
		this.replaceData(offset,count,"");
	},
	replaceData: function(offset, count, text) {
		var start = this.data.substring(0,offset);
		var end = this.data.substring(offset+count);
		text = start + text + end;
		this.nodeValue = this.data = text;
		this.length = text.length;
	}
}
_extends(CharacterData,Node);
function Text() {
};
Text.prototype = {
	nodeName : "#text",
	nodeType : TEXT_NODE,
	splitText : function(offset) {
		var text = this.data;
		var newText = text.substring(offset);
		text = text.substring(0, offset);
		this.data = this.nodeValue = text;
		this.length = text.length;
		var newNode = this.ownerDocument.createTextNode(newText);
		if(this.parentNode){
			this.parentNode.insertBefore(newNode, this.nextSibling);
		}
		return newNode;
	}
}
_extends(Text,CharacterData);
function Comment() {
};
Comment.prototype = {
	nodeName : "#comment",
	nodeType : COMMENT_NODE
}
_extends(Comment,CharacterData);

function CDATASection() {
};
CDATASection.prototype = {
	nodeName : "#cdata-section",
	nodeType : CDATA_SECTION_NODE
}
_extends(CDATASection,CharacterData);


function DocumentType() {
};
DocumentType.prototype.nodeType = DOCUMENT_TYPE_NODE;
_extends(DocumentType,Node);

function Notation() {
};
Notation.prototype.nodeType = NOTATION_NODE;
_extends(Notation,Node);

function Entity() {
};
Entity.prototype.nodeType = ENTITY_NODE;
_extends(Entity,Node);

function EntityReference() {
};
EntityReference.prototype.nodeType = ENTITY_REFERENCE_NODE;
_extends(EntityReference,Node);

function DocumentFragment() {
};
DocumentFragment.prototype.nodeName =	"#document-fragment";
DocumentFragment.prototype.nodeType =	DOCUMENT_FRAGMENT_NODE;
_extends(DocumentFragment,Node);


function ProcessingInstruction() {
}
ProcessingInstruction.prototype.nodeType = PROCESSING_INSTRUCTION_NODE;
_extends(ProcessingInstruction,Node);
function XMLSerializer(){}
XMLSerializer.prototype.serializeToString = function(node,isHtml,nodeFilter){
	return nodeSerializeToString.call(node,isHtml,nodeFilter);
}
Node.prototype.toString = nodeSerializeToString;
function nodeSerializeToString(isHtml,nodeFilter){
	var buf = [];
	var refNode = this.nodeType == 9 && this.documentElement || this;
	var prefix = refNode.prefix;
	var uri = refNode.namespaceURI;

	if(uri && prefix == null){
		//console.log(prefix)
		var prefix = refNode.lookupPrefix(uri);
		if(prefix == null){
			//isHTML = true;
			var visibleNamespaces=[
			{namespace:uri,prefix:null}
			//{namespace:uri,prefix:''}
			]
		}
	}
	serializeToString(this,buf,isHtml,nodeFilter,visibleNamespaces);
	//console.log('###',this.nodeType,uri,prefix,buf.join(''))
	return buf.join('');
}

function needNamespaceDefine(node, isHTML, visibleNamespaces) {
	var prefix = node.prefix || '';
	var uri = node.namespaceURI;
	// According to [Namespaces in XML 1.0](https://www.w3.org/TR/REC-xml-names/#ns-using) ,
	// and more specifically https://www.w3.org/TR/REC-xml-names/#nsc-NoPrefixUndecl :
	// > In a namespace declaration for a prefix [...], the attribute value MUST NOT be empty.
	// in a similar manner [Namespaces in XML 1.1](https://www.w3.org/TR/xml-names11/#ns-using)
	// and more specifically https://www.w3.org/TR/xml-names11/#nsc-NSDeclared :
	// > [...] Furthermore, the attribute value [...] must not be an empty string.
	// so serializing empty namespace value like xmlns:ds="" would produce an invalid XML document.
	if (!uri) {
		return false;
	}
	if (prefix === "xml" && uri === NAMESPACE.XML || uri === NAMESPACE.XMLNS) {
		return false;
	}

	var i = visibleNamespaces.length
	while (i--) {
		var ns = visibleNamespaces[i];
		// get namespace prefix
		if (ns.prefix === prefix) {
			return ns.namespace !== uri;
		}
	}
	return true;
}
/**
 * Well-formed constraint: No < in Attribute Values
 * > The replacement text of any entity referred to directly or indirectly
 * > in an attribute value must not contain a <.
 * @see https://www.w3.org/TR/xml11/#CleanAttrVals
 * @see https://www.w3.org/TR/xml11/#NT-AttValue
 *
 * Literal whitespace other than space that appear in attribute values
 * are serialized as their entity references, so they will be preserved.
 * (In contrast to whitespace literals in the input which are normalized to spaces)
 * @see https://www.w3.org/TR/xml11/#AVNormalize
 * @see https://w3c.github.io/DOM-Parsing/#serializing-an-element-s-attributes
 */
function addSerializedAttribute(buf, qualifiedName, value) {
	buf.push(' ', qualifiedName, '="', value.replace(/[<>&"\t\n\r]/g, _xmlEncoder), '"')
}

function serializeToString(node,buf,isHTML,nodeFilter,visibleNamespaces){
	if (!visibleNamespaces) {
		visibleNamespaces = [];
	}

	if(nodeFilter){
		node = nodeFilter(node);
		if(node){
			if(typeof node == 'string'){
				buf.push(node);
				return;
			}
		}else{
			return;
		}
		//buf.sort.apply(attrs, attributeSorter);
	}

	switch(node.nodeType){
	case ELEMENT_NODE:
		var attrs = node.attributes;
		var len = attrs.length;
		var child = node.firstChild;
		var nodeName = node.tagName;

		isHTML = NAMESPACE.isHTML(node.namespaceURI) || isHTML

		var prefixedNodeName = nodeName
		if (!isHTML && !node.prefix && node.namespaceURI) {
			var defaultNS
			// lookup current default ns from `xmlns` attribute
			for (var ai = 0; ai < attrs.length; ai++) {
				if (attrs.item(ai).name === 'xmlns') {
					defaultNS = attrs.item(ai).value
					break
				}
			}
			if (!defaultNS) {
				// lookup current default ns in visibleNamespaces
				for (var nsi = visibleNamespaces.length - 1; nsi >= 0; nsi--) {
					var namespace = visibleNamespaces[nsi]
					if (namespace.prefix === '' && namespace.namespace === node.namespaceURI) {
						defaultNS = namespace.namespace
						break
					}
				}
			}
			if (defaultNS !== node.namespaceURI) {
				for (var nsi = visibleNamespaces.length - 1; nsi >= 0; nsi--) {
					var namespace = visibleNamespaces[nsi]
					if (namespace.namespace === node.namespaceURI) {
						if (namespace.prefix) {
							prefixedNodeName = namespace.prefix + ':' + nodeName
						}
						break
					}
				}
			}
		}

		buf.push('<', prefixedNodeName);

		for(var i=0;i<len;i++){
			// add namespaces for attributes
			var attr = attrs.item(i);
			if (attr.prefix == 'xmlns') {
				visibleNamespaces.push({ prefix: attr.localName, namespace: attr.value });
			}else if(attr.nodeName == 'xmlns'){
				visibleNamespaces.push({ prefix: '', namespace: attr.value });
			}
		}

		for(var i=0;i<len;i++){
			var attr = attrs.item(i);
			if (needNamespaceDefine(attr,isHTML, visibleNamespaces)) {
				var prefix = attr.prefix||'';
				var uri = attr.namespaceURI;
				addSerializedAttribute(buf, prefix ? 'xmlns:' + prefix : "xmlns", uri);
				visibleNamespaces.push({ prefix: prefix, namespace:uri });
			}
			serializeToString(attr,buf,isHTML,nodeFilter,visibleNamespaces);
		}

		// add namespace for current node
		if (nodeName === prefixedNodeName && needNamespaceDefine(node, isHTML, visibleNamespaces)) {
			var prefix = node.prefix||'';
			var uri = node.namespaceURI;
			addSerializedAttribute(buf, prefix ? 'xmlns:' + prefix : "xmlns", uri);
			visibleNamespaces.push({ prefix: prefix, namespace:uri });
		}

		if(child || isHTML && !/^(?:meta|link|img|br|hr|input)$/i.test(nodeName)){
			buf.push('>');
			//if is cdata child node
			if(isHTML && /^script$/i.test(nodeName)){
				while(child){
					if(child.data){
						buf.push(child.data);
					}else{
						serializeToString(child, buf, isHTML, nodeFilter, visibleNamespaces.slice());
					}
					child = child.nextSibling;
				}
			}else
			{
				while(child){
					serializeToString(child, buf, isHTML, nodeFilter, visibleNamespaces.slice());
					child = child.nextSibling;
				}
			}
			buf.push('</',prefixedNodeName,'>');
		}else{
			buf.push('/>');
		}
		// remove added visible namespaces
		//visibleNamespaces.length = startVisibleNamespaces;
		return;
	case DOCUMENT_NODE:
	case DOCUMENT_FRAGMENT_NODE:
		var child = node.firstChild;
		while(child){
			serializeToString(child, buf, isHTML, nodeFilter, visibleNamespaces.slice());
			child = child.nextSibling;
		}
		return;
	case ATTRIBUTE_NODE:
		return addSerializedAttribute(buf, node.name, node.value);
	case TEXT_NODE:
		/**
		 * The ampersand character (&) and the left angle bracket (<) must not appear in their literal form,
		 * except when used as markup delimiters, or within a comment, a processing instruction, or a CDATA section.
		 * If they are needed elsewhere, they must be escaped using either numeric character references or the strings
		 * `&amp;` and `&lt;` respectively.
		 * The right angle bracket (>) may be represented using the string " &gt; ", and must, for compatibility,
		 * be escaped using either `&gt;` or a character reference when it appears in the string `]]>` in content,
		 * when that string is not marking the end of a CDATA section.
		 *
		 * In the content of elements, character data is any string of characters
		 * which does not contain the start-delimiter of any markup
		 * and does not include the CDATA-section-close delimiter, `]]>`.
		 *
		 * @see https://www.w3.org/TR/xml/#NT-CharData
		 * @see https://w3c.github.io/DOM-Parsing/#xml-serializing-a-text-node
		 */
		return buf.push(node.data
			.replace(/[<&>]/g,_xmlEncoder)
		);
	case CDATA_SECTION_NODE:
		return buf.push( '<![CDATA[',node.data,']]>');
	case COMMENT_NODE:
		return buf.push( "<!--",node.data,"-->");
	case DOCUMENT_TYPE_NODE:
		var pubid = node.publicId;
		var sysid = node.systemId;
		buf.push('<!DOCTYPE ',node.name);
		if(pubid){
			buf.push(' PUBLIC ', pubid);
			if (sysid && sysid!='.') {
				buf.push(' ', sysid);
			}
			buf.push('>');
		}else if(sysid && sysid!='.'){
			buf.push(' SYSTEM ', sysid, '>');
		}else{
			var sub = node.internalSubset;
			if(sub){
				buf.push(" [",sub,"]");
			}
			buf.push(">");
		}
		return;
	case PROCESSING_INSTRUCTION_NODE:
		return buf.push( "<?",node.target," ",node.data,"?>");
	case ENTITY_REFERENCE_NODE:
		return buf.push( '&',node.nodeName,';');
	//case ENTITY_NODE:
	//case NOTATION_NODE:
	default:
		buf.push('??',node.nodeName);
	}
}
function importNode(doc,node,deep){
	var node2;
	switch (node.nodeType) {
	case ELEMENT_NODE:
		node2 = node.cloneNode(false);
		node2.ownerDocument = doc;
		//var attrs = node2.attributes;
		//var len = attrs.length;
		//for(var i=0;i<len;i++){
			//node2.setAttributeNodeNS(importNode(doc,attrs.item(i),deep));
		//}
	case DOCUMENT_FRAGMENT_NODE:
		break;
	case ATTRIBUTE_NODE:
		deep = true;
		break;
	//case ENTITY_REFERENCE_NODE:
	//case PROCESSING_INSTRUCTION_NODE:
	////case TEXT_NODE:
	//case CDATA_SECTION_NODE:
	//case COMMENT_NODE:
	//	deep = false;
	//	break;
	//case DOCUMENT_NODE:
	//case DOCUMENT_TYPE_NODE:
	//cannot be imported.
	//case ENTITY_NODE:
	//case NOTATION_NODE：
	//can not hit in level3
	//default:throw e;
	}
	if(!node2){
		node2 = node.cloneNode(false);//false
	}
	node2.ownerDocument = doc;
	node2.parentNode = null;
	if(deep){
		var child = node.firstChild;
		while(child){
			node2.appendChild(importNode(doc,child,deep));
			child = child.nextSibling;
		}
	}
	return node2;
}
//
//var _relationMap = {firstChild:1,lastChild:1,previousSibling:1,nextSibling:1,
//					attributes:1,childNodes:1,parentNode:1,documentElement:1,doctype,};
function cloneNode(doc,node,deep){
	var node2 = new node.constructor();
	for (var n in node) {
		if (Object.prototype.hasOwnProperty.call(node, n)) {
			var v = node[n];
			if (typeof v != "object") {
				if (v != node2[n]) {
					node2[n] = v;
				}
			}
		}
	}
	if(node.childNodes){
		node2.childNodes = new NodeList();
	}
	node2.ownerDocument = doc;
	switch (node2.nodeType) {
	case ELEMENT_NODE:
		var attrs	= node.attributes;
		var attrs2	= node2.attributes = new NamedNodeMap();
		var len = attrs.length
		attrs2._ownerElement = node2;
		for(var i=0;i<len;i++){
			node2.setAttributeNode(cloneNode(doc,attrs.item(i),true));
		}
		break;;
	case ATTRIBUTE_NODE:
		deep = true;
	}
	if(deep){
		var child = node.firstChild;
		while(child){
			node2.appendChild(cloneNode(doc,child,deep));
			child = child.nextSibling;
		}
	}
	return node2;
}

function __set__(object,key,value){
	object[key] = value
}
//do dynamic
try{
	if(Object.defineProperty){
		Object.defineProperty(LiveNodeList.prototype,'length',{
			get:function(){
				_updateLiveList(this);
				return this.$$length;
			}
		});

		Object.defineProperty(Node.prototype,'textContent',{
			get:function(){
				return getTextContent(this);
			},

			set:function(data){
				switch(this.nodeType){
				case ELEMENT_NODE:
				case DOCUMENT_FRAGMENT_NODE:
					while(this.firstChild){
						this.removeChild(this.firstChild);
					}
					if(data || String(data)){
						this.appendChild(this.ownerDocument.createTextNode(data));
					}
					break;

				default:
					this.data = data;
					this.value = data;
					this.nodeValue = data;
				}
			}
		})

		function getTextContent(node){
			switch(node.nodeType){
			case ELEMENT_NODE:
			case DOCUMENT_FRAGMENT_NODE:
				var buf = [];
				node = node.firstChild;
				while(node){
					if(node.nodeType!==7 && node.nodeType !==8){
						buf.push(getTextContent(node));
					}
					node = node.nextSibling;
				}
				return buf.join('');
			default:
				return node.nodeValue;
			}
		}

		__set__ = function(object,key,value){
			//console.log(value)
			object['$$'+key] = value
		}
	}
}catch(e){//ie8
}

//if(typeof require == 'function'){
	exports.DocumentType = DocumentType;
	exports.DOMException = DOMException;
	exports.DOMImplementation = DOMImplementation;
	exports.Element = Element;
	exports.Node = Node;
	exports.NodeList = NodeList;
	exports.XMLSerializer = XMLSerializer;
//}


/***/ }),

/***/ 8508:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

var freeze = (__nccwpck_require__(9756).freeze);

/**
 * The entities that are predefined in every XML document.
 *
 * @see https://www.w3.org/TR/2006/REC-xml11-20060816/#sec-predefined-ent W3C XML 1.1
 * @see https://www.w3.org/TR/2008/REC-xml-20081126/#sec-predefined-ent W3C XML 1.0
 * @see https://en.wikipedia.org/wiki/List_of_XML_and_HTML_character_entity_references#Predefined_entities_in_XML Wikipedia
 */
exports.XML_ENTITIES = freeze({amp:'&', apos:"'", gt:'>', lt:'<', quot:'"'})

/**
 * A map of currently 241 entities that are detected in an HTML document.
 * They contain all entries from `XML_ENTITIES`.
 *
 * @see XML_ENTITIES
 * @see DOMParser.parseFromString
 * @see DOMImplementation.prototype.createHTMLDocument
 * @see https://html.spec.whatwg.org/#named-character-references WHATWG HTML(5) Spec
 * @see https://www.w3.org/TR/xml-entity-names/ W3C XML Entity Names
 * @see https://www.w3.org/TR/html4/sgml/entities.html W3C HTML4/SGML
 * @see https://en.wikipedia.org/wiki/List_of_XML_and_HTML_character_entity_references#Character_entity_references_in_HTML Wikipedia (HTML)
 * @see https://en.wikipedia.org/wiki/List_of_XML_and_HTML_character_entity_references#Entities_representing_special_characters_in_XHTML Wikpedia (XHTML)
 */
exports.HTML_ENTITIES = freeze({
       lt: '<',
       gt: '>',
       amp: '&',
       quot: '"',
       apos: "'",
       Agrave: "À",
       Aacute: "Á",
       Acirc: "Â",
       Atilde: "Ã",
       Auml: "Ä",
       Aring: "Å",
       AElig: "Æ",
       Ccedil: "Ç",
       Egrave: "È",
       Eacute: "É",
       Ecirc: "Ê",
       Euml: "Ë",
       Igrave: "Ì",
       Iacute: "Í",
       Icirc: "Î",
       Iuml: "Ï",
       ETH: "Ð",
       Ntilde: "Ñ",
       Ograve: "Ò",
       Oacute: "Ó",
       Ocirc: "Ô",
       Otilde: "Õ",
       Ouml: "Ö",
       Oslash: "Ø",
       Ugrave: "Ù",
       Uacute: "Ú",
       Ucirc: "Û",
       Uuml: "Ü",
       Yacute: "Ý",
       THORN: "Þ",
       szlig: "ß",
       agrave: "à",
       aacute: "á",
       acirc: "â",
       atilde: "ã",
       auml: "ä",
       aring: "å",
       aelig: "æ",
       ccedil: "ç",
       egrave: "è",
       eacute: "é",
       ecirc: "ê",
       euml: "ë",
       igrave: "ì",
       iacute: "í",
       icirc: "î",
       iuml: "ï",
       eth: "ð",
       ntilde: "ñ",
       ograve: "ò",
       oacute: "ó",
       ocirc: "ô",
       otilde: "õ",
       ouml: "ö",
       oslash: "ø",
       ugrave: "ù",
       uacute: "ú",
       ucirc: "û",
       uuml: "ü",
       yacute: "ý",
       thorn: "þ",
       yuml: "ÿ",
       nbsp: "\u00a0",
       iexcl: "¡",
       cent: "¢",
       pound: "£",
       curren: "¤",
       yen: "¥",
       brvbar: "¦",
       sect: "§",
       uml: "¨",
       copy: "©",
       ordf: "ª",
       laquo: "«",
       not: "¬",
       shy: "­­",
       reg: "®",
       macr: "¯",
       deg: "°",
       plusmn: "±",
       sup2: "²",
       sup3: "³",
       acute: "´",
       micro: "µ",
       para: "¶",
       middot: "·",
       cedil: "¸",
       sup1: "¹",
       ordm: "º",
       raquo: "»",
       frac14: "¼",
       frac12: "½",
       frac34: "¾",
       iquest: "¿",
       times: "×",
       divide: "÷",
       forall: "∀",
       part: "∂",
       exist: "∃",
       empty: "∅",
       nabla: "∇",
       isin: "∈",
       notin: "∉",
       ni: "∋",
       prod: "∏",
       sum: "∑",
       minus: "−",
       lowast: "∗",
       radic: "√",
       prop: "∝",
       infin: "∞",
       ang: "∠",
       and: "∧",
       or: "∨",
       cap: "∩",
       cup: "∪",
       'int': "∫",
       there4: "∴",
       sim: "∼",
       cong: "≅",
       asymp: "≈",
       ne: "≠",
       equiv: "≡",
       le: "≤",
       ge: "≥",
       sub: "⊂",
       sup: "⊃",
       nsub: "⊄",
       sube: "⊆",
       supe: "⊇",
       oplus: "⊕",
       otimes: "⊗",
       perp: "⊥",
       sdot: "⋅",
       Alpha: "Α",
       Beta: "Β",
       Gamma: "Γ",
       Delta: "Δ",
       Epsilon: "Ε",
       Zeta: "Ζ",
       Eta: "Η",
       Theta: "Θ",
       Iota: "Ι",
       Kappa: "Κ",
       Lambda: "Λ",
       Mu: "Μ",
       Nu: "Ν",
       Xi: "Ξ",
       Omicron: "Ο",
       Pi: "Π",
       Rho: "Ρ",
       Sigma: "Σ",
       Tau: "Τ",
       Upsilon: "Υ",
       Phi: "Φ",
       Chi: "Χ",
       Psi: "Ψ",
       Omega: "Ω",
       alpha: "α",
       beta: "β",
       gamma: "γ",
       delta: "δ",
       epsilon: "ε",
       zeta: "ζ",
       eta: "η",
       theta: "θ",
       iota: "ι",
       kappa: "κ",
       lambda: "λ",
       mu: "μ",
       nu: "ν",
       xi: "ξ",
       omicron: "ο",
       pi: "π",
       rho: "ρ",
       sigmaf: "ς",
       sigma: "σ",
       tau: "τ",
       upsilon: "υ",
       phi: "φ",
       chi: "χ",
       psi: "ψ",
       omega: "ω",
       thetasym: "ϑ",
       upsih: "ϒ",
       piv: "ϖ",
       OElig: "Œ",
       oelig: "œ",
       Scaron: "Š",
       scaron: "š",
       Yuml: "Ÿ",
       fnof: "ƒ",
       circ: "ˆ",
       tilde: "˜",
       ensp: " ",
       emsp: " ",
       thinsp: " ",
       zwnj: "‌",
       zwj: "‍",
       lrm: "‎",
       rlm: "‏",
       ndash: "–",
       mdash: "—",
       lsquo: "‘",
       rsquo: "’",
       sbquo: "‚",
       ldquo: "“",
       rdquo: "”",
       bdquo: "„",
       dagger: "†",
       Dagger: "‡",
       bull: "•",
       hellip: "…",
       permil: "‰",
       prime: "′",
       Prime: "″",
       lsaquo: "‹",
       rsaquo: "›",
       oline: "‾",
       euro: "€",
       trade: "™",
       larr: "←",
       uarr: "↑",
       rarr: "→",
       darr: "↓",
       harr: "↔",
       crarr: "↵",
       lceil: "⌈",
       rceil: "⌉",
       lfloor: "⌊",
       rfloor: "⌋",
       loz: "◊",
       spades: "♠",
       clubs: "♣",
       hearts: "♥",
       diams: "♦"
});

/**
 * @deprecated use `HTML_ENTITIES` instead
 * @see HTML_ENTITIES
 */
exports.entityMap = exports.HTML_ENTITIES


/***/ }),

/***/ 9213:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

var dom = __nccwpck_require__(1389)
exports.DOMImplementation = dom.DOMImplementation
exports.XMLSerializer = dom.XMLSerializer
exports.DOMParser = __nccwpck_require__(5072).DOMParser


/***/ }),

/***/ 6058:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

var NAMESPACE = (__nccwpck_require__(9756).NAMESPACE);

//[4]   	NameStartChar	   ::=   	":" | [A-Z] | "_" | [a-z] | [#xC0-#xD6] | [#xD8-#xF6] | [#xF8-#x2FF] | [#x370-#x37D] | [#x37F-#x1FFF] | [#x200C-#x200D] | [#x2070-#x218F] | [#x2C00-#x2FEF] | [#x3001-#xD7FF] | [#xF900-#xFDCF] | [#xFDF0-#xFFFD] | [#x10000-#xEFFFF]
//[4a]   	NameChar	   ::=   	NameStartChar | "-" | "." | [0-9] | #xB7 | [#x0300-#x036F] | [#x203F-#x2040]
//[5]   	Name	   ::=   	NameStartChar (NameChar)*
var nameStartChar = /[A-Z_a-z\xC0-\xD6\xD8-\xF6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD]///\u10000-\uEFFFF
var nameChar = new RegExp("[\\-\\.0-9"+nameStartChar.source.slice(1,-1)+"\\u00B7\\u0300-\\u036F\\u203F-\\u2040]");
var tagNamePattern = new RegExp('^'+nameStartChar.source+nameChar.source+'*(?:\:'+nameStartChar.source+nameChar.source+'*)?$');
//var tagNamePattern = /^[a-zA-Z_][\w\-\.]*(?:\:[a-zA-Z_][\w\-\.]*)?$/
//var handlers = 'resolveEntity,getExternalSubset,characters,endDocument,endElement,endPrefixMapping,ignorableWhitespace,processingInstruction,setDocumentLocator,skippedEntity,startDocument,startElement,startPrefixMapping,notationDecl,unparsedEntityDecl,error,fatalError,warning,attributeDecl,elementDecl,externalEntityDecl,internalEntityDecl,comment,endCDATA,endDTD,endEntity,startCDATA,startDTD,startEntity'.split(',')

//S_TAG,	S_ATTR,	S_EQ,	S_ATTR_NOQUOT_VALUE
//S_ATTR_SPACE,	S_ATTR_END,	S_TAG_SPACE, S_TAG_CLOSE
var S_TAG = 0;//tag name offerring
var S_ATTR = 1;//attr name offerring
var S_ATTR_SPACE=2;//attr name end and space offer
var S_EQ = 3;//=space?
var S_ATTR_NOQUOT_VALUE = 4;//attr value(no quot value only)
var S_ATTR_END = 5;//attr value end and no space(quot end)
var S_TAG_SPACE = 6;//(attr value end || tag end ) && (space offer)
var S_TAG_CLOSE = 7;//closed el<el />

/**
 * Creates an error that will not be caught by XMLReader aka the SAX parser.
 *
 * @param {string} message
 * @param {any?} locator Optional, can provide details about the location in the source
 * @constructor
 */
function ParseError(message, locator) {
	this.message = message
	this.locator = locator
	if(Error.captureStackTrace) Error.captureStackTrace(this, ParseError);
}
ParseError.prototype = new Error();
ParseError.prototype.name = ParseError.name

function XMLReader(){

}

XMLReader.prototype = {
	parse:function(source,defaultNSMap,entityMap){
		var domBuilder = this.domBuilder;
		domBuilder.startDocument();
		_copy(defaultNSMap ,defaultNSMap = {})
		parse(source,defaultNSMap,entityMap,
				domBuilder,this.errorHandler);
		domBuilder.endDocument();
	}
}
function parse(source,defaultNSMapCopy,entityMap,domBuilder,errorHandler){
	function fixedFromCharCode(code) {
		// String.prototype.fromCharCode does not supports
		// > 2 bytes unicode chars directly
		if (code > 0xffff) {
			code -= 0x10000;
			var surrogate1 = 0xd800 + (code >> 10)
				, surrogate2 = 0xdc00 + (code & 0x3ff);

			return String.fromCharCode(surrogate1, surrogate2);
		} else {
			return String.fromCharCode(code);
		}
	}
	function entityReplacer(a){
		var k = a.slice(1,-1);
		if (Object.hasOwnProperty.call(entityMap, k)) {
			return entityMap[k];
		}else if(k.charAt(0) === '#'){
			return fixedFromCharCode(parseInt(k.substr(1).replace('x','0x')))
		}else{
			errorHandler.error('entity not found:'+a);
			return a;
		}
	}
	function appendText(end){//has some bugs
		if(end>start){
			var xt = source.substring(start,end).replace(/&#?\w+;/g,entityReplacer);
			locator&&position(start);
			domBuilder.characters(xt,0,end-start);
			start = end
		}
	}
	function position(p,m){
		while(p>=lineEnd && (m = linePattern.exec(source))){
			lineStart = m.index;
			lineEnd = lineStart + m[0].length;
			locator.lineNumber++;
			//console.log('line++:',locator,startPos,endPos)
		}
		locator.columnNumber = p-lineStart+1;
	}
	var lineStart = 0;
	var lineEnd = 0;
	var linePattern = /.*(?:\r\n?|\n)|.*$/g
	var locator = domBuilder.locator;

	var parseStack = [{currentNSMap:defaultNSMapCopy}]
	var closeMap = {};
	var start = 0;
	while(true){
		try{
			var tagStart = source.indexOf('<',start);
			if(tagStart<0){
				if(!source.substr(start).match(/^\s*$/)){
					var doc = domBuilder.doc;
	    			var text = doc.createTextNode(source.substr(start));
	    			doc.appendChild(text);
	    			domBuilder.currentElement = text;
				}
				return;
			}
			if(tagStart>start){
				appendText(tagStart);
			}
			switch(source.charAt(tagStart+1)){
			case '/':
				var end = source.indexOf('>',tagStart+3);
				var tagName = source.substring(tagStart + 2, end).replace(/[ \t\n\r]+$/g, '');
				var config = parseStack.pop();
				if(end<0){

	        		tagName = source.substring(tagStart+2).replace(/[\s<].*/,'');
	        		errorHandler.error("end tag name: "+tagName+' is not complete:'+config.tagName);
	        		end = tagStart+1+tagName.length;
	        	}else if(tagName.match(/\s</)){
	        		tagName = tagName.replace(/[\s<].*/,'');
	        		errorHandler.error("end tag name: "+tagName+' maybe not complete');
	        		end = tagStart+1+tagName.length;
				}
				var localNSMap = config.localNSMap;
				var endMatch = config.tagName == tagName;
				var endIgnoreCaseMach = endMatch || config.tagName&&config.tagName.toLowerCase() == tagName.toLowerCase()
		        if(endIgnoreCaseMach){
		        	domBuilder.endElement(config.uri,config.localName,tagName);
					if(localNSMap){
						for (var prefix in localNSMap) {
							if (Object.prototype.hasOwnProperty.call(localNSMap, prefix)) {
								domBuilder.endPrefixMapping(prefix);
							}
						}
					}
					if(!endMatch){
		            	errorHandler.fatalError("end tag name: "+tagName+' is not match the current start tagName:'+config.tagName ); // No known test case
					}
		        }else{
		        	parseStack.push(config)
		        }

				end++;
				break;
				// end elment
			case '?':// <?...?>
				locator&&position(tagStart);
				end = parseInstruction(source,tagStart,domBuilder);
				break;
			case '!':// <!doctype,<![CDATA,<!--
				locator&&position(tagStart);
				end = parseDCC(source,tagStart,domBuilder,errorHandler);
				break;
			default:
				locator&&position(tagStart);
				var el = new ElementAttributes();
				var currentNSMap = parseStack[parseStack.length-1].currentNSMap;
				//elStartEnd
				var end = parseElementStartPart(source,tagStart,el,currentNSMap,entityReplacer,errorHandler);
				var len = el.length;


				if(!el.closed && fixSelfClosed(source,end,el.tagName,closeMap)){
					el.closed = true;
					if(!entityMap.nbsp){
						errorHandler.warning('unclosed xml attribute');
					}
				}
				if(locator && len){
					var locator2 = copyLocator(locator,{});
					//try{//attribute position fixed
					for(var i = 0;i<len;i++){
						var a = el[i];
						position(a.offset);
						a.locator = copyLocator(locator,{});
					}
					domBuilder.locator = locator2
					if(appendElement(el,domBuilder,currentNSMap)){
						parseStack.push(el)
					}
					domBuilder.locator = locator;
				}else{
					if(appendElement(el,domBuilder,currentNSMap)){
						parseStack.push(el)
					}
				}

				if (NAMESPACE.isHTML(el.uri) && !el.closed) {
					end = parseHtmlSpecialContent(source,end,el.tagName,entityReplacer,domBuilder)
				} else {
					end++;
				}
			}
		}catch(e){
			if (e instanceof ParseError) {
				throw e;
			}
			errorHandler.error('element parse error: '+e)
			end = -1;
		}
		if(end>start){
			start = end;
		}else{
			//TODO: 这里有可能sax回退，有位置错误风险
			appendText(Math.max(tagStart,start)+1);
		}
	}
}
function copyLocator(f,t){
	t.lineNumber = f.lineNumber;
	t.columnNumber = f.columnNumber;
	return t;
}

/**
 * @see #appendElement(source,elStartEnd,el,selfClosed,entityReplacer,domBuilder,parseStack);
 * @return end of the elementStartPart(end of elementEndPart for selfClosed el)
 */
function parseElementStartPart(source,start,el,currentNSMap,entityReplacer,errorHandler){

	/**
	 * @param {string} qname
	 * @param {string} value
	 * @param {number} startIndex
	 */
	function addAttribute(qname, value, startIndex) {
		if (el.attributeNames.hasOwnProperty(qname)) {
			errorHandler.fatalError('Attribute ' + qname + ' redefined')
		}
		el.addValue(
			qname,
			// @see https://www.w3.org/TR/xml/#AVNormalize
			// since the xmldom sax parser does not "interpret" DTD the following is not implemented:
			// - recursive replacement of (DTD) entity references
			// - trimming and collapsing multiple spaces into a single one for attributes that are not of type CDATA
			value.replace(/[\t\n\r]/g, ' ').replace(/&#?\w+;/g, entityReplacer),
			startIndex
		)
	}
	var attrName;
	var value;
	var p = ++start;
	var s = S_TAG;//status
	while(true){
		var c = source.charAt(p);
		switch(c){
		case '=':
			if(s === S_ATTR){//attrName
				attrName = source.slice(start,p);
				s = S_EQ;
			}else if(s === S_ATTR_SPACE){
				s = S_EQ;
			}else{
				//fatalError: equal must after attrName or space after attrName
				throw new Error('attribute equal must after attrName'); // No known test case
			}
			break;
		case '\'':
		case '"':
			if(s === S_EQ || s === S_ATTR //|| s == S_ATTR_SPACE
				){//equal
				if(s === S_ATTR){
					errorHandler.warning('attribute value must after "="')
					attrName = source.slice(start,p)
				}
				start = p+1;
				p = source.indexOf(c,start)
				if(p>0){
					value = source.slice(start, p);
					addAttribute(attrName, value, start-1);
					s = S_ATTR_END;
				}else{
					//fatalError: no end quot match
					throw new Error('attribute value no end \''+c+'\' match');
				}
			}else if(s == S_ATTR_NOQUOT_VALUE){
				value = source.slice(start, p);
				addAttribute(attrName, value, start);
				errorHandler.warning('attribute "'+attrName+'" missed start quot('+c+')!!');
				start = p+1;
				s = S_ATTR_END
			}else{
				//fatalError: no equal before
				throw new Error('attribute value must after "="'); // No known test case
			}
			break;
		case '/':
			switch(s){
			case S_TAG:
				el.setTagName(source.slice(start,p));
			case S_ATTR_END:
			case S_TAG_SPACE:
			case S_TAG_CLOSE:
				s =S_TAG_CLOSE;
				el.closed = true;
			case S_ATTR_NOQUOT_VALUE:
			case S_ATTR:
				break;
				case S_ATTR_SPACE:
					el.closed = true;
				break;
			//case S_EQ:
			default:
				throw new Error("attribute invalid close char('/')") // No known test case
			}
			break;
		case ''://end document
			errorHandler.error('unexpected end of input');
			if(s == S_TAG){
				el.setTagName(source.slice(start,p));
			}
			return p;
		case '>':
			switch(s){
			case S_TAG:
				el.setTagName(source.slice(start,p));
			case S_ATTR_END:
			case S_TAG_SPACE:
			case S_TAG_CLOSE:
				break;//normal
			case S_ATTR_NOQUOT_VALUE://Compatible state
			case S_ATTR:
				value = source.slice(start,p);
				if(value.slice(-1) === '/'){
					el.closed  = true;
					value = value.slice(0,-1)
				}
			case S_ATTR_SPACE:
				if(s === S_ATTR_SPACE){
					value = attrName;
				}
				if(s == S_ATTR_NOQUOT_VALUE){
					errorHandler.warning('attribute "'+value+'" missed quot(")!');
					addAttribute(attrName, value, start)
				}else{
					if(!NAMESPACE.isHTML(currentNSMap['']) || !value.match(/^(?:disabled|checked|selected)$/i)){
						errorHandler.warning('attribute "'+value+'" missed value!! "'+value+'" instead!!')
					}
					addAttribute(value, value, start)
				}
				break;
			case S_EQ:
				throw new Error('attribute value missed!!');
			}
//			console.log(tagName,tagNamePattern,tagNamePattern.test(tagName))
			return p;
		/*xml space '\x20' | #x9 | #xD | #xA; */
		case '\u0080':
			c = ' ';
		default:
			if(c<= ' '){//space
				switch(s){
				case S_TAG:
					el.setTagName(source.slice(start,p));//tagName
					s = S_TAG_SPACE;
					break;
				case S_ATTR:
					attrName = source.slice(start,p)
					s = S_ATTR_SPACE;
					break;
				case S_ATTR_NOQUOT_VALUE:
					var value = source.slice(start, p);
					errorHandler.warning('attribute "'+value+'" missed quot(")!!');
					addAttribute(attrName, value, start)
				case S_ATTR_END:
					s = S_TAG_SPACE;
					break;
				//case S_TAG_SPACE:
				//case S_EQ:
				//case S_ATTR_SPACE:
				//	void();break;
				//case S_TAG_CLOSE:
					//ignore warning
				}
			}else{//not space
//S_TAG,	S_ATTR,	S_EQ,	S_ATTR_NOQUOT_VALUE
//S_ATTR_SPACE,	S_ATTR_END,	S_TAG_SPACE, S_TAG_CLOSE
				switch(s){
				//case S_TAG:void();break;
				//case S_ATTR:void();break;
				//case S_ATTR_NOQUOT_VALUE:void();break;
				case S_ATTR_SPACE:
					var tagName =  el.tagName;
					if (!NAMESPACE.isHTML(currentNSMap['']) || !attrName.match(/^(?:disabled|checked|selected)$/i)) {
						errorHandler.warning('attribute "'+attrName+'" missed value!! "'+attrName+'" instead2!!')
					}
					addAttribute(attrName, attrName, start);
					start = p;
					s = S_ATTR;
					break;
				case S_ATTR_END:
					errorHandler.warning('attribute space is required"'+attrName+'"!!')
				case S_TAG_SPACE:
					s = S_ATTR;
					start = p;
					break;
				case S_EQ:
					s = S_ATTR_NOQUOT_VALUE;
					start = p;
					break;
				case S_TAG_CLOSE:
					throw new Error("elements closed character '/' and '>' must be connected to");
				}
			}
		}//end outer switch
		//console.log('p++',p)
		p++;
	}
}
/**
 * @return true if has new namespace define
 */
function appendElement(el,domBuilder,currentNSMap){
	var tagName = el.tagName;
	var localNSMap = null;
	//var currentNSMap = parseStack[parseStack.length-1].currentNSMap;
	var i = el.length;
	while(i--){
		var a = el[i];
		var qName = a.qName;
		var value = a.value;
		var nsp = qName.indexOf(':');
		if(nsp>0){
			var prefix = a.prefix = qName.slice(0,nsp);
			var localName = qName.slice(nsp+1);
			var nsPrefix = prefix === 'xmlns' && localName
		}else{
			localName = qName;
			prefix = null
			nsPrefix = qName === 'xmlns' && ''
		}
		//can not set prefix,because prefix !== ''
		a.localName = localName ;
		//prefix == null for no ns prefix attribute
		if(nsPrefix !== false){//hack!!
			if(localNSMap == null){
				localNSMap = {}
				//console.log(currentNSMap,0)
				_copy(currentNSMap,currentNSMap={})
				//console.log(currentNSMap,1)
			}
			currentNSMap[nsPrefix] = localNSMap[nsPrefix] = value;
			a.uri = NAMESPACE.XMLNS
			domBuilder.startPrefixMapping(nsPrefix, value)
		}
	}
	var i = el.length;
	while(i--){
		a = el[i];
		var prefix = a.prefix;
		if(prefix){//no prefix attribute has no namespace
			if(prefix === 'xml'){
				a.uri = NAMESPACE.XML;
			}if(prefix !== 'xmlns'){
				a.uri = currentNSMap[prefix || '']

				//{console.log('###'+a.qName,domBuilder.locator.systemId+'',currentNSMap,a.uri)}
			}
		}
	}
	var nsp = tagName.indexOf(':');
	if(nsp>0){
		prefix = el.prefix = tagName.slice(0,nsp);
		localName = el.localName = tagName.slice(nsp+1);
	}else{
		prefix = null;//important!!
		localName = el.localName = tagName;
	}
	//no prefix element has default namespace
	var ns = el.uri = currentNSMap[prefix || ''];
	domBuilder.startElement(ns,localName,tagName,el);
	//endPrefixMapping and startPrefixMapping have not any help for dom builder
	//localNSMap = null
	if(el.closed){
		domBuilder.endElement(ns,localName,tagName);
		if(localNSMap){
			for (prefix in localNSMap) {
				if (Object.prototype.hasOwnProperty.call(localNSMap, prefix)) {
					domBuilder.endPrefixMapping(prefix);
				}
			}
		}
	}else{
		el.currentNSMap = currentNSMap;
		el.localNSMap = localNSMap;
		//parseStack.push(el);
		return true;
	}
}
function parseHtmlSpecialContent(source,elStartEnd,tagName,entityReplacer,domBuilder){
	if(/^(?:script|textarea)$/i.test(tagName)){
		var elEndStart =  source.indexOf('</'+tagName+'>',elStartEnd);
		var text = source.substring(elStartEnd+1,elEndStart);
		if(/[&<]/.test(text)){
			if(/^script$/i.test(tagName)){
				//if(!/\]\]>/.test(text)){
					//lexHandler.startCDATA();
					domBuilder.characters(text,0,text.length);
					//lexHandler.endCDATA();
					return elEndStart;
				//}
			}//}else{//text area
				text = text.replace(/&#?\w+;/g,entityReplacer);
				domBuilder.characters(text,0,text.length);
				return elEndStart;
			//}

		}
	}
	return elStartEnd+1;
}
function fixSelfClosed(source,elStartEnd,tagName,closeMap){
	//if(tagName in closeMap){
	var pos = closeMap[tagName];
	if(pos == null){
		//console.log(tagName)
		pos =  source.lastIndexOf('</'+tagName+'>')
		if(pos<elStartEnd){//忘记闭合
			pos = source.lastIndexOf('</'+tagName)
		}
		closeMap[tagName] =pos
	}
	return pos<elStartEnd;
	//}
}

function _copy (source, target) {
	for (var n in source) {
		if (Object.prototype.hasOwnProperty.call(source, n)) {
			target[n] = source[n];
		}
	}
}

function parseDCC(source,start,domBuilder,errorHandler){//sure start with '<!'
	var next= source.charAt(start+2)
	switch(next){
	case '-':
		if(source.charAt(start + 3) === '-'){
			var end = source.indexOf('-->',start+4);
			//append comment source.substring(4,end)//<!--
			if(end>start){
				domBuilder.comment(source,start+4,end-start-4);
				return end+3;
			}else{
				errorHandler.error("Unclosed comment");
				return -1;
			}
		}else{
			//error
			return -1;
		}
	default:
		if(source.substr(start+3,6) == 'CDATA['){
			var end = source.indexOf(']]>',start+9);
			domBuilder.startCDATA();
			domBuilder.characters(source,start+9,end-start-9);
			domBuilder.endCDATA()
			return end+3;
		}
		//<!DOCTYPE
		//startDTD(java.lang.String name, java.lang.String publicId, java.lang.String systemId)
		var matchs = split(source,start);
		var len = matchs.length;
		if(len>1 && /!doctype/i.test(matchs[0][0])){
			var name = matchs[1][0];
			var pubid = false;
			var sysid = false;
			if(len>3){
				if(/^public$/i.test(matchs[2][0])){
					pubid = matchs[3][0];
					sysid = len>4 && matchs[4][0];
				}else if(/^system$/i.test(matchs[2][0])){
					sysid = matchs[3][0];
				}
			}
			var lastMatch = matchs[len-1]
			domBuilder.startDTD(name, pubid, sysid);
			domBuilder.endDTD();

			return lastMatch.index+lastMatch[0].length
		}
	}
	return -1;
}



function parseInstruction(source,start,domBuilder){
	var end = source.indexOf('?>',start);
	if(end){
		var match = source.substring(start,end).match(/^<\?(\S*)\s*([\s\S]*?)\s*$/);
		if(match){
			var len = match[0].length;
			domBuilder.processingInstruction(match[1], match[2]) ;
			return end+2;
		}else{//error
			return -1;
		}
	}
	return -1;
}

function ElementAttributes(){
	this.attributeNames = {}
}
ElementAttributes.prototype = {
	setTagName:function(tagName){
		if(!tagNamePattern.test(tagName)){
			throw new Error('invalid tagName:'+tagName)
		}
		this.tagName = tagName
	},
	addValue:function(qName, value, offset) {
		if(!tagNamePattern.test(qName)){
			throw new Error('invalid attribute:'+qName)
		}
		this.attributeNames[qName] = this.length;
		this[this.length++] = {qName:qName,value:value,offset:offset}
	},
	length:0,
	getLocalName:function(i){return this[i].localName},
	getLocator:function(i){return this[i].locator},
	getQName:function(i){return this[i].qName},
	getURI:function(i){return this[i].uri},
	getValue:function(i){return this[i].value}
//	,getIndex:function(uri, localName)){
//		if(localName){
//
//		}else{
//			var qName = uri
//		}
//	},
//	getValue:function(){return this.getValue(this.getIndex.apply(this,arguments))},
//	getType:function(uri,localName){}
//	getType:function(i){},
}



function split(source,start){
	var match;
	var buf = [];
	var reg = /'[^']+'|"[^"]+"|[^\s<>\/=]+=?|(\/?\s*>|<)/g;
	reg.lastIndex = start;
	reg.exec(source);//skip <
	while(match = reg.exec(source)){
		buf.push(match);
		if(match[1])return buf;
	}
}

exports.XMLReader = XMLReader;
exports.ParseError = ParseError;


/***/ }),

/***/ 5063:
/***/ ((module) => {

"use strict";


module.exports = ({onlyFirst = false} = {}) => {
	const pattern = [
		'[\\u001B\\u009B][[\\]()#;?]*(?:(?:(?:(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]+)*|[a-zA-Z\\d]+(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]*)*)?\\u0007)',
		'(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-ntqry=><~]))'
	].join('|');

	return new RegExp(pattern, onlyFirst ? undefined : 'g');
};


/***/ }),

/***/ 2068:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";
/* module decorator */ module = __nccwpck_require__.nmd(module);


const wrapAnsi16 = (fn, offset) => (...args) => {
	const code = fn(...args);
	return `\u001B[${code + offset}m`;
};

const wrapAnsi256 = (fn, offset) => (...args) => {
	const code = fn(...args);
	return `\u001B[${38 + offset};5;${code}m`;
};

const wrapAnsi16m = (fn, offset) => (...args) => {
	const rgb = fn(...args);
	return `\u001B[${38 + offset};2;${rgb[0]};${rgb[1]};${rgb[2]}m`;
};

const ansi2ansi = n => n;
const rgb2rgb = (r, g, b) => [r, g, b];

const setLazyProperty = (object, property, get) => {
	Object.defineProperty(object, property, {
		get: () => {
			const value = get();

			Object.defineProperty(object, property, {
				value,
				enumerable: true,
				configurable: true
			});

			return value;
		},
		enumerable: true,
		configurable: true
	});
};

/** @type {typeof import('color-convert')} */
let colorConvert;
const makeDynamicStyles = (wrap, targetSpace, identity, isBackground) => {
	if (colorConvert === undefined) {
		colorConvert = __nccwpck_require__(6931);
	}

	const offset = isBackground ? 10 : 0;
	const styles = {};

	for (const [sourceSpace, suite] of Object.entries(colorConvert)) {
		const name = sourceSpace === 'ansi16' ? 'ansi' : sourceSpace;
		if (sourceSpace === targetSpace) {
			styles[name] = wrap(identity, offset);
		} else if (typeof suite === 'object') {
			styles[name] = wrap(suite[targetSpace], offset);
		}
	}

	return styles;
};

function assembleStyles() {
	const codes = new Map();
	const styles = {
		modifier: {
			reset: [0, 0],
			// 21 isn't widely supported and 22 does the same thing
			bold: [1, 22],
			dim: [2, 22],
			italic: [3, 23],
			underline: [4, 24],
			inverse: [7, 27],
			hidden: [8, 28],
			strikethrough: [9, 29]
		},
		color: {
			black: [30, 39],
			red: [31, 39],
			green: [32, 39],
			yellow: [33, 39],
			blue: [34, 39],
			magenta: [35, 39],
			cyan: [36, 39],
			white: [37, 39],

			// Bright color
			blackBright: [90, 39],
			redBright: [91, 39],
			greenBright: [92, 39],
			yellowBright: [93, 39],
			blueBright: [94, 39],
			magentaBright: [95, 39],
			cyanBright: [96, 39],
			whiteBright: [97, 39]
		},
		bgColor: {
			bgBlack: [40, 49],
			bgRed: [41, 49],
			bgGreen: [42, 49],
			bgYellow: [43, 49],
			bgBlue: [44, 49],
			bgMagenta: [45, 49],
			bgCyan: [46, 49],
			bgWhite: [47, 49],

			// Bright color
			bgBlackBright: [100, 49],
			bgRedBright: [101, 49],
			bgGreenBright: [102, 49],
			bgYellowBright: [103, 49],
			bgBlueBright: [104, 49],
			bgMagentaBright: [105, 49],
			bgCyanBright: [106, 49],
			bgWhiteBright: [107, 49]
		}
	};

	// Alias bright black as gray (and grey)
	styles.color.gray = styles.color.blackBright;
	styles.bgColor.bgGray = styles.bgColor.bgBlackBright;
	styles.color.grey = styles.color.blackBright;
	styles.bgColor.bgGrey = styles.bgColor.bgBlackBright;

	for (const [groupName, group] of Object.entries(styles)) {
		for (const [styleName, style] of Object.entries(group)) {
			styles[styleName] = {
				open: `\u001B[${style[0]}m`,
				close: `\u001B[${style[1]}m`
			};

			group[styleName] = styles[styleName];

			codes.set(style[0], style[1]);
		}

		Object.defineProperty(styles, groupName, {
			value: group,
			enumerable: false
		});
	}

	Object.defineProperty(styles, 'codes', {
		value: codes,
		enumerable: false
	});

	styles.color.close = '\u001B[39m';
	styles.bgColor.close = '\u001B[49m';

	setLazyProperty(styles.color, 'ansi', () => makeDynamicStyles(wrapAnsi16, 'ansi16', ansi2ansi, false));
	setLazyProperty(styles.color, 'ansi256', () => makeDynamicStyles(wrapAnsi256, 'ansi256', ansi2ansi, false));
	setLazyProperty(styles.color, 'ansi16m', () => makeDynamicStyles(wrapAnsi16m, 'rgb', rgb2rgb, false));
	setLazyProperty(styles.bgColor, 'ansi', () => makeDynamicStyles(wrapAnsi16, 'ansi16', ansi2ansi, true));
	setLazyProperty(styles.bgColor, 'ansi256', () => makeDynamicStyles(wrapAnsi256, 'ansi256', ansi2ansi, true));
	setLazyProperty(styles.bgColor, 'ansi16m', () => makeDynamicStyles(wrapAnsi16m, 'rgb', rgb2rgb, true));

	return styles;
}

// Make the export immutable
Object.defineProperty(module, 'exports', {
	enumerable: true,
	get: assembleStyles
});


/***/ }),

/***/ 7391:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

/* MIT license */
/* eslint-disable no-mixed-operators */
const cssKeywords = __nccwpck_require__(8510);

// NOTE: conversions should only return primitive values (i.e. arrays, or
//       values that give correct `typeof` results).
//       do not use box values types (i.e. Number(), String(), etc.)

const reverseKeywords = {};
for (const key of Object.keys(cssKeywords)) {
	reverseKeywords[cssKeywords[key]] = key;
}

const convert = {
	rgb: {channels: 3, labels: 'rgb'},
	hsl: {channels: 3, labels: 'hsl'},
	hsv: {channels: 3, labels: 'hsv'},
	hwb: {channels: 3, labels: 'hwb'},
	cmyk: {channels: 4, labels: 'cmyk'},
	xyz: {channels: 3, labels: 'xyz'},
	lab: {channels: 3, labels: 'lab'},
	lch: {channels: 3, labels: 'lch'},
	hex: {channels: 1, labels: ['hex']},
	keyword: {channels: 1, labels: ['keyword']},
	ansi16: {channels: 1, labels: ['ansi16']},
	ansi256: {channels: 1, labels: ['ansi256']},
	hcg: {channels: 3, labels: ['h', 'c', 'g']},
	apple: {channels: 3, labels: ['r16', 'g16', 'b16']},
	gray: {channels: 1, labels: ['gray']}
};

module.exports = convert;

// Hide .channels and .labels properties
for (const model of Object.keys(convert)) {
	if (!('channels' in convert[model])) {
		throw new Error('missing channels property: ' + model);
	}

	if (!('labels' in convert[model])) {
		throw new Error('missing channel labels property: ' + model);
	}

	if (convert[model].labels.length !== convert[model].channels) {
		throw new Error('channel and label counts mismatch: ' + model);
	}

	const {channels, labels} = convert[model];
	delete convert[model].channels;
	delete convert[model].labels;
	Object.defineProperty(convert[model], 'channels', {value: channels});
	Object.defineProperty(convert[model], 'labels', {value: labels});
}

convert.rgb.hsl = function (rgb) {
	const r = rgb[0] / 255;
	const g = rgb[1] / 255;
	const b = rgb[2] / 255;
	const min = Math.min(r, g, b);
	const max = Math.max(r, g, b);
	const delta = max - min;
	let h;
	let s;

	if (max === min) {
		h = 0;
	} else if (r === max) {
		h = (g - b) / delta;
	} else if (g === max) {
		h = 2 + (b - r) / delta;
	} else if (b === max) {
		h = 4 + (r - g) / delta;
	}

	h = Math.min(h * 60, 360);

	if (h < 0) {
		h += 360;
	}

	const l = (min + max) / 2;

	if (max === min) {
		s = 0;
	} else if (l <= 0.5) {
		s = delta / (max + min);
	} else {
		s = delta / (2 - max - min);
	}

	return [h, s * 100, l * 100];
};

convert.rgb.hsv = function (rgb) {
	let rdif;
	let gdif;
	let bdif;
	let h;
	let s;

	const r = rgb[0] / 255;
	const g = rgb[1] / 255;
	const b = rgb[2] / 255;
	const v = Math.max(r, g, b);
	const diff = v - Math.min(r, g, b);
	const diffc = function (c) {
		return (v - c) / 6 / diff + 1 / 2;
	};

	if (diff === 0) {
		h = 0;
		s = 0;
	} else {
		s = diff / v;
		rdif = diffc(r);
		gdif = diffc(g);
		bdif = diffc(b);

		if (r === v) {
			h = bdif - gdif;
		} else if (g === v) {
			h = (1 / 3) + rdif - bdif;
		} else if (b === v) {
			h = (2 / 3) + gdif - rdif;
		}

		if (h < 0) {
			h += 1;
		} else if (h > 1) {
			h -= 1;
		}
	}

	return [
		h * 360,
		s * 100,
		v * 100
	];
};

convert.rgb.hwb = function (rgb) {
	const r = rgb[0];
	const g = rgb[1];
	let b = rgb[2];
	const h = convert.rgb.hsl(rgb)[0];
	const w = 1 / 255 * Math.min(r, Math.min(g, b));

	b = 1 - 1 / 255 * Math.max(r, Math.max(g, b));

	return [h, w * 100, b * 100];
};

convert.rgb.cmyk = function (rgb) {
	const r = rgb[0] / 255;
	const g = rgb[1] / 255;
	const b = rgb[2] / 255;

	const k = Math.min(1 - r, 1 - g, 1 - b);
	const c = (1 - r - k) / (1 - k) || 0;
	const m = (1 - g - k) / (1 - k) || 0;
	const y = (1 - b - k) / (1 - k) || 0;

	return [c * 100, m * 100, y * 100, k * 100];
};

function comparativeDistance(x, y) {
	/*
		See https://en.m.wikipedia.org/wiki/Euclidean_distance#Squared_Euclidean_distance
	*/
	return (
		((x[0] - y[0]) ** 2) +
		((x[1] - y[1]) ** 2) +
		((x[2] - y[2]) ** 2)
	);
}

convert.rgb.keyword = function (rgb) {
	const reversed = reverseKeywords[rgb];
	if (reversed) {
		return reversed;
	}

	let currentClosestDistance = Infinity;
	let currentClosestKeyword;

	for (const keyword of Object.keys(cssKeywords)) {
		const value = cssKeywords[keyword];

		// Compute comparative distance
		const distance = comparativeDistance(rgb, value);

		// Check if its less, if so set as closest
		if (distance < currentClosestDistance) {
			currentClosestDistance = distance;
			currentClosestKeyword = keyword;
		}
	}

	return currentClosestKeyword;
};

convert.keyword.rgb = function (keyword) {
	return cssKeywords[keyword];
};

convert.rgb.xyz = function (rgb) {
	let r = rgb[0] / 255;
	let g = rgb[1] / 255;
	let b = rgb[2] / 255;

	// Assume sRGB
	r = r > 0.04045 ? (((r + 0.055) / 1.055) ** 2.4) : (r / 12.92);
	g = g > 0.04045 ? (((g + 0.055) / 1.055) ** 2.4) : (g / 12.92);
	b = b > 0.04045 ? (((b + 0.055) / 1.055) ** 2.4) : (b / 12.92);

	const x = (r * 0.4124) + (g * 0.3576) + (b * 0.1805);
	const y = (r * 0.2126) + (g * 0.7152) + (b * 0.0722);
	const z = (r * 0.0193) + (g * 0.1192) + (b * 0.9505);

	return [x * 100, y * 100, z * 100];
};

convert.rgb.lab = function (rgb) {
	const xyz = convert.rgb.xyz(rgb);
	let x = xyz[0];
	let y = xyz[1];
	let z = xyz[2];

	x /= 95.047;
	y /= 100;
	z /= 108.883;

	x = x > 0.008856 ? (x ** (1 / 3)) : (7.787 * x) + (16 / 116);
	y = y > 0.008856 ? (y ** (1 / 3)) : (7.787 * y) + (16 / 116);
	z = z > 0.008856 ? (z ** (1 / 3)) : (7.787 * z) + (16 / 116);

	const l = (116 * y) - 16;
	const a = 500 * (x - y);
	const b = 200 * (y - z);

	return [l, a, b];
};

convert.hsl.rgb = function (hsl) {
	const h = hsl[0] / 360;
	const s = hsl[1] / 100;
	const l = hsl[2] / 100;
	let t2;
	let t3;
	let val;

	if (s === 0) {
		val = l * 255;
		return [val, val, val];
	}

	if (l < 0.5) {
		t2 = l * (1 + s);
	} else {
		t2 = l + s - l * s;
	}

	const t1 = 2 * l - t2;

	const rgb = [0, 0, 0];
	for (let i = 0; i < 3; i++) {
		t3 = h + 1 / 3 * -(i - 1);
		if (t3 < 0) {
			t3++;
		}

		if (t3 > 1) {
			t3--;
		}

		if (6 * t3 < 1) {
			val = t1 + (t2 - t1) * 6 * t3;
		} else if (2 * t3 < 1) {
			val = t2;
		} else if (3 * t3 < 2) {
			val = t1 + (t2 - t1) * (2 / 3 - t3) * 6;
		} else {
			val = t1;
		}

		rgb[i] = val * 255;
	}

	return rgb;
};

convert.hsl.hsv = function (hsl) {
	const h = hsl[0];
	let s = hsl[1] / 100;
	let l = hsl[2] / 100;
	let smin = s;
	const lmin = Math.max(l, 0.01);

	l *= 2;
	s *= (l <= 1) ? l : 2 - l;
	smin *= lmin <= 1 ? lmin : 2 - lmin;
	const v = (l + s) / 2;
	const sv = l === 0 ? (2 * smin) / (lmin + smin) : (2 * s) / (l + s);

	return [h, sv * 100, v * 100];
};

convert.hsv.rgb = function (hsv) {
	const h = hsv[0] / 60;
	const s = hsv[1] / 100;
	let v = hsv[2] / 100;
	const hi = Math.floor(h) % 6;

	const f = h - Math.floor(h);
	const p = 255 * v * (1 - s);
	const q = 255 * v * (1 - (s * f));
	const t = 255 * v * (1 - (s * (1 - f)));
	v *= 255;

	switch (hi) {
		case 0:
			return [v, t, p];
		case 1:
			return [q, v, p];
		case 2:
			return [p, v, t];
		case 3:
			return [p, q, v];
		case 4:
			return [t, p, v];
		case 5:
			return [v, p, q];
	}
};

convert.hsv.hsl = function (hsv) {
	const h = hsv[0];
	const s = hsv[1] / 100;
	const v = hsv[2] / 100;
	const vmin = Math.max(v, 0.01);
	let sl;
	let l;

	l = (2 - s) * v;
	const lmin = (2 - s) * vmin;
	sl = s * vmin;
	sl /= (lmin <= 1) ? lmin : 2 - lmin;
	sl = sl || 0;
	l /= 2;

	return [h, sl * 100, l * 100];
};

// http://dev.w3.org/csswg/css-color/#hwb-to-rgb
convert.hwb.rgb = function (hwb) {
	const h = hwb[0] / 360;
	let wh = hwb[1] / 100;
	let bl = hwb[2] / 100;
	const ratio = wh + bl;
	let f;

	// Wh + bl cant be > 1
	if (ratio > 1) {
		wh /= ratio;
		bl /= ratio;
	}

	const i = Math.floor(6 * h);
	const v = 1 - bl;
	f = 6 * h - i;

	if ((i & 0x01) !== 0) {
		f = 1 - f;
	}

	const n = wh + f * (v - wh); // Linear interpolation

	let r;
	let g;
	let b;
	/* eslint-disable max-statements-per-line,no-multi-spaces */
	switch (i) {
		default:
		case 6:
		case 0: r = v;  g = n;  b = wh; break;
		case 1: r = n;  g = v;  b = wh; break;
		case 2: r = wh; g = v;  b = n; break;
		case 3: r = wh; g = n;  b = v; break;
		case 4: r = n;  g = wh; b = v; break;
		case 5: r = v;  g = wh; b = n; break;
	}
	/* eslint-enable max-statements-per-line,no-multi-spaces */

	return [r * 255, g * 255, b * 255];
};

convert.cmyk.rgb = function (cmyk) {
	const c = cmyk[0] / 100;
	const m = cmyk[1] / 100;
	const y = cmyk[2] / 100;
	const k = cmyk[3] / 100;

	const r = 1 - Math.min(1, c * (1 - k) + k);
	const g = 1 - Math.min(1, m * (1 - k) + k);
	const b = 1 - Math.min(1, y * (1 - k) + k);

	return [r * 255, g * 255, b * 255];
};

convert.xyz.rgb = function (xyz) {
	const x = xyz[0] / 100;
	const y = xyz[1] / 100;
	const z = xyz[2] / 100;
	let r;
	let g;
	let b;

	r = (x * 3.2406) + (y * -1.5372) + (z * -0.4986);
	g = (x * -0.9689) + (y * 1.8758) + (z * 0.0415);
	b = (x * 0.0557) + (y * -0.2040) + (z * 1.0570);

	// Assume sRGB
	r = r > 0.0031308
		? ((1.055 * (r ** (1.0 / 2.4))) - 0.055)
		: r * 12.92;

	g = g > 0.0031308
		? ((1.055 * (g ** (1.0 / 2.4))) - 0.055)
		: g * 12.92;

	b = b > 0.0031308
		? ((1.055 * (b ** (1.0 / 2.4))) - 0.055)
		: b * 12.92;

	r = Math.min(Math.max(0, r), 1);
	g = Math.min(Math.max(0, g), 1);
	b = Math.min(Math.max(0, b), 1);

	return [r * 255, g * 255, b * 255];
};

convert.xyz.lab = function (xyz) {
	let x = xyz[0];
	let y = xyz[1];
	let z = xyz[2];

	x /= 95.047;
	y /= 100;
	z /= 108.883;

	x = x > 0.008856 ? (x ** (1 / 3)) : (7.787 * x) + (16 / 116);
	y = y > 0.008856 ? (y ** (1 / 3)) : (7.787 * y) + (16 / 116);
	z = z > 0.008856 ? (z ** (1 / 3)) : (7.787 * z) + (16 / 116);

	const l = (116 * y) - 16;
	const a = 500 * (x - y);
	const b = 200 * (y - z);

	return [l, a, b];
};

convert.lab.xyz = function (lab) {
	const l = lab[0];
	const a = lab[1];
	const b = lab[2];
	let x;
	let y;
	let z;

	y = (l + 16) / 116;
	x = a / 500 + y;
	z = y - b / 200;

	const y2 = y ** 3;
	const x2 = x ** 3;
	const z2 = z ** 3;
	y = y2 > 0.008856 ? y2 : (y - 16 / 116) / 7.787;
	x = x2 > 0.008856 ? x2 : (x - 16 / 116) / 7.787;
	z = z2 > 0.008856 ? z2 : (z - 16 / 116) / 7.787;

	x *= 95.047;
	y *= 100;
	z *= 108.883;

	return [x, y, z];
};

convert.lab.lch = function (lab) {
	const l = lab[0];
	const a = lab[1];
	const b = lab[2];
	let h;

	const hr = Math.atan2(b, a);
	h = hr * 360 / 2 / Math.PI;

	if (h < 0) {
		h += 360;
	}

	const c = Math.sqrt(a * a + b * b);

	return [l, c, h];
};

convert.lch.lab = function (lch) {
	const l = lch[0];
	const c = lch[1];
	const h = lch[2];

	const hr = h / 360 * 2 * Math.PI;
	const a = c * Math.cos(hr);
	const b = c * Math.sin(hr);

	return [l, a, b];
};

convert.rgb.ansi16 = function (args, saturation = null) {
	const [r, g, b] = args;
	let value = saturation === null ? convert.rgb.hsv(args)[2] : saturation; // Hsv -> ansi16 optimization

	value = Math.round(value / 50);

	if (value === 0) {
		return 30;
	}

	let ansi = 30
		+ ((Math.round(b / 255) << 2)
		| (Math.round(g / 255) << 1)
		| Math.round(r / 255));

	if (value === 2) {
		ansi += 60;
	}

	return ansi;
};

convert.hsv.ansi16 = function (args) {
	// Optimization here; we already know the value and don't need to get
	// it converted for us.
	return convert.rgb.ansi16(convert.hsv.rgb(args), args[2]);
};

convert.rgb.ansi256 = function (args) {
	const r = args[0];
	const g = args[1];
	const b = args[2];

	// We use the extended greyscale palette here, with the exception of
	// black and white. normal palette only has 4 greyscale shades.
	if (r === g && g === b) {
		if (r < 8) {
			return 16;
		}

		if (r > 248) {
			return 231;
		}

		return Math.round(((r - 8) / 247) * 24) + 232;
	}

	const ansi = 16
		+ (36 * Math.round(r / 255 * 5))
		+ (6 * Math.round(g / 255 * 5))
		+ Math.round(b / 255 * 5);

	return ansi;
};

convert.ansi16.rgb = function (args) {
	let color = args % 10;

	// Handle greyscale
	if (color === 0 || color === 7) {
		if (args > 50) {
			color += 3.5;
		}

		color = color / 10.5 * 255;

		return [color, color, color];
	}

	const mult = (~~(args > 50) + 1) * 0.5;
	const r = ((color & 1) * mult) * 255;
	const g = (((color >> 1) & 1) * mult) * 255;
	const b = (((color >> 2) & 1) * mult) * 255;

	return [r, g, b];
};

convert.ansi256.rgb = function (args) {
	// Handle greyscale
	if (args >= 232) {
		const c = (args - 232) * 10 + 8;
		return [c, c, c];
	}

	args -= 16;

	let rem;
	const r = Math.floor(args / 36) / 5 * 255;
	const g = Math.floor((rem = args % 36) / 6) / 5 * 255;
	const b = (rem % 6) / 5 * 255;

	return [r, g, b];
};

convert.rgb.hex = function (args) {
	const integer = ((Math.round(args[0]) & 0xFF) << 16)
		+ ((Math.round(args[1]) & 0xFF) << 8)
		+ (Math.round(args[2]) & 0xFF);

	const string = integer.toString(16).toUpperCase();
	return '000000'.substring(string.length) + string;
};

convert.hex.rgb = function (args) {
	const match = args.toString(16).match(/[a-f0-9]{6}|[a-f0-9]{3}/i);
	if (!match) {
		return [0, 0, 0];
	}

	let colorString = match[0];

	if (match[0].length === 3) {
		colorString = colorString.split('').map(char => {
			return char + char;
		}).join('');
	}

	const integer = parseInt(colorString, 16);
	const r = (integer >> 16) & 0xFF;
	const g = (integer >> 8) & 0xFF;
	const b = integer & 0xFF;

	return [r, g, b];
};

convert.rgb.hcg = function (rgb) {
	const r = rgb[0] / 255;
	const g = rgb[1] / 255;
	const b = rgb[2] / 255;
	const max = Math.max(Math.max(r, g), b);
	const min = Math.min(Math.min(r, g), b);
	const chroma = (max - min);
	let grayscale;
	let hue;

	if (chroma < 1) {
		grayscale = min / (1 - chroma);
	} else {
		grayscale = 0;
	}

	if (chroma <= 0) {
		hue = 0;
	} else
	if (max === r) {
		hue = ((g - b) / chroma) % 6;
	} else
	if (max === g) {
		hue = 2 + (b - r) / chroma;
	} else {
		hue = 4 + (r - g) / chroma;
	}

	hue /= 6;
	hue %= 1;

	return [hue * 360, chroma * 100, grayscale * 100];
};

convert.hsl.hcg = function (hsl) {
	const s = hsl[1] / 100;
	const l = hsl[2] / 100;

	const c = l < 0.5 ? (2.0 * s * l) : (2.0 * s * (1.0 - l));

	let f = 0;
	if (c < 1.0) {
		f = (l - 0.5 * c) / (1.0 - c);
	}

	return [hsl[0], c * 100, f * 100];
};

convert.hsv.hcg = function (hsv) {
	const s = hsv[1] / 100;
	const v = hsv[2] / 100;

	const c = s * v;
	let f = 0;

	if (c < 1.0) {
		f = (v - c) / (1 - c);
	}

	return [hsv[0], c * 100, f * 100];
};

convert.hcg.rgb = function (hcg) {
	const h = hcg[0] / 360;
	const c = hcg[1] / 100;
	const g = hcg[2] / 100;

	if (c === 0.0) {
		return [g * 255, g * 255, g * 255];
	}

	const pure = [0, 0, 0];
	const hi = (h % 1) * 6;
	const v = hi % 1;
	const w = 1 - v;
	let mg = 0;

	/* eslint-disable max-statements-per-line */
	switch (Math.floor(hi)) {
		case 0:
			pure[0] = 1; pure[1] = v; pure[2] = 0; break;
		case 1:
			pure[0] = w; pure[1] = 1; pure[2] = 0; break;
		case 2:
			pure[0] = 0; pure[1] = 1; pure[2] = v; break;
		case 3:
			pure[0] = 0; pure[1] = w; pure[2] = 1; break;
		case 4:
			pure[0] = v; pure[1] = 0; pure[2] = 1; break;
		default:
			pure[0] = 1; pure[1] = 0; pure[2] = w;
	}
	/* eslint-enable max-statements-per-line */

	mg = (1.0 - c) * g;

	return [
		(c * pure[0] + mg) * 255,
		(c * pure[1] + mg) * 255,
		(c * pure[2] + mg) * 255
	];
};

convert.hcg.hsv = function (hcg) {
	const c = hcg[1] / 100;
	const g = hcg[2] / 100;

	const v = c + g * (1.0 - c);
	let f = 0;

	if (v > 0.0) {
		f = c / v;
	}

	return [hcg[0], f * 100, v * 100];
};

convert.hcg.hsl = function (hcg) {
	const c = hcg[1] / 100;
	const g = hcg[2] / 100;

	const l = g * (1.0 - c) + 0.5 * c;
	let s = 0;

	if (l > 0.0 && l < 0.5) {
		s = c / (2 * l);
	} else
	if (l >= 0.5 && l < 1.0) {
		s = c / (2 * (1 - l));
	}

	return [hcg[0], s * 100, l * 100];
};

convert.hcg.hwb = function (hcg) {
	const c = hcg[1] / 100;
	const g = hcg[2] / 100;
	const v = c + g * (1.0 - c);
	return [hcg[0], (v - c) * 100, (1 - v) * 100];
};

convert.hwb.hcg = function (hwb) {
	const w = hwb[1] / 100;
	const b = hwb[2] / 100;
	const v = 1 - b;
	const c = v - w;
	let g = 0;

	if (c < 1) {
		g = (v - c) / (1 - c);
	}

	return [hwb[0], c * 100, g * 100];
};

convert.apple.rgb = function (apple) {
	return [(apple[0] / 65535) * 255, (apple[1] / 65535) * 255, (apple[2] / 65535) * 255];
};

convert.rgb.apple = function (rgb) {
	return [(rgb[0] / 255) * 65535, (rgb[1] / 255) * 65535, (rgb[2] / 255) * 65535];
};

convert.gray.rgb = function (args) {
	return [args[0] / 100 * 255, args[0] / 100 * 255, args[0] / 100 * 255];
};

convert.gray.hsl = function (args) {
	return [0, 0, args[0]];
};

convert.gray.hsv = convert.gray.hsl;

convert.gray.hwb = function (gray) {
	return [0, 100, gray[0]];
};

convert.gray.cmyk = function (gray) {
	return [0, 0, 0, gray[0]];
};

convert.gray.lab = function (gray) {
	return [gray[0], 0, 0];
};

convert.gray.hex = function (gray) {
	const val = Math.round(gray[0] / 100 * 255) & 0xFF;
	const integer = (val << 16) + (val << 8) + val;

	const string = integer.toString(16).toUpperCase();
	return '000000'.substring(string.length) + string;
};

convert.rgb.gray = function (rgb) {
	const val = (rgb[0] + rgb[1] + rgb[2]) / 3;
	return [val / 255 * 100];
};


/***/ }),

/***/ 6931:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const conversions = __nccwpck_require__(7391);
const route = __nccwpck_require__(880);

const convert = {};

const models = Object.keys(conversions);

function wrapRaw(fn) {
	const wrappedFn = function (...args) {
		const arg0 = args[0];
		if (arg0 === undefined || arg0 === null) {
			return arg0;
		}

		if (arg0.length > 1) {
			args = arg0;
		}

		return fn(args);
	};

	// Preserve .conversion property if there is one
	if ('conversion' in fn) {
		wrappedFn.conversion = fn.conversion;
	}

	return wrappedFn;
}

function wrapRounded(fn) {
	const wrappedFn = function (...args) {
		const arg0 = args[0];

		if (arg0 === undefined || arg0 === null) {
			return arg0;
		}

		if (arg0.length > 1) {
			args = arg0;
		}

		const result = fn(args);

		// We're assuming the result is an array here.
		// see notice in conversions.js; don't use box types
		// in conversion functions.
		if (typeof result === 'object') {
			for (let len = result.length, i = 0; i < len; i++) {
				result[i] = Math.round(result[i]);
			}
		}

		return result;
	};

	// Preserve .conversion property if there is one
	if ('conversion' in fn) {
		wrappedFn.conversion = fn.conversion;
	}

	return wrappedFn;
}

models.forEach(fromModel => {
	convert[fromModel] = {};

	Object.defineProperty(convert[fromModel], 'channels', {value: conversions[fromModel].channels});
	Object.defineProperty(convert[fromModel], 'labels', {value: conversions[fromModel].labels});

	const routes = route(fromModel);
	const routeModels = Object.keys(routes);

	routeModels.forEach(toModel => {
		const fn = routes[toModel];

		convert[fromModel][toModel] = wrapRounded(fn);
		convert[fromModel][toModel].raw = wrapRaw(fn);
	});
});

module.exports = convert;


/***/ }),

/***/ 880:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const conversions = __nccwpck_require__(7391);

/*
	This function routes a model to all other models.

	all functions that are routed have a property `.conversion` attached
	to the returned synthetic function. This property is an array
	of strings, each with the steps in between the 'from' and 'to'
	color models (inclusive).

	conversions that are not possible simply are not included.
*/

function buildGraph() {
	const graph = {};
	// https://jsperf.com/object-keys-vs-for-in-with-closure/3
	const models = Object.keys(conversions);

	for (let len = models.length, i = 0; i < len; i++) {
		graph[models[i]] = {
			// http://jsperf.com/1-vs-infinity
			// micro-opt, but this is simple.
			distance: -1,
			parent: null
		};
	}

	return graph;
}

// https://en.wikipedia.org/wiki/Breadth-first_search
function deriveBFS(fromModel) {
	const graph = buildGraph();
	const queue = [fromModel]; // Unshift -> queue -> pop

	graph[fromModel].distance = 0;

	while (queue.length) {
		const current = queue.pop();
		const adjacents = Object.keys(conversions[current]);

		for (let len = adjacents.length, i = 0; i < len; i++) {
			const adjacent = adjacents[i];
			const node = graph[adjacent];

			if (node.distance === -1) {
				node.distance = graph[current].distance + 1;
				node.parent = current;
				queue.unshift(adjacent);
			}
		}
	}

	return graph;
}

function link(from, to) {
	return function (args) {
		return to(from(args));
	};
}

function wrapConversion(toModel, graph) {
	const path = [graph[toModel].parent, toModel];
	let fn = conversions[graph[toModel].parent][toModel];

	let cur = graph[toModel].parent;
	while (graph[cur].parent) {
		path.unshift(graph[cur].parent);
		fn = link(conversions[graph[cur].parent][cur], fn);
		cur = graph[cur].parent;
	}

	fn.conversion = path;
	return fn;
}

module.exports = function (fromModel) {
	const graph = deriveBFS(fromModel);
	const conversion = {};

	const models = Object.keys(graph);
	for (let len = models.length, i = 0; i < len; i++) {
		const toModel = models[i];
		const node = graph[toModel];

		if (node.parent === null) {
			// No possible conversion, or this node is the source model.
			continue;
		}

		conversion[toModel] = wrapConversion(toModel, graph);
	}

	return conversion;
};



/***/ }),

/***/ 8510:
/***/ ((module) => {

"use strict";


module.exports = {
	"aliceblue": [240, 248, 255],
	"antiquewhite": [250, 235, 215],
	"aqua": [0, 255, 255],
	"aquamarine": [127, 255, 212],
	"azure": [240, 255, 255],
	"beige": [245, 245, 220],
	"bisque": [255, 228, 196],
	"black": [0, 0, 0],
	"blanchedalmond": [255, 235, 205],
	"blue": [0, 0, 255],
	"blueviolet": [138, 43, 226],
	"brown": [165, 42, 42],
	"burlywood": [222, 184, 135],
	"cadetblue": [95, 158, 160],
	"chartreuse": [127, 255, 0],
	"chocolate": [210, 105, 30],
	"coral": [255, 127, 80],
	"cornflowerblue": [100, 149, 237],
	"cornsilk": [255, 248, 220],
	"crimson": [220, 20, 60],
	"cyan": [0, 255, 255],
	"darkblue": [0, 0, 139],
	"darkcyan": [0, 139, 139],
	"darkgoldenrod": [184, 134, 11],
	"darkgray": [169, 169, 169],
	"darkgreen": [0, 100, 0],
	"darkgrey": [169, 169, 169],
	"darkkhaki": [189, 183, 107],
	"darkmagenta": [139, 0, 139],
	"darkolivegreen": [85, 107, 47],
	"darkorange": [255, 140, 0],
	"darkorchid": [153, 50, 204],
	"darkred": [139, 0, 0],
	"darksalmon": [233, 150, 122],
	"darkseagreen": [143, 188, 143],
	"darkslateblue": [72, 61, 139],
	"darkslategray": [47, 79, 79],
	"darkslategrey": [47, 79, 79],
	"darkturquoise": [0, 206, 209],
	"darkviolet": [148, 0, 211],
	"deeppink": [255, 20, 147],
	"deepskyblue": [0, 191, 255],
	"dimgray": [105, 105, 105],
	"dimgrey": [105, 105, 105],
	"dodgerblue": [30, 144, 255],
	"firebrick": [178, 34, 34],
	"floralwhite": [255, 250, 240],
	"forestgreen": [34, 139, 34],
	"fuchsia": [255, 0, 255],
	"gainsboro": [220, 220, 220],
	"ghostwhite": [248, 248, 255],
	"gold": [255, 215, 0],
	"goldenrod": [218, 165, 32],
	"gray": [128, 128, 128],
	"green": [0, 128, 0],
	"greenyellow": [173, 255, 47],
	"grey": [128, 128, 128],
	"honeydew": [240, 255, 240],
	"hotpink": [255, 105, 180],
	"indianred": [205, 92, 92],
	"indigo": [75, 0, 130],
	"ivory": [255, 255, 240],
	"khaki": [240, 230, 140],
	"lavender": [230, 230, 250],
	"lavenderblush": [255, 240, 245],
	"lawngreen": [124, 252, 0],
	"lemonchiffon": [255, 250, 205],
	"lightblue": [173, 216, 230],
	"lightcoral": [240, 128, 128],
	"lightcyan": [224, 255, 255],
	"lightgoldenrodyellow": [250, 250, 210],
	"lightgray": [211, 211, 211],
	"lightgreen": [144, 238, 144],
	"lightgrey": [211, 211, 211],
	"lightpink": [255, 182, 193],
	"lightsalmon": [255, 160, 122],
	"lightseagreen": [32, 178, 170],
	"lightskyblue": [135, 206, 250],
	"lightslategray": [119, 136, 153],
	"lightslategrey": [119, 136, 153],
	"lightsteelblue": [176, 196, 222],
	"lightyellow": [255, 255, 224],
	"lime": [0, 255, 0],
	"limegreen": [50, 205, 50],
	"linen": [250, 240, 230],
	"magenta": [255, 0, 255],
	"maroon": [128, 0, 0],
	"mediumaquamarine": [102, 205, 170],
	"mediumblue": [0, 0, 205],
	"mediumorchid": [186, 85, 211],
	"mediumpurple": [147, 112, 219],
	"mediumseagreen": [60, 179, 113],
	"mediumslateblue": [123, 104, 238],
	"mediumspringgreen": [0, 250, 154],
	"mediumturquoise": [72, 209, 204],
	"mediumvioletred": [199, 21, 133],
	"midnightblue": [25, 25, 112],
	"mintcream": [245, 255, 250],
	"mistyrose": [255, 228, 225],
	"moccasin": [255, 228, 181],
	"navajowhite": [255, 222, 173],
	"navy": [0, 0, 128],
	"oldlace": [253, 245, 230],
	"olive": [128, 128, 0],
	"olivedrab": [107, 142, 35],
	"orange": [255, 165, 0],
	"orangered": [255, 69, 0],
	"orchid": [218, 112, 214],
	"palegoldenrod": [238, 232, 170],
	"palegreen": [152, 251, 152],
	"paleturquoise": [175, 238, 238],
	"palevioletred": [219, 112, 147],
	"papayawhip": [255, 239, 213],
	"peachpuff": [255, 218, 185],
	"peru": [205, 133, 63],
	"pink": [255, 192, 203],
	"plum": [221, 160, 221],
	"powderblue": [176, 224, 230],
	"purple": [128, 0, 128],
	"rebeccapurple": [102, 51, 153],
	"red": [255, 0, 0],
	"rosybrown": [188, 143, 143],
	"royalblue": [65, 105, 225],
	"saddlebrown": [139, 69, 19],
	"salmon": [250, 128, 114],
	"sandybrown": [244, 164, 96],
	"seagreen": [46, 139, 87],
	"seashell": [255, 245, 238],
	"sienna": [160, 82, 45],
	"silver": [192, 192, 192],
	"skyblue": [135, 206, 235],
	"slateblue": [106, 90, 205],
	"slategray": [112, 128, 144],
	"slategrey": [112, 128, 144],
	"snow": [255, 250, 250],
	"springgreen": [0, 255, 127],
	"steelblue": [70, 130, 180],
	"tan": [210, 180, 140],
	"teal": [0, 128, 128],
	"thistle": [216, 191, 216],
	"tomato": [255, 99, 71],
	"turquoise": [64, 224, 208],
	"violet": [238, 130, 238],
	"wheat": [245, 222, 179],
	"white": [255, 255, 255],
	"whitesmoke": [245, 245, 245],
	"yellow": [255, 255, 0],
	"yellowgreen": [154, 205, 50]
};


/***/ }),

/***/ 8212:
/***/ ((module) => {

"use strict";


module.exports = function () {
  // https://mths.be/emoji
  return /\uD83C\uDFF4\uDB40\uDC67\uDB40\uDC62(?:\uDB40\uDC65\uDB40\uDC6E\uDB40\uDC67|\uDB40\uDC73\uDB40\uDC63\uDB40\uDC74|\uDB40\uDC77\uDB40\uDC6C\uDB40\uDC73)\uDB40\uDC7F|\uD83D\uDC68(?:\uD83C\uDFFC\u200D(?:\uD83E\uDD1D\u200D\uD83D\uDC68\uD83C\uDFFB|\uD83C[\uDF3E\uDF73\uDF93\uDFA4\uDFA8\uDFEB\uDFED]|\uD83D[\uDCBB\uDCBC\uDD27\uDD2C\uDE80\uDE92]|\uD83E[\uDDAF-\uDDB3\uDDBC\uDDBD])|\uD83C\uDFFF\u200D(?:\uD83E\uDD1D\u200D\uD83D\uDC68(?:\uD83C[\uDFFB-\uDFFE])|\uD83C[\uDF3E\uDF73\uDF93\uDFA4\uDFA8\uDFEB\uDFED]|\uD83D[\uDCBB\uDCBC\uDD27\uDD2C\uDE80\uDE92]|\uD83E[\uDDAF-\uDDB3\uDDBC\uDDBD])|\uD83C\uDFFE\u200D(?:\uD83E\uDD1D\u200D\uD83D\uDC68(?:\uD83C[\uDFFB-\uDFFD])|\uD83C[\uDF3E\uDF73\uDF93\uDFA4\uDFA8\uDFEB\uDFED]|\uD83D[\uDCBB\uDCBC\uDD27\uDD2C\uDE80\uDE92]|\uD83E[\uDDAF-\uDDB3\uDDBC\uDDBD])|\uD83C\uDFFD\u200D(?:\uD83E\uDD1D\u200D\uD83D\uDC68(?:\uD83C[\uDFFB\uDFFC])|\uD83C[\uDF3E\uDF73\uDF93\uDFA4\uDFA8\uDFEB\uDFED]|\uD83D[\uDCBB\uDCBC\uDD27\uDD2C\uDE80\uDE92]|\uD83E[\uDDAF-\uDDB3\uDDBC\uDDBD])|\u200D(?:\u2764\uFE0F\u200D(?:\uD83D\uDC8B\u200D)?\uD83D\uDC68|(?:\uD83D[\uDC68\uDC69])\u200D(?:\uD83D\uDC66\u200D\uD83D\uDC66|\uD83D\uDC67\u200D(?:\uD83D[\uDC66\uDC67]))|\uD83D\uDC66\u200D\uD83D\uDC66|\uD83D\uDC67\u200D(?:\uD83D[\uDC66\uDC67])|(?:\uD83D[\uDC68\uDC69])\u200D(?:\uD83D[\uDC66\uDC67])|[\u2695\u2696\u2708]\uFE0F|\uD83D[\uDC66\uDC67]|\uD83C[\uDF3E\uDF73\uDF93\uDFA4\uDFA8\uDFEB\uDFED]|\uD83D[\uDCBB\uDCBC\uDD27\uDD2C\uDE80\uDE92]|\uD83E[\uDDAF-\uDDB3\uDDBC\uDDBD])|(?:\uD83C\uDFFB\u200D[\u2695\u2696\u2708]|\uD83C\uDFFF\u200D[\u2695\u2696\u2708]|\uD83C\uDFFE\u200D[\u2695\u2696\u2708]|\uD83C\uDFFD\u200D[\u2695\u2696\u2708]|\uD83C\uDFFC\u200D[\u2695\u2696\u2708])\uFE0F|\uD83C\uDFFB\u200D(?:\uD83C[\uDF3E\uDF73\uDF93\uDFA4\uDFA8\uDFEB\uDFED]|\uD83D[\uDCBB\uDCBC\uDD27\uDD2C\uDE80\uDE92]|\uD83E[\uDDAF-\uDDB3\uDDBC\uDDBD])|\uD83C[\uDFFB-\uDFFF])|(?:\uD83E\uDDD1\uD83C\uDFFB\u200D\uD83E\uDD1D\u200D\uD83E\uDDD1|\uD83D\uDC69\uD83C\uDFFC\u200D\uD83E\uDD1D\u200D\uD83D\uDC69)\uD83C\uDFFB|\uD83E\uDDD1(?:\uD83C\uDFFF\u200D\uD83E\uDD1D\u200D\uD83E\uDDD1(?:\uD83C[\uDFFB-\uDFFF])|\u200D\uD83E\uDD1D\u200D\uD83E\uDDD1)|(?:\uD83E\uDDD1\uD83C\uDFFE\u200D\uD83E\uDD1D\u200D\uD83E\uDDD1|\uD83D\uDC69\uD83C\uDFFF\u200D\uD83E\uDD1D\u200D(?:\uD83D[\uDC68\uDC69]))(?:\uD83C[\uDFFB-\uDFFE])|(?:\uD83E\uDDD1\uD83C\uDFFC\u200D\uD83E\uDD1D\u200D\uD83E\uDDD1|\uD83D\uDC69\uD83C\uDFFD\u200D\uD83E\uDD1D\u200D\uD83D\uDC69)(?:\uD83C[\uDFFB\uDFFC])|\uD83D\uDC69(?:\uD83C\uDFFE\u200D(?:\uD83E\uDD1D\u200D\uD83D\uDC68(?:\uD83C[\uDFFB-\uDFFD\uDFFF])|\uD83C[\uDF3E\uDF73\uDF93\uDFA4\uDFA8\uDFEB\uDFED]|\uD83D[\uDCBB\uDCBC\uDD27\uDD2C\uDE80\uDE92]|\uD83E[\uDDAF-\uDDB3\uDDBC\uDDBD])|\uD83C\uDFFC\u200D(?:\uD83E\uDD1D\u200D\uD83D\uDC68(?:\uD83C[\uDFFB\uDFFD-\uDFFF])|\uD83C[\uDF3E\uDF73\uDF93\uDFA4\uDFA8\uDFEB\uDFED]|\uD83D[\uDCBB\uDCBC\uDD27\uDD2C\uDE80\uDE92]|\uD83E[\uDDAF-\uDDB3\uDDBC\uDDBD])|\uD83C\uDFFB\u200D(?:\uD83E\uDD1D\u200D\uD83D\uDC68(?:\uD83C[\uDFFC-\uDFFF])|\uD83C[\uDF3E\uDF73\uDF93\uDFA4\uDFA8\uDFEB\uDFED]|\uD83D[\uDCBB\uDCBC\uDD27\uDD2C\uDE80\uDE92]|\uD83E[\uDDAF-\uDDB3\uDDBC\uDDBD])|\uD83C\uDFFD\u200D(?:\uD83E\uDD1D\u200D\uD83D\uDC68(?:\uD83C[\uDFFB\uDFFC\uDFFE\uDFFF])|\uD83C[\uDF3E\uDF73\uDF93\uDFA4\uDFA8\uDFEB\uDFED]|\uD83D[\uDCBB\uDCBC\uDD27\uDD2C\uDE80\uDE92]|\uD83E[\uDDAF-\uDDB3\uDDBC\uDDBD])|\u200D(?:\u2764\uFE0F\u200D(?:\uD83D\uDC8B\u200D(?:\uD83D[\uDC68\uDC69])|\uD83D[\uDC68\uDC69])|\uD83C[\uDF3E\uDF73\uDF93\uDFA4\uDFA8\uDFEB\uDFED]|\uD83D[\uDCBB\uDCBC\uDD27\uDD2C\uDE80\uDE92]|\uD83E[\uDDAF-\uDDB3\uDDBC\uDDBD])|\uD83C\uDFFF\u200D(?:\uD83C[\uDF3E\uDF73\uDF93\uDFA4\uDFA8\uDFEB\uDFED]|\uD83D[\uDCBB\uDCBC\uDD27\uDD2C\uDE80\uDE92]|\uD83E[\uDDAF-\uDDB3\uDDBC\uDDBD]))|\uD83D\uDC69\u200D\uD83D\uDC69\u200D(?:\uD83D\uDC66\u200D\uD83D\uDC66|\uD83D\uDC67\u200D(?:\uD83D[\uDC66\uDC67]))|(?:\uD83E\uDDD1\uD83C\uDFFD\u200D\uD83E\uDD1D\u200D\uD83E\uDDD1|\uD83D\uDC69\uD83C\uDFFE\u200D\uD83E\uDD1D\u200D\uD83D\uDC69)(?:\uD83C[\uDFFB-\uDFFD])|\uD83D\uDC69\u200D\uD83D\uDC66\u200D\uD83D\uDC66|\uD83D\uDC69\u200D\uD83D\uDC69\u200D(?:\uD83D[\uDC66\uDC67])|(?:\uD83D\uDC41\uFE0F\u200D\uD83D\uDDE8|\uD83D\uDC69(?:\uD83C\uDFFF\u200D[\u2695\u2696\u2708]|\uD83C\uDFFE\u200D[\u2695\u2696\u2708]|\uD83C\uDFFC\u200D[\u2695\u2696\u2708]|\uD83C\uDFFB\u200D[\u2695\u2696\u2708]|\uD83C\uDFFD\u200D[\u2695\u2696\u2708]|\u200D[\u2695\u2696\u2708])|(?:(?:\u26F9|\uD83C[\uDFCB\uDFCC]|\uD83D\uDD75)\uFE0F|\uD83D\uDC6F|\uD83E[\uDD3C\uDDDE\uDDDF])\u200D[\u2640\u2642]|(?:\u26F9|\uD83C[\uDFCB\uDFCC]|\uD83D\uDD75)(?:\uD83C[\uDFFB-\uDFFF])\u200D[\u2640\u2642]|(?:\uD83C[\uDFC3\uDFC4\uDFCA]|\uD83D[\uDC6E\uDC71\uDC73\uDC77\uDC81\uDC82\uDC86\uDC87\uDE45-\uDE47\uDE4B\uDE4D\uDE4E\uDEA3\uDEB4-\uDEB6]|\uD83E[\uDD26\uDD37-\uDD39\uDD3D\uDD3E\uDDB8\uDDB9\uDDCD-\uDDCF\uDDD6-\uDDDD])(?:(?:\uD83C[\uDFFB-\uDFFF])\u200D[\u2640\u2642]|\u200D[\u2640\u2642])|\uD83C\uDFF4\u200D\u2620)\uFE0F|\uD83D\uDC69\u200D\uD83D\uDC67\u200D(?:\uD83D[\uDC66\uDC67])|\uD83C\uDFF3\uFE0F\u200D\uD83C\uDF08|\uD83D\uDC15\u200D\uD83E\uDDBA|\uD83D\uDC69\u200D\uD83D\uDC66|\uD83D\uDC69\u200D\uD83D\uDC67|\uD83C\uDDFD\uD83C\uDDF0|\uD83C\uDDF4\uD83C\uDDF2|\uD83C\uDDF6\uD83C\uDDE6|[#\*0-9]\uFE0F\u20E3|\uD83C\uDDE7(?:\uD83C[\uDDE6\uDDE7\uDDE9-\uDDEF\uDDF1-\uDDF4\uDDF6-\uDDF9\uDDFB\uDDFC\uDDFE\uDDFF])|\uD83C\uDDF9(?:\uD83C[\uDDE6\uDDE8\uDDE9\uDDEB-\uDDED\uDDEF-\uDDF4\uDDF7\uDDF9\uDDFB\uDDFC\uDDFF])|\uD83C\uDDEA(?:\uD83C[\uDDE6\uDDE8\uDDEA\uDDEC\uDDED\uDDF7-\uDDFA])|\uD83E\uDDD1(?:\uD83C[\uDFFB-\uDFFF])|\uD83C\uDDF7(?:\uD83C[\uDDEA\uDDF4\uDDF8\uDDFA\uDDFC])|\uD83D\uDC69(?:\uD83C[\uDFFB-\uDFFF])|\uD83C\uDDF2(?:\uD83C[\uDDE6\uDDE8-\uDDED\uDDF0-\uDDFF])|\uD83C\uDDE6(?:\uD83C[\uDDE8-\uDDEC\uDDEE\uDDF1\uDDF2\uDDF4\uDDF6-\uDDFA\uDDFC\uDDFD\uDDFF])|\uD83C\uDDF0(?:\uD83C[\uDDEA\uDDEC-\uDDEE\uDDF2\uDDF3\uDDF5\uDDF7\uDDFC\uDDFE\uDDFF])|\uD83C\uDDED(?:\uD83C[\uDDF0\uDDF2\uDDF3\uDDF7\uDDF9\uDDFA])|\uD83C\uDDE9(?:\uD83C[\uDDEA\uDDEC\uDDEF\uDDF0\uDDF2\uDDF4\uDDFF])|\uD83C\uDDFE(?:\uD83C[\uDDEA\uDDF9])|\uD83C\uDDEC(?:\uD83C[\uDDE6\uDDE7\uDDE9-\uDDEE\uDDF1-\uDDF3\uDDF5-\uDDFA\uDDFC\uDDFE])|\uD83C\uDDF8(?:\uD83C[\uDDE6-\uDDEA\uDDEC-\uDDF4\uDDF7-\uDDF9\uDDFB\uDDFD-\uDDFF])|\uD83C\uDDEB(?:\uD83C[\uDDEE-\uDDF0\uDDF2\uDDF4\uDDF7])|\uD83C\uDDF5(?:\uD83C[\uDDE6\uDDEA-\uDDED\uDDF0-\uDDF3\uDDF7-\uDDF9\uDDFC\uDDFE])|\uD83C\uDDFB(?:\uD83C[\uDDE6\uDDE8\uDDEA\uDDEC\uDDEE\uDDF3\uDDFA])|\uD83C\uDDF3(?:\uD83C[\uDDE6\uDDE8\uDDEA-\uDDEC\uDDEE\uDDF1\uDDF4\uDDF5\uDDF7\uDDFA\uDDFF])|\uD83C\uDDE8(?:\uD83C[\uDDE6\uDDE8\uDDE9\uDDEB-\uDDEE\uDDF0-\uDDF5\uDDF7\uDDFA-\uDDFF])|\uD83C\uDDF1(?:\uD83C[\uDDE6-\uDDE8\uDDEE\uDDF0\uDDF7-\uDDFB\uDDFE])|\uD83C\uDDFF(?:\uD83C[\uDDE6\uDDF2\uDDFC])|\uD83C\uDDFC(?:\uD83C[\uDDEB\uDDF8])|\uD83C\uDDFA(?:\uD83C[\uDDE6\uDDEC\uDDF2\uDDF3\uDDF8\uDDFE\uDDFF])|\uD83C\uDDEE(?:\uD83C[\uDDE8-\uDDEA\uDDF1-\uDDF4\uDDF6-\uDDF9])|\uD83C\uDDEF(?:\uD83C[\uDDEA\uDDF2\uDDF4\uDDF5])|(?:\uD83C[\uDFC3\uDFC4\uDFCA]|\uD83D[\uDC6E\uDC71\uDC73\uDC77\uDC81\uDC82\uDC86\uDC87\uDE45-\uDE47\uDE4B\uDE4D\uDE4E\uDEA3\uDEB4-\uDEB6]|\uD83E[\uDD26\uDD37-\uDD39\uDD3D\uDD3E\uDDB8\uDDB9\uDDCD-\uDDCF\uDDD6-\uDDDD])(?:\uD83C[\uDFFB-\uDFFF])|(?:\u26F9|\uD83C[\uDFCB\uDFCC]|\uD83D\uDD75)(?:\uD83C[\uDFFB-\uDFFF])|(?:[\u261D\u270A-\u270D]|\uD83C[\uDF85\uDFC2\uDFC7]|\uD83D[\uDC42\uDC43\uDC46-\uDC50\uDC66\uDC67\uDC6B-\uDC6D\uDC70\uDC72\uDC74-\uDC76\uDC78\uDC7C\uDC83\uDC85\uDCAA\uDD74\uDD7A\uDD90\uDD95\uDD96\uDE4C\uDE4F\uDEC0\uDECC]|\uD83E[\uDD0F\uDD18-\uDD1C\uDD1E\uDD1F\uDD30-\uDD36\uDDB5\uDDB6\uDDBB\uDDD2-\uDDD5])(?:\uD83C[\uDFFB-\uDFFF])|(?:[\u231A\u231B\u23E9-\u23EC\u23F0\u23F3\u25FD\u25FE\u2614\u2615\u2648-\u2653\u267F\u2693\u26A1\u26AA\u26AB\u26BD\u26BE\u26C4\u26C5\u26CE\u26D4\u26EA\u26F2\u26F3\u26F5\u26FA\u26FD\u2705\u270A\u270B\u2728\u274C\u274E\u2753-\u2755\u2757\u2795-\u2797\u27B0\u27BF\u2B1B\u2B1C\u2B50\u2B55]|\uD83C[\uDC04\uDCCF\uDD8E\uDD91-\uDD9A\uDDE6-\uDDFF\uDE01\uDE1A\uDE2F\uDE32-\uDE36\uDE38-\uDE3A\uDE50\uDE51\uDF00-\uDF20\uDF2D-\uDF35\uDF37-\uDF7C\uDF7E-\uDF93\uDFA0-\uDFCA\uDFCF-\uDFD3\uDFE0-\uDFF0\uDFF4\uDFF8-\uDFFF]|\uD83D[\uDC00-\uDC3E\uDC40\uDC42-\uDCFC\uDCFF-\uDD3D\uDD4B-\uDD4E\uDD50-\uDD67\uDD7A\uDD95\uDD96\uDDA4\uDDFB-\uDE4F\uDE80-\uDEC5\uDECC\uDED0-\uDED2\uDED5\uDEEB\uDEEC\uDEF4-\uDEFA\uDFE0-\uDFEB]|\uD83E[\uDD0D-\uDD3A\uDD3C-\uDD45\uDD47-\uDD71\uDD73-\uDD76\uDD7A-\uDDA2\uDDA5-\uDDAA\uDDAE-\uDDCA\uDDCD-\uDDFF\uDE70-\uDE73\uDE78-\uDE7A\uDE80-\uDE82\uDE90-\uDE95])|(?:[#\*0-9\xA9\xAE\u203C\u2049\u2122\u2139\u2194-\u2199\u21A9\u21AA\u231A\u231B\u2328\u23CF\u23E9-\u23F3\u23F8-\u23FA\u24C2\u25AA\u25AB\u25B6\u25C0\u25FB-\u25FE\u2600-\u2604\u260E\u2611\u2614\u2615\u2618\u261D\u2620\u2622\u2623\u2626\u262A\u262E\u262F\u2638-\u263A\u2640\u2642\u2648-\u2653\u265F\u2660\u2663\u2665\u2666\u2668\u267B\u267E\u267F\u2692-\u2697\u2699\u269B\u269C\u26A0\u26A1\u26AA\u26AB\u26B0\u26B1\u26BD\u26BE\u26C4\u26C5\u26C8\u26CE\u26CF\u26D1\u26D3\u26D4\u26E9\u26EA\u26F0-\u26F5\u26F7-\u26FA\u26FD\u2702\u2705\u2708-\u270D\u270F\u2712\u2714\u2716\u271D\u2721\u2728\u2733\u2734\u2744\u2747\u274C\u274E\u2753-\u2755\u2757\u2763\u2764\u2795-\u2797\u27A1\u27B0\u27BF\u2934\u2935\u2B05-\u2B07\u2B1B\u2B1C\u2B50\u2B55\u3030\u303D\u3297\u3299]|\uD83C[\uDC04\uDCCF\uDD70\uDD71\uDD7E\uDD7F\uDD8E\uDD91-\uDD9A\uDDE6-\uDDFF\uDE01\uDE02\uDE1A\uDE2F\uDE32-\uDE3A\uDE50\uDE51\uDF00-\uDF21\uDF24-\uDF93\uDF96\uDF97\uDF99-\uDF9B\uDF9E-\uDFF0\uDFF3-\uDFF5\uDFF7-\uDFFF]|\uD83D[\uDC00-\uDCFD\uDCFF-\uDD3D\uDD49-\uDD4E\uDD50-\uDD67\uDD6F\uDD70\uDD73-\uDD7A\uDD87\uDD8A-\uDD8D\uDD90\uDD95\uDD96\uDDA4\uDDA5\uDDA8\uDDB1\uDDB2\uDDBC\uDDC2-\uDDC4\uDDD1-\uDDD3\uDDDC-\uDDDE\uDDE1\uDDE3\uDDE8\uDDEF\uDDF3\uDDFA-\uDE4F\uDE80-\uDEC5\uDECB-\uDED2\uDED5\uDEE0-\uDEE5\uDEE9\uDEEB\uDEEC\uDEF0\uDEF3-\uDEFA\uDFE0-\uDFEB]|\uD83E[\uDD0D-\uDD3A\uDD3C-\uDD45\uDD47-\uDD71\uDD73-\uDD76\uDD7A-\uDDA2\uDDA5-\uDDAA\uDDAE-\uDDCA\uDDCD-\uDDFF\uDE70-\uDE73\uDE78-\uDE7A\uDE80-\uDE82\uDE90-\uDE95])\uFE0F|(?:[\u261D\u26F9\u270A-\u270D]|\uD83C[\uDF85\uDFC2-\uDFC4\uDFC7\uDFCA-\uDFCC]|\uD83D[\uDC42\uDC43\uDC46-\uDC50\uDC66-\uDC78\uDC7C\uDC81-\uDC83\uDC85-\uDC87\uDC8F\uDC91\uDCAA\uDD74\uDD75\uDD7A\uDD90\uDD95\uDD96\uDE45-\uDE47\uDE4B-\uDE4F\uDEA3\uDEB4-\uDEB6\uDEC0\uDECC]|\uD83E[\uDD0F\uDD18-\uDD1F\uDD26\uDD30-\uDD39\uDD3C-\uDD3E\uDDB5\uDDB6\uDDB8\uDDB9\uDDBB\uDDCD-\uDDCF\uDDD1-\uDDDD])/g;
};


/***/ }),

/***/ 2644:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const { dirname, resolve } = __nccwpck_require__(1017);
const { readdirSync, statSync } = __nccwpck_require__(7147);

module.exports = function (start, callback) {
	let dir = resolve('.', start);
	let tmp, stats = statSync(dir);

	if (!stats.isDirectory()) {
		dir = dirname(dir);
	}

	while (true) {
		tmp = callback(dir, readdirSync(dir));
		if (tmp) return resolve(dir, tmp);
		dir = dirname(tmp = dir);
		if (tmp === dir) break;
	}
}


/***/ }),

/***/ 351:
/***/ ((module) => {

"use strict";

// Call this function in a another function to find out the file from
// which that function was called from. (Inspects the v8 stack trace)
//
// Inspired by http://stackoverflow.com/questions/13227489
module.exports = function getCallerFile(position) {
    if (position === void 0) { position = 2; }
    if (position >= Error.stackTraceLimit) {
        throw new TypeError('getCallerFile(position) requires position be less then Error.stackTraceLimit but position was: `' + position + '` and Error.stackTraceLimit was: `' + Error.stackTraceLimit + '`');
    }
    var oldPrepareStackTrace = Error.prepareStackTrace;
    Error.prepareStackTrace = function (_, stack) { return stack; };
    var stack = new Error().stack;
    Error.prepareStackTrace = oldPrepareStackTrace;
    if (stack !== null && typeof stack === 'object') {
        // stack[0] holds this file
        // stack[1] holds where this function was called
        // stack[2] holds the file we're interested in
        return stack[position] ? stack[position].getFileName() : undefined;
    }
};
//# sourceMappingURL=index.js.map

/***/ }),

/***/ 4882:
/***/ ((module) => {

"use strict";
/* eslint-disable yoda */


const isFullwidthCodePoint = codePoint => {
	if (Number.isNaN(codePoint)) {
		return false;
	}

	// Code points are derived from:
	// http://www.unix.org/Public/UNIDATA/EastAsianWidth.txt
	if (
		codePoint >= 0x1100 && (
			codePoint <= 0x115F || // Hangul Jamo
			codePoint === 0x2329 || // LEFT-POINTING ANGLE BRACKET
			codePoint === 0x232A || // RIGHT-POINTING ANGLE BRACKET
			// CJK Radicals Supplement .. Enclosed CJK Letters and Months
			(0x2E80 <= codePoint && codePoint <= 0x3247 && codePoint !== 0x303F) ||
			// Enclosed CJK Letters and Months .. CJK Unified Ideographs Extension A
			(0x3250 <= codePoint && codePoint <= 0x4DBF) ||
			// CJK Unified Ideographs .. Yi Radicals
			(0x4E00 <= codePoint && codePoint <= 0xA4C6) ||
			// Hangul Jamo Extended-A
			(0xA960 <= codePoint && codePoint <= 0xA97C) ||
			// Hangul Syllables
			(0xAC00 <= codePoint && codePoint <= 0xD7A3) ||
			// CJK Compatibility Ideographs
			(0xF900 <= codePoint && codePoint <= 0xFAFF) ||
			// Vertical Forms
			(0xFE10 <= codePoint && codePoint <= 0xFE19) ||
			// CJK Compatibility Forms .. Small Form Variants
			(0xFE30 <= codePoint && codePoint <= 0xFE6B) ||
			// Halfwidth and Fullwidth Forms
			(0xFF01 <= codePoint && codePoint <= 0xFF60) ||
			(0xFFE0 <= codePoint && codePoint <= 0xFFE6) ||
			// Kana Supplement
			(0x1B000 <= codePoint && codePoint <= 0x1B001) ||
			// Enclosed Ideographic Supplement
			(0x1F200 <= codePoint && codePoint <= 0x1F251) ||
			// CJK Unified Ideographs Extension B .. Tertiary Ideographic Plane
			(0x20000 <= codePoint && codePoint <= 0x3FFFD)
		)
	) {
		return true;
	}

	return false;
};

module.exports = isFullwidthCodePoint;
module.exports["default"] = isFullwidthCodePoint;


/***/ }),

/***/ 9200:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


var fs = __nccwpck_require__(7147),
  join = (__nccwpck_require__(1017).join),
  resolve = (__nccwpck_require__(1017).resolve),
  dirname = (__nccwpck_require__(1017).dirname),
  defaultOptions = {
    extensions: ['js', 'json', 'coffee'],
    recurse: true,
    rename: function (name) {
      return name;
    },
    visit: function (obj) {
      return obj;
    }
  };

function checkFileInclusion(path, filename, options) {
  return (
    // verify file has valid extension
    (new RegExp('\\.(' + options.extensions.join('|') + ')$', 'i').test(filename)) &&

    // if options.include is a RegExp, evaluate it and make sure the path passes
    !(options.include && options.include instanceof RegExp && !options.include.test(path)) &&

    // if options.include is a function, evaluate it and make sure the path passes
    !(options.include && typeof options.include === 'function' && !options.include(path, filename)) &&

    // if options.exclude is a RegExp, evaluate it and make sure the path doesn't pass
    !(options.exclude && options.exclude instanceof RegExp && options.exclude.test(path)) &&

    // if options.exclude is a function, evaluate it and make sure the path doesn't pass
    !(options.exclude && typeof options.exclude === 'function' && options.exclude(path, filename))
  );
}

function requireDirectory(m, path, options) {
  var retval = {};

  // path is optional
  if (path && !options && typeof path !== 'string') {
    options = path;
    path = null;
  }

  // default options
  options = options || {};
  for (var prop in defaultOptions) {
    if (typeof options[prop] === 'undefined') {
      options[prop] = defaultOptions[prop];
    }
  }

  // if no path was passed in, assume the equivelant of __dirname from caller
  // otherwise, resolve path relative to the equivalent of __dirname
  path = !path ? dirname(m.filename) : resolve(dirname(m.filename), path);

  // get the path of each file in specified directory, append to current tree node, recurse
  fs.readdirSync(path).forEach(function (filename) {
    var joined = join(path, filename),
      files,
      key,
      obj;

    if (fs.statSync(joined).isDirectory() && options.recurse) {
      // this node is a directory; recurse
      files = requireDirectory(m, joined, options);
      // exclude empty directories
      if (Object.keys(files).length) {
        retval[options.rename(filename, joined, filename)] = files;
      }
    } else {
      if (joined !== m.filename && checkFileInclusion(joined, filename, options)) {
        // hash node key shouldn't include file extension
        key = filename.substring(0, filename.lastIndexOf('.'));
        obj = m.require(joined);
        retval[options.rename(key, joined, filename)] = options.visit(obj, joined, filename) || obj;
      }
    }
  });

  return retval;
}

module.exports = requireDirectory;
module.exports.defaults = defaultOptions;


/***/ }),

/***/ 2577:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

const stripAnsi = __nccwpck_require__(5591);
const isFullwidthCodePoint = __nccwpck_require__(4882);
const emojiRegex = __nccwpck_require__(8212);

const stringWidth = string => {
	if (typeof string !== 'string' || string.length === 0) {
		return 0;
	}

	string = stripAnsi(string);

	if (string.length === 0) {
		return 0;
	}

	string = string.replace(emojiRegex(), '  ');

	let width = 0;

	for (let i = 0; i < string.length; i++) {
		const code = string.codePointAt(i);

		// Ignore control characters
		if (code <= 0x1F || (code >= 0x7F && code <= 0x9F)) {
			continue;
		}

		// Ignore combining characters
		if (code >= 0x300 && code <= 0x36F) {
			continue;
		}

		// Surrogates
		if (code > 0xFFFF) {
			i++;
		}

		width += isFullwidthCodePoint(code) ? 2 : 1;
	}

	return width;
};

module.exports = stringWidth;
// TODO: remove this in the next major version
module.exports["default"] = stringWidth;


/***/ }),

/***/ 5591:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

const ansiRegex = __nccwpck_require__(5063);

module.exports = string => typeof string === 'string' ? string.replace(ansiRegex(), '') : string;


/***/ }),

/***/ 4294:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

module.exports = __nccwpck_require__(4219);


/***/ }),

/***/ 4219:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


var net = __nccwpck_require__(1808);
var tls = __nccwpck_require__(4404);
var http = __nccwpck_require__(3685);
var https = __nccwpck_require__(5687);
var events = __nccwpck_require__(2361);
var assert = __nccwpck_require__(9491);
var util = __nccwpck_require__(3837);


exports.httpOverHttp = httpOverHttp;
exports.httpsOverHttp = httpsOverHttp;
exports.httpOverHttps = httpOverHttps;
exports.httpsOverHttps = httpsOverHttps;


function httpOverHttp(options) {
  var agent = new TunnelingAgent(options);
  agent.request = http.request;
  return agent;
}

function httpsOverHttp(options) {
  var agent = new TunnelingAgent(options);
  agent.request = http.request;
  agent.createSocket = createSecureSocket;
  agent.defaultPort = 443;
  return agent;
}

function httpOverHttps(options) {
  var agent = new TunnelingAgent(options);
  agent.request = https.request;
  return agent;
}

function httpsOverHttps(options) {
  var agent = new TunnelingAgent(options);
  agent.request = https.request;
  agent.createSocket = createSecureSocket;
  agent.defaultPort = 443;
  return agent;
}


function TunnelingAgent(options) {
  var self = this;
  self.options = options || {};
  self.proxyOptions = self.options.proxy || {};
  self.maxSockets = self.options.maxSockets || http.Agent.defaultMaxSockets;
  self.requests = [];
  self.sockets = [];

  self.on('free', function onFree(socket, host, port, localAddress) {
    var options = toOptions(host, port, localAddress);
    for (var i = 0, len = self.requests.length; i < len; ++i) {
      var pending = self.requests[i];
      if (pending.host === options.host && pending.port === options.port) {
        // Detect the request to connect same origin server,
        // reuse the connection.
        self.requests.splice(i, 1);
        pending.request.onSocket(socket);
        return;
      }
    }
    socket.destroy();
    self.removeSocket(socket);
  });
}
util.inherits(TunnelingAgent, events.EventEmitter);

TunnelingAgent.prototype.addRequest = function addRequest(req, host, port, localAddress) {
  var self = this;
  var options = mergeOptions({request: req}, self.options, toOptions(host, port, localAddress));

  if (self.sockets.length >= this.maxSockets) {
    // We are over limit so we'll add it to the queue.
    self.requests.push(options);
    return;
  }

  // If we are under maxSockets create a new one.
  self.createSocket(options, function(socket) {
    socket.on('free', onFree);
    socket.on('close', onCloseOrRemove);
    socket.on('agentRemove', onCloseOrRemove);
    req.onSocket(socket);

    function onFree() {
      self.emit('free', socket, options);
    }

    function onCloseOrRemove(err) {
      self.removeSocket(socket);
      socket.removeListener('free', onFree);
      socket.removeListener('close', onCloseOrRemove);
      socket.removeListener('agentRemove', onCloseOrRemove);
    }
  });
};

TunnelingAgent.prototype.createSocket = function createSocket(options, cb) {
  var self = this;
  var placeholder = {};
  self.sockets.push(placeholder);

  var connectOptions = mergeOptions({}, self.proxyOptions, {
    method: 'CONNECT',
    path: options.host + ':' + options.port,
    agent: false,
    headers: {
      host: options.host + ':' + options.port
    }
  });
  if (options.localAddress) {
    connectOptions.localAddress = options.localAddress;
  }
  if (connectOptions.proxyAuth) {
    connectOptions.headers = connectOptions.headers || {};
    connectOptions.headers['Proxy-Authorization'] = 'Basic ' +
        new Buffer(connectOptions.proxyAuth).toString('base64');
  }

  debug('making CONNECT request');
  var connectReq = self.request(connectOptions);
  connectReq.useChunkedEncodingByDefault = false; // for v0.6
  connectReq.once('response', onResponse); // for v0.6
  connectReq.once('upgrade', onUpgrade);   // for v0.6
  connectReq.once('connect', onConnect);   // for v0.7 or later
  connectReq.once('error', onError);
  connectReq.end();

  function onResponse(res) {
    // Very hacky. This is necessary to avoid http-parser leaks.
    res.upgrade = true;
  }

  function onUpgrade(res, socket, head) {
    // Hacky.
    process.nextTick(function() {
      onConnect(res, socket, head);
    });
  }

  function onConnect(res, socket, head) {
    connectReq.removeAllListeners();
    socket.removeAllListeners();

    if (res.statusCode !== 200) {
      debug('tunneling socket could not be established, statusCode=%d',
        res.statusCode);
      socket.destroy();
      var error = new Error('tunneling socket could not be established, ' +
        'statusCode=' + res.statusCode);
      error.code = 'ECONNRESET';
      options.request.emit('error', error);
      self.removeSocket(placeholder);
      return;
    }
    if (head.length > 0) {
      debug('got illegal response body from proxy');
      socket.destroy();
      var error = new Error('got illegal response body from proxy');
      error.code = 'ECONNRESET';
      options.request.emit('error', error);
      self.removeSocket(placeholder);
      return;
    }
    debug('tunneling connection has established');
    self.sockets[self.sockets.indexOf(placeholder)] = socket;
    return cb(socket);
  }

  function onError(cause) {
    connectReq.removeAllListeners();

    debug('tunneling socket could not be established, cause=%s\n',
          cause.message, cause.stack);
    var error = new Error('tunneling socket could not be established, ' +
                          'cause=' + cause.message);
    error.code = 'ECONNRESET';
    options.request.emit('error', error);
    self.removeSocket(placeholder);
  }
};

TunnelingAgent.prototype.removeSocket = function removeSocket(socket) {
  var pos = this.sockets.indexOf(socket)
  if (pos === -1) {
    return;
  }
  this.sockets.splice(pos, 1);

  var pending = this.requests.shift();
  if (pending) {
    // If we have pending requests and a socket gets closed a new one
    // needs to be created to take over in the pool for the one that closed.
    this.createSocket(pending, function(socket) {
      pending.request.onSocket(socket);
    });
  }
};

function createSecureSocket(options, cb) {
  var self = this;
  TunnelingAgent.prototype.createSocket.call(self, options, function(socket) {
    var hostHeader = options.request.getHeader('host');
    var tlsOptions = mergeOptions({}, self.options, {
      socket: socket,
      servername: hostHeader ? hostHeader.replace(/:.*$/, '') : options.host
    });

    // 0 is dummy port for v0.6
    var secureSocket = tls.connect(0, tlsOptions);
    self.sockets[self.sockets.indexOf(socket)] = secureSocket;
    cb(secureSocket);
  });
}


function toOptions(host, port, localAddress) {
  if (typeof host === 'string') { // since v0.10
    return {
      host: host,
      port: port,
      localAddress: localAddress
    };
  }
  return host; // for v0.11 or later
}

function mergeOptions(target) {
  for (var i = 1, len = arguments.length; i < len; ++i) {
    var overrides = arguments[i];
    if (typeof overrides === 'object') {
      var keys = Object.keys(overrides);
      for (var j = 0, keyLen = keys.length; j < keyLen; ++j) {
        var k = keys[j];
        if (overrides[k] !== undefined) {
          target[k] = overrides[k];
        }
      }
    }
  }
  return target;
}


var debug;
if (process.env.NODE_DEBUG && /\btunnel\b/.test(process.env.NODE_DEBUG)) {
  debug = function() {
    var args = Array.prototype.slice.call(arguments);
    if (typeof args[0] === 'string') {
      args[0] = 'TUNNEL: ' + args[0];
    } else {
      args.unshift('TUNNEL:');
    }
    console.error.apply(console, args);
  }
} else {
  debug = function() {};
}
exports.debug = debug; // for test


/***/ }),

/***/ 5840:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
Object.defineProperty(exports, "v1", ({
  enumerable: true,
  get: function () {
    return _v.default;
  }
}));
Object.defineProperty(exports, "v3", ({
  enumerable: true,
  get: function () {
    return _v2.default;
  }
}));
Object.defineProperty(exports, "v4", ({
  enumerable: true,
  get: function () {
    return _v3.default;
  }
}));
Object.defineProperty(exports, "v5", ({
  enumerable: true,
  get: function () {
    return _v4.default;
  }
}));
Object.defineProperty(exports, "NIL", ({
  enumerable: true,
  get: function () {
    return _nil.default;
  }
}));
Object.defineProperty(exports, "version", ({
  enumerable: true,
  get: function () {
    return _version.default;
  }
}));
Object.defineProperty(exports, "validate", ({
  enumerable: true,
  get: function () {
    return _validate.default;
  }
}));
Object.defineProperty(exports, "stringify", ({
  enumerable: true,
  get: function () {
    return _stringify.default;
  }
}));
Object.defineProperty(exports, "parse", ({
  enumerable: true,
  get: function () {
    return _parse.default;
  }
}));

var _v = _interopRequireDefault(__nccwpck_require__(8628));

var _v2 = _interopRequireDefault(__nccwpck_require__(6409));

var _v3 = _interopRequireDefault(__nccwpck_require__(5122));

var _v4 = _interopRequireDefault(__nccwpck_require__(9120));

var _nil = _interopRequireDefault(__nccwpck_require__(5332));

var _version = _interopRequireDefault(__nccwpck_require__(1595));

var _validate = _interopRequireDefault(__nccwpck_require__(6900));

var _stringify = _interopRequireDefault(__nccwpck_require__(8950));

var _parse = _interopRequireDefault(__nccwpck_require__(2746));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/***/ }),

/***/ 4569:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _crypto = _interopRequireDefault(__nccwpck_require__(6113));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function md5(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === 'string') {
    bytes = Buffer.from(bytes, 'utf8');
  }

  return _crypto.default.createHash('md5').update(bytes).digest();
}

var _default = md5;
exports["default"] = _default;

/***/ }),

/***/ 5332:
/***/ ((__unused_webpack_module, exports) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;
var _default = '00000000-0000-0000-0000-000000000000';
exports["default"] = _default;

/***/ }),

/***/ 2746:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _validate = _interopRequireDefault(__nccwpck_require__(6900));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function parse(uuid) {
  if (!(0, _validate.default)(uuid)) {
    throw TypeError('Invalid UUID');
  }

  let v;
  const arr = new Uint8Array(16); // Parse ########-....-....-....-............

  arr[0] = (v = parseInt(uuid.slice(0, 8), 16)) >>> 24;
  arr[1] = v >>> 16 & 0xff;
  arr[2] = v >>> 8 & 0xff;
  arr[3] = v & 0xff; // Parse ........-####-....-....-............

  arr[4] = (v = parseInt(uuid.slice(9, 13), 16)) >>> 8;
  arr[5] = v & 0xff; // Parse ........-....-####-....-............

  arr[6] = (v = parseInt(uuid.slice(14, 18), 16)) >>> 8;
  arr[7] = v & 0xff; // Parse ........-....-....-####-............

  arr[8] = (v = parseInt(uuid.slice(19, 23), 16)) >>> 8;
  arr[9] = v & 0xff; // Parse ........-....-....-....-############
  // (Use "/" to avoid 32-bit truncation when bit-shifting high-order bytes)

  arr[10] = (v = parseInt(uuid.slice(24, 36), 16)) / 0x10000000000 & 0xff;
  arr[11] = v / 0x100000000 & 0xff;
  arr[12] = v >>> 24 & 0xff;
  arr[13] = v >>> 16 & 0xff;
  arr[14] = v >>> 8 & 0xff;
  arr[15] = v & 0xff;
  return arr;
}

var _default = parse;
exports["default"] = _default;

/***/ }),

/***/ 814:
/***/ ((__unused_webpack_module, exports) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;
var _default = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;
exports["default"] = _default;

/***/ }),

/***/ 807:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = rng;

var _crypto = _interopRequireDefault(__nccwpck_require__(6113));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const rnds8Pool = new Uint8Array(256); // # of random values to pre-allocate

let poolPtr = rnds8Pool.length;

function rng() {
  if (poolPtr > rnds8Pool.length - 16) {
    _crypto.default.randomFillSync(rnds8Pool);

    poolPtr = 0;
  }

  return rnds8Pool.slice(poolPtr, poolPtr += 16);
}

/***/ }),

/***/ 5274:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _crypto = _interopRequireDefault(__nccwpck_require__(6113));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function sha1(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === 'string') {
    bytes = Buffer.from(bytes, 'utf8');
  }

  return _crypto.default.createHash('sha1').update(bytes).digest();
}

var _default = sha1;
exports["default"] = _default;

/***/ }),

/***/ 8950:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _validate = _interopRequireDefault(__nccwpck_require__(6900));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * Convert array of 16 byte values to UUID string format of the form:
 * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 */
const byteToHex = [];

for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 0x100).toString(16).substr(1));
}

function stringify(arr, offset = 0) {
  // Note: Be careful editing this code!  It's been tuned for performance
  // and works in ways you may not expect. See https://github.com/uuidjs/uuid/pull/434
  const uuid = (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase(); // Consistency check for valid UUID.  If this throws, it's likely due to one
  // of the following:
  // - One or more input array values don't map to a hex octet (leading to
  // "undefined" in the uuid)
  // - Invalid input values for the RFC `version` or `variant` fields

  if (!(0, _validate.default)(uuid)) {
    throw TypeError('Stringified UUID is invalid');
  }

  return uuid;
}

var _default = stringify;
exports["default"] = _default;

/***/ }),

/***/ 8628:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _rng = _interopRequireDefault(__nccwpck_require__(807));

var _stringify = _interopRequireDefault(__nccwpck_require__(8950));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// **`v1()` - Generate time-based UUID**
//
// Inspired by https://github.com/LiosK/UUID.js
// and http://docs.python.org/library/uuid.html
let _nodeId;

let _clockseq; // Previous uuid creation time


let _lastMSecs = 0;
let _lastNSecs = 0; // See https://github.com/uuidjs/uuid for API details

function v1(options, buf, offset) {
  let i = buf && offset || 0;
  const b = buf || new Array(16);
  options = options || {};
  let node = options.node || _nodeId;
  let clockseq = options.clockseq !== undefined ? options.clockseq : _clockseq; // node and clockseq need to be initialized to random values if they're not
  // specified.  We do this lazily to minimize issues related to insufficient
  // system entropy.  See #189

  if (node == null || clockseq == null) {
    const seedBytes = options.random || (options.rng || _rng.default)();

    if (node == null) {
      // Per 4.5, create and 48-bit node id, (47 random bits + multicast bit = 1)
      node = _nodeId = [seedBytes[0] | 0x01, seedBytes[1], seedBytes[2], seedBytes[3], seedBytes[4], seedBytes[5]];
    }

    if (clockseq == null) {
      // Per 4.2.2, randomize (14 bit) clockseq
      clockseq = _clockseq = (seedBytes[6] << 8 | seedBytes[7]) & 0x3fff;
    }
  } // UUID timestamps are 100 nano-second units since the Gregorian epoch,
  // (1582-10-15 00:00).  JSNumbers aren't precise enough for this, so
  // time is handled internally as 'msecs' (integer milliseconds) and 'nsecs'
  // (100-nanoseconds offset from msecs) since unix epoch, 1970-01-01 00:00.


  let msecs = options.msecs !== undefined ? options.msecs : Date.now(); // Per 4.2.1.2, use count of uuid's generated during the current clock
  // cycle to simulate higher resolution clock

  let nsecs = options.nsecs !== undefined ? options.nsecs : _lastNSecs + 1; // Time since last uuid creation (in msecs)

  const dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 10000; // Per 4.2.1.2, Bump clockseq on clock regression

  if (dt < 0 && options.clockseq === undefined) {
    clockseq = clockseq + 1 & 0x3fff;
  } // Reset nsecs if clock regresses (new clockseq) or we've moved onto a new
  // time interval


  if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === undefined) {
    nsecs = 0;
  } // Per 4.2.1.2 Throw error if too many uuids are requested


  if (nsecs >= 10000) {
    throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
  }

  _lastMSecs = msecs;
  _lastNSecs = nsecs;
  _clockseq = clockseq; // Per 4.1.4 - Convert from unix epoch to Gregorian epoch

  msecs += 12219292800000; // `time_low`

  const tl = ((msecs & 0xfffffff) * 10000 + nsecs) % 0x100000000;
  b[i++] = tl >>> 24 & 0xff;
  b[i++] = tl >>> 16 & 0xff;
  b[i++] = tl >>> 8 & 0xff;
  b[i++] = tl & 0xff; // `time_mid`

  const tmh = msecs / 0x100000000 * 10000 & 0xfffffff;
  b[i++] = tmh >>> 8 & 0xff;
  b[i++] = tmh & 0xff; // `time_high_and_version`

  b[i++] = tmh >>> 24 & 0xf | 0x10; // include version

  b[i++] = tmh >>> 16 & 0xff; // `clock_seq_hi_and_reserved` (Per 4.2.2 - include variant)

  b[i++] = clockseq >>> 8 | 0x80; // `clock_seq_low`

  b[i++] = clockseq & 0xff; // `node`

  for (let n = 0; n < 6; ++n) {
    b[i + n] = node[n];
  }

  return buf || (0, _stringify.default)(b);
}

var _default = v1;
exports["default"] = _default;

/***/ }),

/***/ 6409:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _v = _interopRequireDefault(__nccwpck_require__(5998));

var _md = _interopRequireDefault(__nccwpck_require__(4569));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const v3 = (0, _v.default)('v3', 0x30, _md.default);
var _default = v3;
exports["default"] = _default;

/***/ }),

/***/ 5998:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = _default;
exports.URL = exports.DNS = void 0;

var _stringify = _interopRequireDefault(__nccwpck_require__(8950));

var _parse = _interopRequireDefault(__nccwpck_require__(2746));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function stringToBytes(str) {
  str = unescape(encodeURIComponent(str)); // UTF8 escape

  const bytes = [];

  for (let i = 0; i < str.length; ++i) {
    bytes.push(str.charCodeAt(i));
  }

  return bytes;
}

const DNS = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
exports.DNS = DNS;
const URL = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';
exports.URL = URL;

function _default(name, version, hashfunc) {
  function generateUUID(value, namespace, buf, offset) {
    if (typeof value === 'string') {
      value = stringToBytes(value);
    }

    if (typeof namespace === 'string') {
      namespace = (0, _parse.default)(namespace);
    }

    if (namespace.length !== 16) {
      throw TypeError('Namespace must be array-like (16 iterable integer values, 0-255)');
    } // Compute hash of namespace and value, Per 4.3
    // Future: Use spread syntax when supported on all platforms, e.g. `bytes =
    // hashfunc([...namespace, ... value])`


    let bytes = new Uint8Array(16 + value.length);
    bytes.set(namespace);
    bytes.set(value, namespace.length);
    bytes = hashfunc(bytes);
    bytes[6] = bytes[6] & 0x0f | version;
    bytes[8] = bytes[8] & 0x3f | 0x80;

    if (buf) {
      offset = offset || 0;

      for (let i = 0; i < 16; ++i) {
        buf[offset + i] = bytes[i];
      }

      return buf;
    }

    return (0, _stringify.default)(bytes);
  } // Function#name is not settable on some platforms (#270)


  try {
    generateUUID.name = name; // eslint-disable-next-line no-empty
  } catch (err) {} // For CommonJS default export support


  generateUUID.DNS = DNS;
  generateUUID.URL = URL;
  return generateUUID;
}

/***/ }),

/***/ 5122:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _rng = _interopRequireDefault(__nccwpck_require__(807));

var _stringify = _interopRequireDefault(__nccwpck_require__(8950));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function v4(options, buf, offset) {
  options = options || {};

  const rnds = options.random || (options.rng || _rng.default)(); // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`


  rnds[6] = rnds[6] & 0x0f | 0x40;
  rnds[8] = rnds[8] & 0x3f | 0x80; // Copy bytes to buffer, if provided

  if (buf) {
    offset = offset || 0;

    for (let i = 0; i < 16; ++i) {
      buf[offset + i] = rnds[i];
    }

    return buf;
  }

  return (0, _stringify.default)(rnds);
}

var _default = v4;
exports["default"] = _default;

/***/ }),

/***/ 9120:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _v = _interopRequireDefault(__nccwpck_require__(5998));

var _sha = _interopRequireDefault(__nccwpck_require__(5274));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const v5 = (0, _v.default)('v5', 0x50, _sha.default);
var _default = v5;
exports["default"] = _default;

/***/ }),

/***/ 6900:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _regex = _interopRequireDefault(__nccwpck_require__(814));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function validate(uuid) {
  return typeof uuid === 'string' && _regex.default.test(uuid);
}

var _default = validate;
exports["default"] = _default;

/***/ }),

/***/ 1595:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _validate = _interopRequireDefault(__nccwpck_require__(6900));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function version(uuid) {
  if (!(0, _validate.default)(uuid)) {
    throw TypeError('Invalid UUID');
  }

  return parseInt(uuid.substr(14, 1), 16);
}

var _default = version;
exports["default"] = _default;

/***/ }),

/***/ 9824:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

const stringWidth = __nccwpck_require__(2577);
const stripAnsi = __nccwpck_require__(5591);
const ansiStyles = __nccwpck_require__(2068);

const ESCAPES = new Set([
	'\u001B',
	'\u009B'
]);

const END_CODE = 39;

const ANSI_ESCAPE_BELL = '\u0007';
const ANSI_CSI = '[';
const ANSI_OSC = ']';
const ANSI_SGR_TERMINATOR = 'm';
const ANSI_ESCAPE_LINK = `${ANSI_OSC}8;;`;

const wrapAnsi = code => `${ESCAPES.values().next().value}${ANSI_CSI}${code}${ANSI_SGR_TERMINATOR}`;
const wrapAnsiHyperlink = uri => `${ESCAPES.values().next().value}${ANSI_ESCAPE_LINK}${uri}${ANSI_ESCAPE_BELL}`;

// Calculate the length of words split on ' ', ignoring
// the extra characters added by ansi escape codes
const wordLengths = string => string.split(' ').map(character => stringWidth(character));

// Wrap a long word across multiple rows
// Ansi escape codes do not count towards length
const wrapWord = (rows, word, columns) => {
	const characters = [...word];

	let isInsideEscape = false;
	let isInsideLinkEscape = false;
	let visible = stringWidth(stripAnsi(rows[rows.length - 1]));

	for (const [index, character] of characters.entries()) {
		const characterLength = stringWidth(character);

		if (visible + characterLength <= columns) {
			rows[rows.length - 1] += character;
		} else {
			rows.push(character);
			visible = 0;
		}

		if (ESCAPES.has(character)) {
			isInsideEscape = true;
			isInsideLinkEscape = characters.slice(index + 1).join('').startsWith(ANSI_ESCAPE_LINK);
		}

		if (isInsideEscape) {
			if (isInsideLinkEscape) {
				if (character === ANSI_ESCAPE_BELL) {
					isInsideEscape = false;
					isInsideLinkEscape = false;
				}
			} else if (character === ANSI_SGR_TERMINATOR) {
				isInsideEscape = false;
			}

			continue;
		}

		visible += characterLength;

		if (visible === columns && index < characters.length - 1) {
			rows.push('');
			visible = 0;
		}
	}

	// It's possible that the last row we copy over is only
	// ansi escape characters, handle this edge-case
	if (!visible && rows[rows.length - 1].length > 0 && rows.length > 1) {
		rows[rows.length - 2] += rows.pop();
	}
};

// Trims spaces from a string ignoring invisible sequences
const stringVisibleTrimSpacesRight = string => {
	const words = string.split(' ');
	let last = words.length;

	while (last > 0) {
		if (stringWidth(words[last - 1]) > 0) {
			break;
		}

		last--;
	}

	if (last === words.length) {
		return string;
	}

	return words.slice(0, last).join(' ') + words.slice(last).join('');
};

// The wrap-ansi module can be invoked in either 'hard' or 'soft' wrap mode
//
// 'hard' will never allow a string to take up more than columns characters
//
// 'soft' allows long words to expand past the column length
const exec = (string, columns, options = {}) => {
	if (options.trim !== false && string.trim() === '') {
		return '';
	}

	let returnValue = '';
	let escapeCode;
	let escapeUrl;

	const lengths = wordLengths(string);
	let rows = [''];

	for (const [index, word] of string.split(' ').entries()) {
		if (options.trim !== false) {
			rows[rows.length - 1] = rows[rows.length - 1].trimStart();
		}

		let rowLength = stringWidth(rows[rows.length - 1]);

		if (index !== 0) {
			if (rowLength >= columns && (options.wordWrap === false || options.trim === false)) {
				// If we start with a new word but the current row length equals the length of the columns, add a new row
				rows.push('');
				rowLength = 0;
			}

			if (rowLength > 0 || options.trim === false) {
				rows[rows.length - 1] += ' ';
				rowLength++;
			}
		}

		// In 'hard' wrap mode, the length of a line is never allowed to extend past 'columns'
		if (options.hard && lengths[index] > columns) {
			const remainingColumns = (columns - rowLength);
			const breaksStartingThisLine = 1 + Math.floor((lengths[index] - remainingColumns - 1) / columns);
			const breaksStartingNextLine = Math.floor((lengths[index] - 1) / columns);
			if (breaksStartingNextLine < breaksStartingThisLine) {
				rows.push('');
			}

			wrapWord(rows, word, columns);
			continue;
		}

		if (rowLength + lengths[index] > columns && rowLength > 0 && lengths[index] > 0) {
			if (options.wordWrap === false && rowLength < columns) {
				wrapWord(rows, word, columns);
				continue;
			}

			rows.push('');
		}

		if (rowLength + lengths[index] > columns && options.wordWrap === false) {
			wrapWord(rows, word, columns);
			continue;
		}

		rows[rows.length - 1] += word;
	}

	if (options.trim !== false) {
		rows = rows.map(stringVisibleTrimSpacesRight);
	}

	const pre = [...rows.join('\n')];

	for (const [index, character] of pre.entries()) {
		returnValue += character;

		if (ESCAPES.has(character)) {
			const {groups} = new RegExp(`(?:\\${ANSI_CSI}(?<code>\\d+)m|\\${ANSI_ESCAPE_LINK}(?<uri>.*)${ANSI_ESCAPE_BELL})`).exec(pre.slice(index).join('')) || {groups: {}};
			if (groups.code !== undefined) {
				const code = Number.parseFloat(groups.code);
				escapeCode = code === END_CODE ? undefined : code;
			} else if (groups.uri !== undefined) {
				escapeUrl = groups.uri.length === 0 ? undefined : groups.uri;
			}
		}

		const code = ansiStyles.codes.get(Number(escapeCode));

		if (pre[index + 1] === '\n') {
			if (escapeUrl) {
				returnValue += wrapAnsiHyperlink('');
			}

			if (escapeCode && code) {
				returnValue += wrapAnsi(code);
			}
		} else if (character === '\n') {
			if (escapeCode && code) {
				returnValue += wrapAnsi(escapeCode);
			}

			if (escapeUrl) {
				returnValue += wrapAnsiHyperlink(escapeUrl);
			}
		}
	}

	return returnValue;
};

// For each newline, invoke the method separately
module.exports = (string, columns, options) => {
	return String(string)
		.normalize()
		.replace(/\r\n/g, '\n')
		.split('\n')
		.map(line => exec(line, columns, options))
		.join('\n');
};


/***/ }),

/***/ 5319:
/***/ ((__unused_webpack_module, exports) => {

/*
 * xpath.js
 *
 * An XPath 1.0 library for JavaScript.
 *
 * Cameron McCormack <cam (at) mcc.id.au>
 *
 * This work is licensed under the MIT License.
 *
 * Revision 20: April 26, 2011
 *   Fixed a typo resulting in FIRST_ORDERED_NODE_TYPE results being wrong,
 *   thanks to <shi_a009 (at) hotmail.com>.
 *
 * Revision 19: November 29, 2005
 *   Nodesets now store their nodes in a height balanced tree, increasing
 *   performance for the common case of selecting nodes in document order,
 *   thanks to Sébastien Cramatte <contact (at) zeninteractif.com>.
 *   AVL tree code adapted from Raimund Neumann <rnova (at) gmx.net>.
 *
 * Revision 18: October 27, 2005
 *   DOM 3 XPath support.  Caveats:
 *     - namespace prefixes aren't resolved in XPathEvaluator.createExpression,
 *       but in XPathExpression.evaluate.
 *     - XPathResult.invalidIteratorState is not implemented.
 *
 * Revision 17: October 25, 2005
 *   Some core XPath function fixes and a patch to avoid crashing certain
 *   versions of MSXML in PathExpr.prototype.getOwnerElement, thanks to
 *   Sébastien Cramatte <contact (at) zeninteractif.com>.
 *
 * Revision 16: September 22, 2005
 *   Workarounds for some IE 5.5 deficiencies.
 *   Fixed problem with prefix node tests on attribute nodes.
 *
 * Revision 15: May 21, 2005
 *   Fixed problem with QName node tests on elements with an xmlns="...".
 *
 * Revision 14: May 19, 2005
 *   Fixed QName node tests on attribute node regression.
 *
 * Revision 13: May 3, 2005
 *   Node tests are case insensitive now if working in an HTML DOM.
 *
 * Revision 12: April 26, 2005
 *   Updated licence.  Slight code changes to enable use of Dean
 *   Edwards' script compression, http://dean.edwards.name/packer/ .
 *
 * Revision 11: April 23, 2005
 *   Fixed bug with 'and' and 'or' operators, fix thanks to
 *   Sandy McArthur <sandy (at) mcarthur.org>.
 *
 * Revision 10: April 15, 2005
 *   Added support for a virtual root node, supposedly helpful for
 *   implementing XForms.  Fixed problem with QName node tests and
 *   the parent axis.
 *
 * Revision 9: March 17, 2005
 *   Namespace resolver tweaked so using the document node as the context
 *   for namespace lookups is equivalent to using the document element.
 *
 * Revision 8: February 13, 2005
 *   Handle implicit declaration of 'xmlns' namespace prefix.
 *   Fixed bug when comparing nodesets.
 *   Instance data can now be associated with a FunctionResolver, and
 *     workaround for MSXML not supporting 'localName' and 'getElementById',
 *     thanks to Grant Gongaware.
 *   Fix a few problems when the context node is the root node.
 *
 * Revision 7: February 11, 2005
 *   Default namespace resolver fix from Grant Gongaware
 *   <grant (at) gongaware.com>.
 *
 * Revision 6: February 10, 2005
 *   Fixed bug in 'number' function.
 *
 * Revision 5: February 9, 2005
 *   Fixed bug where text nodes not getting converted to string values.
 *
 * Revision 4: January 21, 2005
 *   Bug in 'name' function, fix thanks to Bill Edney.
 *   Fixed incorrect processing of namespace nodes.
 *   Fixed NamespaceResolver to resolve 'xml' namespace.
 *   Implemented union '|' operator.
 *
 * Revision 3: January 14, 2005
 *   Fixed bug with nodeset comparisons, bug lexing < and >.
 *
 * Revision 2: October 26, 2004
 *   QName node test namespace handling fixed.  Few other bug fixes.
 *
 * Revision 1: August 13, 2004
 *   Bug fixes from William J. Edney <bedney (at) technicalpursuit.com>.
 *   Added minimal licence.
 *
 * Initial version: June 14, 2004
 */

// non-node wrapper
var xpath = ( false) ? 0 : exports;

(function (exports) {
    "use strict";

    // functional helpers
    function curry(func) {
        var slice = Array.prototype.slice,
            totalargs = func.length,
            partial = function (args, fn) {
                return function () {
                    return fn.apply(this, args.concat(slice.call(arguments)));
                }
            },
            fn = function () {
                var args = slice.call(arguments);
                return (args.length < totalargs) ?
                    partial(args, fn) :
                    func.apply(this, slice.apply(arguments, [0, totalargs]));
            };
        return fn;
    }

    var forEach = function (f, xs) {
        for (var i = 0; i < xs.length; i += 1) {
            f(xs[i], i, xs);
        }
    };

    var reduce = function (f, seed, xs) {
        var acc = seed;

        forEach(function (x, i) { acc = f(acc, x, i); }, xs);

        return acc;
    };

    var map = function (f, xs) {
        var mapped = new Array(xs.length);

        forEach(function (x, i) { mapped[i] = f(x); }, xs);

        return mapped;
    };

    var filter = function (f, xs) {
        var filtered = [];

        forEach(function (x, i) { if (f(x, i)) { filtered.push(x); } }, xs);

        return filtered;
    };

    var includes = function (values, value) {
        for (var i = 0; i < values.length; i += 1) {
            if (values[i] === value) {
                return true;
            }
        }

        return false;
    };

    function always(value) { return function () { return value; } }

    function toString(x) { return x.toString(); }
    var join = function (s, xs) { return xs.join(s); };
    var wrap = function (pref, suf, str) { return pref + str + suf; };

    var prototypeConcat = Array.prototype.concat;

    // .apply() fails above a certain number of arguments - https://github.com/goto100/xpath/pull/98
    var MAX_ARGUMENT_LENGTH = 32767;

    function flatten(arr) {
        var result = [];

        for (var start = 0; start < arr.length; start += MAX_ARGUMENT_LENGTH) {
            var chunk = arr.slice(start, start + MAX_ARGUMENT_LENGTH);
            
            result = prototypeConcat.apply(result, chunk);
        }
        
        return result;
    }

    function assign(target, varArgs) { // .length of function is 2
        var to = Object(target);

        for (var index = 1; index < arguments.length; index++) {
            var nextSource = arguments[index];

            if (nextSource != null) { // Skip over if undefined or null
                for (var nextKey in nextSource) {
                    // Avoid bugs when hasOwnProperty is shadowed
                    if (Object.prototype.hasOwnProperty.call(nextSource, nextKey)) {
                        to[nextKey] = nextSource[nextKey];
                    }
                }
            }
        }

        return to;
    }

    // XPathParser ///////////////////////////////////////////////////////////////

    XPathParser.prototype = new Object();
    XPathParser.prototype.constructor = XPathParser;
    XPathParser.superclass = Object.prototype;

    function XPathParser() {
        this.init();
    }

    XPathParser.prototype.init = function () {
        this.reduceActions = [];

        this.reduceActions[3] = function (rhs) {
            return new OrOperation(rhs[0], rhs[2]);
        };
        this.reduceActions[5] = function (rhs) {
            return new AndOperation(rhs[0], rhs[2]);
        };
        this.reduceActions[7] = function (rhs) {
            return new EqualsOperation(rhs[0], rhs[2]);
        };
        this.reduceActions[8] = function (rhs) {
            return new NotEqualOperation(rhs[0], rhs[2]);
        };
        this.reduceActions[10] = function (rhs) {
            return new LessThanOperation(rhs[0], rhs[2]);
        };
        this.reduceActions[11] = function (rhs) {
            return new GreaterThanOperation(rhs[0], rhs[2]);
        };
        this.reduceActions[12] = function (rhs) {
            return new LessThanOrEqualOperation(rhs[0], rhs[2]);
        };
        this.reduceActions[13] = function (rhs) {
            return new GreaterThanOrEqualOperation(rhs[0], rhs[2]);
        };
        this.reduceActions[15] = function (rhs) {
            return new PlusOperation(rhs[0], rhs[2]);
        };
        this.reduceActions[16] = function (rhs) {
            return new MinusOperation(rhs[0], rhs[2]);
        };
        this.reduceActions[18] = function (rhs) {
            return new MultiplyOperation(rhs[0], rhs[2]);
        };
        this.reduceActions[19] = function (rhs) {
            return new DivOperation(rhs[0], rhs[2]);
        };
        this.reduceActions[20] = function (rhs) {
            return new ModOperation(rhs[0], rhs[2]);
        };
        this.reduceActions[22] = function (rhs) {
            return new UnaryMinusOperation(rhs[1]);
        };
        this.reduceActions[24] = function (rhs) {
            return new BarOperation(rhs[0], rhs[2]);
        };
        this.reduceActions[25] = function (rhs) {
            return new PathExpr(undefined, undefined, rhs[0]);
        };
        this.reduceActions[27] = function (rhs) {
            rhs[0].locationPath = rhs[2];
            return rhs[0];
        };
        this.reduceActions[28] = function (rhs) {
            rhs[0].locationPath = rhs[2];
            rhs[0].locationPath.steps.unshift(new Step(Step.DESCENDANTORSELF, NodeTest.nodeTest, []));
            return rhs[0];
        };
        this.reduceActions[29] = function (rhs) {
            return new PathExpr(rhs[0], [], undefined);
        };
        this.reduceActions[30] = function (rhs) {
            if (Utilities.instance_of(rhs[0], PathExpr)) {
                if (rhs[0].filterPredicates == undefined) {
                    rhs[0].filterPredicates = [];
                }
                rhs[0].filterPredicates.push(rhs[1]);
                return rhs[0];
            } else {
                return new PathExpr(rhs[0], [rhs[1]], undefined);
            }
        };
        this.reduceActions[32] = function (rhs) {
            return rhs[1];
        };
        this.reduceActions[33] = function (rhs) {
            return new XString(rhs[0]);
        };
        this.reduceActions[34] = function (rhs) {
            return new XNumber(rhs[0]);
        };
        this.reduceActions[36] = function (rhs) {
            return new FunctionCall(rhs[0], []);
        };
        this.reduceActions[37] = function (rhs) {
            return new FunctionCall(rhs[0], rhs[2]);
        };
        this.reduceActions[38] = function (rhs) {
            return [rhs[0]];
        };
        this.reduceActions[39] = function (rhs) {
            rhs[2].unshift(rhs[0]);
            return rhs[2];
        };
        this.reduceActions[43] = function (rhs) {
            return new LocationPath(true, []);
        };
        this.reduceActions[44] = function (rhs) {
            rhs[1].absolute = true;
            return rhs[1];
        };
        this.reduceActions[46] = function (rhs) {
            return new LocationPath(false, [rhs[0]]);
        };
        this.reduceActions[47] = function (rhs) {
            rhs[0].steps.push(rhs[2]);
            return rhs[0];
        };
        this.reduceActions[49] = function (rhs) {
            return new Step(rhs[0], rhs[1], []);
        };
        this.reduceActions[50] = function (rhs) {
            return new Step(Step.CHILD, rhs[0], []);
        };
        this.reduceActions[51] = function (rhs) {
            return new Step(rhs[0], rhs[1], rhs[2]);
        };
        this.reduceActions[52] = function (rhs) {
            return new Step(Step.CHILD, rhs[0], rhs[1]);
        };
        this.reduceActions[54] = function (rhs) {
            return [rhs[0]];
        };
        this.reduceActions[55] = function (rhs) {
            rhs[1].unshift(rhs[0]);
            return rhs[1];
        };
        this.reduceActions[56] = function (rhs) {
            if (rhs[0] == "ancestor") {
                return Step.ANCESTOR;
            } else if (rhs[0] == "ancestor-or-self") {
                return Step.ANCESTORORSELF;
            } else if (rhs[0] == "attribute") {
                return Step.ATTRIBUTE;
            } else if (rhs[0] == "child") {
                return Step.CHILD;
            } else if (rhs[0] == "descendant") {
                return Step.DESCENDANT;
            } else if (rhs[0] == "descendant-or-self") {
                return Step.DESCENDANTORSELF;
            } else if (rhs[0] == "following") {
                return Step.FOLLOWING;
            } else if (rhs[0] == "following-sibling") {
                return Step.FOLLOWINGSIBLING;
            } else if (rhs[0] == "namespace") {
                return Step.NAMESPACE;
            } else if (rhs[0] == "parent") {
                return Step.PARENT;
            } else if (rhs[0] == "preceding") {
                return Step.PRECEDING;
            } else if (rhs[0] == "preceding-sibling") {
                return Step.PRECEDINGSIBLING;
            } else if (rhs[0] == "self") {
                return Step.SELF;
            }
            return -1;
        };
        this.reduceActions[57] = function (rhs) {
            return Step.ATTRIBUTE;
        };
        this.reduceActions[59] = function (rhs) {
            if (rhs[0] == "comment") {
                return NodeTest.commentTest;
            } else if (rhs[0] == "text") {
                return NodeTest.textTest;
            } else if (rhs[0] == "processing-instruction") {
                return NodeTest.anyPiTest;
            } else if (rhs[0] == "node") {
                return NodeTest.nodeTest;
            }
            return new NodeTest(-1, undefined);
        };
        this.reduceActions[60] = function (rhs) {
            return new NodeTest.PITest(rhs[2]);
        };
        this.reduceActions[61] = function (rhs) {
            return rhs[1];
        };
        this.reduceActions[63] = function (rhs) {
            rhs[1].absolute = true;
            rhs[1].steps.unshift(new Step(Step.DESCENDANTORSELF, NodeTest.nodeTest, []));
            return rhs[1];
        };
        this.reduceActions[64] = function (rhs) {
            rhs[0].steps.push(new Step(Step.DESCENDANTORSELF, NodeTest.nodeTest, []));
            rhs[0].steps.push(rhs[2]);
            return rhs[0];
        };
        this.reduceActions[65] = function (rhs) {
            return new Step(Step.SELF, NodeTest.nodeTest, []);
        };
        this.reduceActions[66] = function (rhs) {
            return new Step(Step.PARENT, NodeTest.nodeTest, []);
        };
        this.reduceActions[67] = function (rhs) {
            return new VariableReference(rhs[1]);
        };
        this.reduceActions[68] = function (rhs) {
            return NodeTest.nameTestAny;
        };
        this.reduceActions[69] = function (rhs) {
            return new NodeTest.NameTestPrefixAny(rhs[0].split(':')[0]);
        };
        this.reduceActions[70] = function (rhs) {
            return new NodeTest.NameTestQName(rhs[0]);
        };
    };

    XPathParser.actionTable = [
        " s s        sssssssss    s ss  s  ss",
        "                 s                  ",
        "r  rrrrrrrrr         rrrrrrr rr  r  ",
        "                rrrrr               ",
        " s s        sssssssss    s ss  s  ss",
        "rs  rrrrrrrr s  sssssrrrrrr  rrs rs ",
        " s s        sssssssss    s ss  s  ss",
        "                            s       ",
        "                            s       ",
        "r  rrrrrrrrr         rrrrrrr rr rr  ",
        "r  rrrrrrrrr         rrrrrrr rr rr  ",
        "r  rrrrrrrrr         rrrrrrr rr rr  ",
        "r  rrrrrrrrr         rrrrrrr rr rr  ",
        "r  rrrrrrrrr         rrrrrrr rr rr  ",
        "  s                                 ",
        "                            s       ",
        " s           s  sssss          s  s ",
        "r  rrrrrrrrr         rrrrrrr rr  r  ",
        "a                                   ",
        "r       s                    rr  r  ",
        "r      sr                    rr  r  ",
        "r   s  rr            s       rr  r  ",
        "r   rssrr            rss     rr  r  ",
        "r   rrrrr            rrrss   rr  r  ",
        "r   rrrrrsss         rrrrr   rr  r  ",
        "r   rrrrrrrr         rrrrr   rr  r  ",
        "r   rrrrrrrr         rrrrrs  rr  r  ",
        "r   rrrrrrrr         rrrrrr  rr  r  ",
        "r   rrrrrrrr         rrrrrr  rr  r  ",
        "r  srrrrrrrr         rrrrrrs rr sr  ",
        "r  srrrrrrrr         rrrrrrs rr  r  ",
        "r  rrrrrrrrr         rrrrrrr rr rr  ",
        "r  rrrrrrrrr         rrrrrrr rr rr  ",
        "r  rrrrrrrrr         rrrrrrr rr rr  ",
        "r   rrrrrrrr         rrrrrr  rr  r  ",
        "r   rrrrrrrr         rrrrrr  rr  r  ",
        "r  rrrrrrrrr         rrrrrrr rr  r  ",
        "r  rrrrrrrrr         rrrrrrr rr  r  ",
        "                sssss               ",
        "r  rrrrrrrrr         rrrrrrr rr sr  ",
        "r  rrrrrrrrr         rrrrrrr rr  r  ",
        "r  rrrrrrrrr         rrrrrrr rr rr  ",
        "r  rrrrrrrrr         rrrrrrr rr rr  ",
        "                             s      ",
        "r  srrrrrrrr         rrrrrrs rr  r  ",
        "r   rrrrrrrr         rrrrr   rr  r  ",
        "              s                     ",
        "                             s      ",
        "                rrrrr               ",
        " s s        sssssssss    s sss s  ss",
        "r  srrrrrrrr         rrrrrrs rr  r  ",
        " s s        sssssssss    s ss  s  ss",
        " s s        sssssssss    s ss  s  ss",
        " s s        sssssssss    s ss  s  ss",
        " s s        sssssssss    s ss  s  ss",
        " s s        sssssssss    s ss  s  ss",
        " s s        sssssssss    s ss  s  ss",
        " s s        sssssssss    s ss  s  ss",
        " s s        sssssssss    s ss  s  ss",
        " s s        sssssssss    s ss  s  ss",
        " s s        sssssssss    s ss  s  ss",
        " s s        sssssssss    s ss  s  ss",
        " s s        sssssssss    s ss  s  ss",
        " s s        sssssssss    s ss  s  ss",
        " s s        sssssssss      ss  s  ss",
        " s s        sssssssss    s ss  s  ss",
        " s           s  sssss          s  s ",
        " s           s  sssss          s  s ",
        "r  rrrrrrrrr         rrrrrrr rr rr  ",
        " s           s  sssss          s  s ",
        " s           s  sssss          s  s ",
        "r  rrrrrrrrr         rrrrrrr rr sr  ",
        "r  rrrrrrrrr         rrrrrrr rr sr  ",
        "r  rrrrrrrrr         rrrrrrr rr  r  ",
        "r  rrrrrrrrr         rrrrrrr rr rr  ",
        "                             s      ",
        "r  rrrrrrrrr         rrrrrrr rr rr  ",
        "r  rrrrrrrrr         rrrrrrr rr rr  ",
        "                             rr     ",
        "                             s      ",
        "                             rs     ",
        "r      sr                    rr  r  ",
        "r   s  rr            s       rr  r  ",
        "r   rssrr            rss     rr  r  ",
        "r   rssrr            rss     rr  r  ",
        "r   rrrrr            rrrss   rr  r  ",
        "r   rrrrr            rrrss   rr  r  ",
        "r   rrrrr            rrrss   rr  r  ",
        "r   rrrrr            rrrss   rr  r  ",
        "r   rrrrrsss         rrrrr   rr  r  ",
        "r   rrrrrsss         rrrrr   rr  r  ",
        "r   rrrrrrrr         rrrrr   rr  r  ",
        "r   rrrrrrrr         rrrrr   rr  r  ",
        "r   rrrrrrrr         rrrrr   rr  r  ",
        "r   rrrrrrrr         rrrrrr  rr  r  ",
        "                                 r  ",
        "                                 s  ",
        "r  srrrrrrrr         rrrrrrs rr  r  ",
        "r  srrrrrrrr         rrrrrrs rr  r  ",
        "r  rrrrrrrrr         rrrrrrr rr  r  ",
        "r  rrrrrrrrr         rrrrrrr rr  r  ",
        "r  rrrrrrrrr         rrrrrrr rr  r  ",
        "r  rrrrrrrrr         rrrrrrr rr  r  ",
        "r  rrrrrrrrr         rrrrrrr rr rr  ",
        "r  rrrrrrrrr         rrrrrrr rr rr  ",
        " s s        sssssssss    s ss  s  ss",
        "r  rrrrrrrrr         rrrrrrr rr rr  ",
        "                             r      "
    ];

    XPathParser.actionTableNumber = [
        " 1 0        /.-,+*)('    & %$  #  \"!",
        "                 J                  ",
        "a  aaaaaaaaa         aaaaaaa aa  a  ",
        "                YYYYY               ",
        " 1 0        /.-,+*)('    & %$  #  \"!",
        "K1  KKKKKKKK .  +*)('KKKKKK  KK# K\" ",
        " 1 0        /.-,+*)('    & %$  #  \"!",
        "                            N       ",
        "                            O       ",
        "e  eeeeeeeee         eeeeeee ee ee  ",
        "f  fffffffff         fffffff ff ff  ",
        "d  ddddddddd         ddddddd dd dd  ",
        "B  BBBBBBBBB         BBBBBBB BB BB  ",
        "A  AAAAAAAAA         AAAAAAA AA AA  ",
        "  P                                 ",
        "                            Q       ",
        " 1           .  +*)('          #  \" ",
        "b  bbbbbbbbb         bbbbbbb bb  b  ",
        "                                    ",
        "!       S                    !!  !  ",
        "\"      T\"                    \"\"  \"  ",
        "$   V  $$            U       $$  $  ",
        "&   &ZY&&            &XW     &&  &  ",
        ")   )))))            )))\\[   ))  )  ",
        ".   ....._^]         .....   ..  .  ",
        "1   11111111         11111   11  1  ",
        "5   55555555         55555`  55  5  ",
        "7   77777777         777777  77  7  ",
        "9   99999999         999999  99  9  ",
        ":  c::::::::         ::::::b :: a:  ",
        "I  fIIIIIIII         IIIIIIe II  I  ",
        "=  =========         ======= == ==  ",
        "?  ?????????         ??????? ?? ??  ",
        "C  CCCCCCCCC         CCCCCCC CC CC  ",
        "J   JJJJJJJJ         JJJJJJ  JJ  J  ",
        "M   MMMMMMMM         MMMMMM  MM  M  ",
        "N  NNNNNNNNN         NNNNNNN NN  N  ",
        "P  PPPPPPPPP         PPPPPPP PP  P  ",
        "                +*)('               ",
        "R  RRRRRRRRR         RRRRRRR RR aR  ",
        "U  UUUUUUUUU         UUUUUUU UU  U  ",
        "Z  ZZZZZZZZZ         ZZZZZZZ ZZ ZZ  ",
        "c  ccccccccc         ccccccc cc cc  ",
        "                             j      ",
        "L  fLLLLLLLL         LLLLLLe LL  L  ",
        "6   66666666         66666   66  6  ",
        "              k                     ",
        "                             l      ",
        "                XXXXX               ",
        " 1 0        /.-,+*)('    & %$m #  \"!",
        "_  f________         ______e __  _  ",
        " 1 0        /.-,+*)('    & %$  #  \"!",
        " 1 0        /.-,+*)('    & %$  #  \"!",
        " 1 0        /.-,+*)('    & %$  #  \"!",
        " 1 0        /.-,+*)('    & %$  #  \"!",
        " 1 0        /.-,+*)('    & %$  #  \"!",
        " 1 0        /.-,+*)('    & %$  #  \"!",
        " 1 0        /.-,+*)('    & %$  #  \"!",
        " 1 0        /.-,+*)('    & %$  #  \"!",
        " 1 0        /.-,+*)('    & %$  #  \"!",
        " 1 0        /.-,+*)('    & %$  #  \"!",
        " 1 0        /.-,+*)('    & %$  #  \"!",
        " 1 0        /.-,+*)('    & %$  #  \"!",
        " 1 0        /.-,+*)('    & %$  #  \"!",
        " 1 0        /.-,+*)('      %$  #  \"!",
        " 1 0        /.-,+*)('    & %$  #  \"!",
        " 1           .  +*)('          #  \" ",
        " 1           .  +*)('          #  \" ",
        ">  >>>>>>>>>         >>>>>>> >> >>  ",
        " 1           .  +*)('          #  \" ",
        " 1           .  +*)('          #  \" ",
        "Q  QQQQQQQQQ         QQQQQQQ QQ aQ  ",
        "V  VVVVVVVVV         VVVVVVV VV aV  ",
        "T  TTTTTTTTT         TTTTTTT TT  T  ",
        "@  @@@@@@@@@         @@@@@@@ @@ @@  ",
        "                             \x87      ",
        "[  [[[[[[[[[         [[[[[[[ [[ [[  ",
        "D  DDDDDDDDD         DDDDDDD DD DD  ",
        "                             HH     ",
        "                             \x88      ",
        "                             F\x89     ",
        "#      T#                    ##  #  ",
        "%   V  %%            U       %%  %  ",
        "'   'ZY''            'XW     ''  '  ",
        "(   (ZY((            (XW     ((  (  ",
        "+   +++++            +++\\[   ++  +  ",
        "*   *****            ***\\[   **  *  ",
        "-   -----            ---\\[   --  -  ",
        ",   ,,,,,            ,,,\\[   ,,  ,  ",
        "0   00000_^]         00000   00  0  ",
        "/   /////_^]         /////   //  /  ",
        "2   22222222         22222   22  2  ",
        "3   33333333         33333   33  3  ",
        "4   44444444         44444   44  4  ",
        "8   88888888         888888  88  8  ",
        "                                 ^  ",
        "                                 \x8a  ",
        ";  f;;;;;;;;         ;;;;;;e ;;  ;  ",
        "<  f<<<<<<<<         <<<<<<e <<  <  ",
        "O  OOOOOOOOO         OOOOOOO OO  O  ",
        "`  `````````         ``````` ``  `  ",
        "S  SSSSSSSSS         SSSSSSS SS  S  ",
        "W  WWWWWWWWW         WWWWWWW WW  W  ",
        "\\  \\\\\\\\\\\\\\\\\\         \\\\\\\\\\\\\\ \\\\ \\\\  ",
        "E  EEEEEEEEE         EEEEEEE EE EE  ",
        " 1 0        /.-,+*)('    & %$  #  \"!",
        "]  ]]]]]]]]]         ]]]]]]] ]] ]]  ",
        "                             G      "
    ];

    XPathParser.gotoTable = [
        "3456789:;<=>?@ AB  CDEFGH IJ ",
        "                             ",
        "                             ",
        "                             ",
        "L456789:;<=>?@ AB  CDEFGH IJ ",
        "            M        EFGH IJ ",
        "       N;<=>?@ AB  CDEFGH IJ ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "            S        EFGH IJ ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "              e              ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                        h  J ",
        "              i          j   ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "o456789:;<=>?@ ABpqCDEFGH IJ ",
        "                             ",
        "  r6789:;<=>?@ AB  CDEFGH IJ ",
        "   s789:;<=>?@ AB  CDEFGH IJ ",
        "    t89:;<=>?@ AB  CDEFGH IJ ",
        "    u89:;<=>?@ AB  CDEFGH IJ ",
        "     v9:;<=>?@ AB  CDEFGH IJ ",
        "     w9:;<=>?@ AB  CDEFGH IJ ",
        "     x9:;<=>?@ AB  CDEFGH IJ ",
        "     y9:;<=>?@ AB  CDEFGH IJ ",
        "      z:;<=>?@ AB  CDEFGH IJ ",
        "      {:;<=>?@ AB  CDEFGH IJ ",
        "       |;<=>?@ AB  CDEFGH IJ ",
        "       };<=>?@ AB  CDEFGH IJ ",
        "       ~;<=>?@ AB  CDEFGH IJ ",
        "         \x7f=>?@ AB  CDEFGH IJ ",
        "\x80456789:;<=>?@ AB  CDEFGH IJ\x81",
        "            \x82        EFGH IJ ",
        "            \x83        EFGH IJ ",
        "                             ",
        "                     \x84 GH IJ ",
        "                     \x85 GH IJ ",
        "              i          \x86   ",
        "              i          \x87   ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "                             ",
        "o456789:;<=>?@ AB\x8cqCDEFGH IJ ",
        "                             ",
        "                             "
    ];

    XPathParser.productions = [
        [1, 1, 2],
        [2, 1, 3],
        [3, 1, 4],
        [3, 3, 3, -9, 4],
        [4, 1, 5],
        [4, 3, 4, -8, 5],
        [5, 1, 6],
        [5, 3, 5, -22, 6],
        [5, 3, 5, -5, 6],
        [6, 1, 7],
        [6, 3, 6, -23, 7],
        [6, 3, 6, -24, 7],
        [6, 3, 6, -6, 7],
        [6, 3, 6, -7, 7],
        [7, 1, 8],
        [7, 3, 7, -25, 8],
        [7, 3, 7, -26, 8],
        [8, 1, 9],
        [8, 3, 8, -12, 9],
        [8, 3, 8, -11, 9],
        [8, 3, 8, -10, 9],
        [9, 1, 10],
        [9, 2, -26, 9],
        [10, 1, 11],
        [10, 3, 10, -27, 11],
        [11, 1, 12],
        [11, 1, 13],
        [11, 3, 13, -28, 14],
        [11, 3, 13, -4, 14],
        [13, 1, 15],
        [13, 2, 13, 16],
        [15, 1, 17],
        [15, 3, -29, 2, -30],
        [15, 1, -15],
        [15, 1, -16],
        [15, 1, 18],
        [18, 3, -13, -29, -30],
        [18, 4, -13, -29, 19, -30],
        [19, 1, 20],
        [19, 3, 20, -31, 19],
        [20, 1, 2],
        [12, 1, 14],
        [12, 1, 21],
        [21, 1, -28],
        [21, 2, -28, 14],
        [21, 1, 22],
        [14, 1, 23],
        [14, 3, 14, -28, 23],
        [14, 1, 24],
        [23, 2, 25, 26],
        [23, 1, 26],
        [23, 3, 25, 26, 27],
        [23, 2, 26, 27],
        [23, 1, 28],
        [27, 1, 16],
        [27, 2, 16, 27],
        [25, 2, -14, -3],
        [25, 1, -32],
        [26, 1, 29],
        [26, 3, -20, -29, -30],
        [26, 4, -21, -29, -15, -30],
        [16, 3, -33, 30, -34],
        [30, 1, 2],
        [22, 2, -4, 14],
        [24, 3, 14, -4, 23],
        [28, 1, -35],
        [28, 1, -2],
        [17, 2, -36, -18],
        [29, 1, -17],
        [29, 1, -19],
        [29, 1, -18]
    ];

    XPathParser.DOUBLEDOT = 2;
    XPathParser.DOUBLECOLON = 3;
    XPathParser.DOUBLESLASH = 4;
    XPathParser.NOTEQUAL = 5;
    XPathParser.LESSTHANOREQUAL = 6;
    XPathParser.GREATERTHANOREQUAL = 7;
    XPathParser.AND = 8;
    XPathParser.OR = 9;
    XPathParser.MOD = 10;
    XPathParser.DIV = 11;
    XPathParser.MULTIPLYOPERATOR = 12;
    XPathParser.FUNCTIONNAME = 13;
    XPathParser.AXISNAME = 14;
    XPathParser.LITERAL = 15;
    XPathParser.NUMBER = 16;
    XPathParser.ASTERISKNAMETEST = 17;
    XPathParser.QNAME = 18;
    XPathParser.NCNAMECOLONASTERISK = 19;
    XPathParser.NODETYPE = 20;
    XPathParser.PROCESSINGINSTRUCTIONWITHLITERAL = 21;
    XPathParser.EQUALS = 22;
    XPathParser.LESSTHAN = 23;
    XPathParser.GREATERTHAN = 24;
    XPathParser.PLUS = 25;
    XPathParser.MINUS = 26;
    XPathParser.BAR = 27;
    XPathParser.SLASH = 28;
    XPathParser.LEFTPARENTHESIS = 29;
    XPathParser.RIGHTPARENTHESIS = 30;
    XPathParser.COMMA = 31;
    XPathParser.AT = 32;
    XPathParser.LEFTBRACKET = 33;
    XPathParser.RIGHTBRACKET = 34;
    XPathParser.DOT = 35;
    XPathParser.DOLLAR = 36;

    XPathParser.prototype.tokenize = function (s1) {
        var types = [];
        var values = [];
        var s = s1 + '\0';

        var pos = 0;
        var c = s.charAt(pos++);
        while (1) {
            while (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                c = s.charAt(pos++);
            }
            if (c == '\0' || pos >= s.length) {
                break;
            }

            if (c == '(') {
                types.push(XPathParser.LEFTPARENTHESIS);
                values.push(c);
                c = s.charAt(pos++);
                continue;
            }
            if (c == ')') {
                types.push(XPathParser.RIGHTPARENTHESIS);
                values.push(c);
                c = s.charAt(pos++);
                continue;
            }
            if (c == '[') {
                types.push(XPathParser.LEFTBRACKET);
                values.push(c);
                c = s.charAt(pos++);
                continue;
            }
            if (c == ']') {
                types.push(XPathParser.RIGHTBRACKET);
                values.push(c);
                c = s.charAt(pos++);
                continue;
            }
            if (c == '@') {
                types.push(XPathParser.AT);
                values.push(c);
                c = s.charAt(pos++);
                continue;
            }
            if (c == ',') {
                types.push(XPathParser.COMMA);
                values.push(c);
                c = s.charAt(pos++);
                continue;
            }
            if (c == '|') {
                types.push(XPathParser.BAR);
                values.push(c);
                c = s.charAt(pos++);
                continue;
            }
            if (c == '+') {
                types.push(XPathParser.PLUS);
                values.push(c);
                c = s.charAt(pos++);
                continue;
            }
            if (c == '-') {
                types.push(XPathParser.MINUS);
                values.push(c);
                c = s.charAt(pos++);
                continue;
            }
            if (c == '=') {
                types.push(XPathParser.EQUALS);
                values.push(c);
                c = s.charAt(pos++);
                continue;
            }
            if (c == '$') {
                types.push(XPathParser.DOLLAR);
                values.push(c);
                c = s.charAt(pos++);
                continue;
            }

            if (c == '.') {
                c = s.charAt(pos++);
                if (c == '.') {
                    types.push(XPathParser.DOUBLEDOT);
                    values.push("..");
                    c = s.charAt(pos++);
                    continue;
                }
                if (c >= '0' && c <= '9') {
                    var number = "." + c;
                    c = s.charAt(pos++);
                    while (c >= '0' && c <= '9') {
                        number += c;
                        c = s.charAt(pos++);
                    }
                    types.push(XPathParser.NUMBER);
                    values.push(number);
                    continue;
                }
                types.push(XPathParser.DOT);
                values.push('.');
                continue;
            }

            if (c == '\'' || c == '"') {
                var delimiter = c;
                var literal = "";
                while (pos < s.length && (c = s.charAt(pos)) !== delimiter) {
                    literal += c;
                    pos += 1;
                }
                if (c !== delimiter) {
                    throw XPathException.fromMessage("Unterminated string literal: " + delimiter + literal);
                }
                pos += 1;
                types.push(XPathParser.LITERAL);
                values.push(literal);
                c = s.charAt(pos++);
                continue;
            }

            if (c >= '0' && c <= '9') {
                var number = c;
                c = s.charAt(pos++);
                while (c >= '0' && c <= '9') {
                    number += c;
                    c = s.charAt(pos++);
                }
                if (c == '.') {
                    if (s.charAt(pos) >= '0' && s.charAt(pos) <= '9') {
                        number += c;
                        number += s.charAt(pos++);
                        c = s.charAt(pos++);
                        while (c >= '0' && c <= '9') {
                            number += c;
                            c = s.charAt(pos++);
                        }
                    }
                }
                types.push(XPathParser.NUMBER);
                values.push(number);
                continue;
            }

            if (c == '*') {
                if (types.length > 0) {
                    var last = types[types.length - 1];
                    if (last != XPathParser.AT
                        && last != XPathParser.DOUBLECOLON
                        && last != XPathParser.LEFTPARENTHESIS
                        && last != XPathParser.LEFTBRACKET
                        && last != XPathParser.AND
                        && last != XPathParser.OR
                        && last != XPathParser.MOD
                        && last != XPathParser.DIV
                        && last != XPathParser.MULTIPLYOPERATOR
                        && last != XPathParser.SLASH
                        && last != XPathParser.DOUBLESLASH
                        && last != XPathParser.BAR
                        && last != XPathParser.PLUS
                        && last != XPathParser.MINUS
                        && last != XPathParser.EQUALS
                        && last != XPathParser.NOTEQUAL
                        && last != XPathParser.LESSTHAN
                        && last != XPathParser.LESSTHANOREQUAL
                        && last != XPathParser.GREATERTHAN
                        && last != XPathParser.GREATERTHANOREQUAL) {
                        types.push(XPathParser.MULTIPLYOPERATOR);
                        values.push(c);
                        c = s.charAt(pos++);
                        continue;
                    }
                }
                types.push(XPathParser.ASTERISKNAMETEST);
                values.push(c);
                c = s.charAt(pos++);
                continue;
            }

            if (c == ':') {
                if (s.charAt(pos) == ':') {
                    types.push(XPathParser.DOUBLECOLON);
                    values.push("::");
                    pos++;
                    c = s.charAt(pos++);
                    continue;
                }
            }

            if (c == '/') {
                c = s.charAt(pos++);
                if (c == '/') {
                    types.push(XPathParser.DOUBLESLASH);
                    values.push("//");
                    c = s.charAt(pos++);
                    continue;
                }
                types.push(XPathParser.SLASH);
                values.push('/');
                continue;
            }

            if (c == '!') {
                if (s.charAt(pos) == '=') {
                    types.push(XPathParser.NOTEQUAL);
                    values.push("!=");
                    pos++;
                    c = s.charAt(pos++);
                    continue;
                }
            }

            if (c == '<') {
                if (s.charAt(pos) == '=') {
                    types.push(XPathParser.LESSTHANOREQUAL);
                    values.push("<=");
                    pos++;
                    c = s.charAt(pos++);
                    continue;
                }
                types.push(XPathParser.LESSTHAN);
                values.push('<');
                c = s.charAt(pos++);
                continue;
            }

            if (c == '>') {
                if (s.charAt(pos) == '=') {
                    types.push(XPathParser.GREATERTHANOREQUAL);
                    values.push(">=");
                    pos++;
                    c = s.charAt(pos++);
                    continue;
                }
                types.push(XPathParser.GREATERTHAN);
                values.push('>');
                c = s.charAt(pos++);
                continue;
            }

            if (c == '_' || Utilities.isLetter(c.charCodeAt(0))) {
                var name = c;
                c = s.charAt(pos++);
                while (Utilities.isNCNameChar(c.charCodeAt(0))) {
                    name += c;
                    c = s.charAt(pos++);
                }
                if (types.length > 0) {
                    var last = types[types.length - 1];
                    if (last != XPathParser.AT
                        && last != XPathParser.DOUBLECOLON
                        && last != XPathParser.LEFTPARENTHESIS
                        && last != XPathParser.LEFTBRACKET
                        && last != XPathParser.AND
                        && last != XPathParser.OR
                        && last != XPathParser.MOD
                        && last != XPathParser.DIV
                        && last != XPathParser.MULTIPLYOPERATOR
                        && last != XPathParser.SLASH
                        && last != XPathParser.DOUBLESLASH
                        && last != XPathParser.BAR
                        && last != XPathParser.PLUS
                        && last != XPathParser.MINUS
                        && last != XPathParser.EQUALS
                        && last != XPathParser.NOTEQUAL
                        && last != XPathParser.LESSTHAN
                        && last != XPathParser.LESSTHANOREQUAL
                        && last != XPathParser.GREATERTHAN
                        && last != XPathParser.GREATERTHANOREQUAL) {
                        if (name == "and") {
                            types.push(XPathParser.AND);
                            values.push(name);
                            continue;
                        }
                        if (name == "or") {
                            types.push(XPathParser.OR);
                            values.push(name);
                            continue;
                        }
                        if (name == "mod") {
                            types.push(XPathParser.MOD);
                            values.push(name);
                            continue;
                        }
                        if (name == "div") {
                            types.push(XPathParser.DIV);
                            values.push(name);
                            continue;
                        }
                    }
                }
                if (c == ':') {
                    if (s.charAt(pos) == '*') {
                        types.push(XPathParser.NCNAMECOLONASTERISK);
                        values.push(name + ":*");
                        pos++;
                        c = s.charAt(pos++);
                        continue;
                    }
                    if (s.charAt(pos) == '_' || Utilities.isLetter(s.charCodeAt(pos))) {
                        name += ':';
                        c = s.charAt(pos++);
                        while (Utilities.isNCNameChar(c.charCodeAt(0))) {
                            name += c;
                            c = s.charAt(pos++);
                        }
                        if (c == '(') {
                            types.push(XPathParser.FUNCTIONNAME);
                            values.push(name);
                            continue;
                        }
                        types.push(XPathParser.QNAME);
                        values.push(name);
                        continue;
                    }
                    if (s.charAt(pos) == ':') {
                        types.push(XPathParser.AXISNAME);
                        values.push(name);
                        continue;
                    }
                }
                if (c == '(') {
                    if (name == "comment" || name == "text" || name == "node") {
                        types.push(XPathParser.NODETYPE);
                        values.push(name);
                        continue;
                    }
                    if (name == "processing-instruction") {
                        if (s.charAt(pos) == ')') {
                            types.push(XPathParser.NODETYPE);
                        } else {
                            types.push(XPathParser.PROCESSINGINSTRUCTIONWITHLITERAL);
                        }
                        values.push(name);
                        continue;
                    }
                    types.push(XPathParser.FUNCTIONNAME);
                    values.push(name);
                    continue;
                }
                types.push(XPathParser.QNAME);
                values.push(name);
                continue;
            }

            throw new Error("Unexpected character " + c);
        }
        types.push(1);
        values.push("[EOF]");
        return [types, values];
    };

    XPathParser.SHIFT = 's';
    XPathParser.REDUCE = 'r';
    XPathParser.ACCEPT = 'a';

    XPathParser.prototype.parse = function (s) {
        var types;
        var values;
        var res = this.tokenize(s);
        if (res == undefined) {
            return undefined;
        }
        types = res[0];
        values = res[1];
        var tokenPos = 0;
        var state = [];
        var tokenType = [];
        var tokenValue = [];
        var s;
        var a;
        var t;

        state.push(0);
        tokenType.push(1);
        tokenValue.push("_S");

        a = types[tokenPos];
        t = values[tokenPos++];
        while (1) {
            s = state[state.length - 1];
            switch (XPathParser.actionTable[s].charAt(a - 1)) {
                case XPathParser.SHIFT:
                    tokenType.push(-a);
                    tokenValue.push(t);
                    state.push(XPathParser.actionTableNumber[s].charCodeAt(a - 1) - 32);
                    a = types[tokenPos];
                    t = values[tokenPos++];
                    break;
                case XPathParser.REDUCE:
                    var num = XPathParser.productions[XPathParser.actionTableNumber[s].charCodeAt(a - 1) - 32][1];
                    var rhs = [];
                    for (var i = 0; i < num; i++) {
                        tokenType.pop();
                        rhs.unshift(tokenValue.pop());
                        state.pop();
                    }
                    var s_ = state[state.length - 1];
                    tokenType.push(XPathParser.productions[XPathParser.actionTableNumber[s].charCodeAt(a - 1) - 32][0]);
                    if (this.reduceActions[XPathParser.actionTableNumber[s].charCodeAt(a - 1) - 32] == undefined) {
                        tokenValue.push(rhs[0]);
                    } else {
                        tokenValue.push(this.reduceActions[XPathParser.actionTableNumber[s].charCodeAt(a - 1) - 32](rhs));
                    }
                    state.push(XPathParser.gotoTable[s_].charCodeAt(XPathParser.productions[XPathParser.actionTableNumber[s].charCodeAt(a - 1) - 32][0] - 2) - 33);
                    break;
                case XPathParser.ACCEPT:
                    return new XPath(tokenValue.pop());
                default:
                    throw new Error("XPath parse error");
            }
        }
    };

    // XPath /////////////////////////////////////////////////////////////////////

    XPath.prototype = new Object();
    XPath.prototype.constructor = XPath;
    XPath.superclass = Object.prototype;

    function XPath(e) {
        this.expression = e;
    }

    XPath.prototype.toString = function () {
        return this.expression.toString();
    };

    function setIfUnset(obj, prop, value) {
        if (!(prop in obj)) {
            obj[prop] = value;
        }
    }

    XPath.prototype.evaluate = function (c) {
        c.contextNode = c.expressionContextNode;
        c.contextSize = 1;
        c.contextPosition = 1;

        // [2017-11-25] Removed usage of .implementation.hasFeature() since it does
        //              not reliably detect HTML DOMs (always returns false in xmldom and true in browsers)
        if (c.isHtml) {
            setIfUnset(c, 'caseInsensitive', true);
            setIfUnset(c, 'allowAnyNamespaceForNoPrefix', true);
        }

        setIfUnset(c, 'caseInsensitive', false);

        return this.expression.evaluate(c);
    };

    XPath.XML_NAMESPACE_URI = "http://www.w3.org/XML/1998/namespace";
    XPath.XMLNS_NAMESPACE_URI = "http://www.w3.org/2000/xmlns/";

    // Expression ////////////////////////////////////////////////////////////////

    Expression.prototype = new Object();
    Expression.prototype.constructor = Expression;
    Expression.superclass = Object.prototype;

    function Expression() {
    }

    Expression.prototype.init = function () {
    };

    Expression.prototype.toString = function () {
        return "<Expression>";
    };

    Expression.prototype.evaluate = function (c) {
        throw new Error("Could not evaluate expression.");
    };

    // UnaryOperation ////////////////////////////////////////////////////////////

    UnaryOperation.prototype = new Expression();
    UnaryOperation.prototype.constructor = UnaryOperation;
    UnaryOperation.superclass = Expression.prototype;

    function UnaryOperation(rhs) {
        if (arguments.length > 0) {
            this.init(rhs);
        }
    }

    UnaryOperation.prototype.init = function (rhs) {
        this.rhs = rhs;
    };

    // UnaryMinusOperation ///////////////////////////////////////////////////////

    UnaryMinusOperation.prototype = new UnaryOperation();
    UnaryMinusOperation.prototype.constructor = UnaryMinusOperation;
    UnaryMinusOperation.superclass = UnaryOperation.prototype;

    function UnaryMinusOperation(rhs) {
        if (arguments.length > 0) {
            this.init(rhs);
        }
    }

    UnaryMinusOperation.prototype.init = function (rhs) {
        UnaryMinusOperation.superclass.init.call(this, rhs);
    };

    UnaryMinusOperation.prototype.evaluate = function (c) {
        return this.rhs.evaluate(c).number().negate();
    };

    UnaryMinusOperation.prototype.toString = function () {
        return "-" + this.rhs.toString();
    };

    // BinaryOperation ///////////////////////////////////////////////////////////

    BinaryOperation.prototype = new Expression();
    BinaryOperation.prototype.constructor = BinaryOperation;
    BinaryOperation.superclass = Expression.prototype;

    function BinaryOperation(lhs, rhs) {
        if (arguments.length > 0) {
            this.init(lhs, rhs);
        }
    }

    BinaryOperation.prototype.init = function (lhs, rhs) {
        this.lhs = lhs;
        this.rhs = rhs;
    };

    // OrOperation ///////////////////////////////////////////////////////////////

    OrOperation.prototype = new BinaryOperation();
    OrOperation.prototype.constructor = OrOperation;
    OrOperation.superclass = BinaryOperation.prototype;

    function OrOperation(lhs, rhs) {
        if (arguments.length > 0) {
            this.init(lhs, rhs);
        }
    }

    OrOperation.prototype.init = function (lhs, rhs) {
        OrOperation.superclass.init.call(this, lhs, rhs);
    };

    OrOperation.prototype.toString = function () {
        return "(" + this.lhs.toString() + " or " + this.rhs.toString() + ")";
    };

    OrOperation.prototype.evaluate = function (c) {
        var b = this.lhs.evaluate(c).bool();
        if (b.booleanValue()) {
            return b;
        }
        return this.rhs.evaluate(c).bool();
    };

    // AndOperation //////////////////////////////////////////////////////////////

    AndOperation.prototype = new BinaryOperation();
    AndOperation.prototype.constructor = AndOperation;
    AndOperation.superclass = BinaryOperation.prototype;

    function AndOperation(lhs, rhs) {
        if (arguments.length > 0) {
            this.init(lhs, rhs);
        }
    }

    AndOperation.prototype.init = function (lhs, rhs) {
        AndOperation.superclass.init.call(this, lhs, rhs);
    };

    AndOperation.prototype.toString = function () {
        return "(" + this.lhs.toString() + " and " + this.rhs.toString() + ")";
    };

    AndOperation.prototype.evaluate = function (c) {
        var b = this.lhs.evaluate(c).bool();
        if (!b.booleanValue()) {
            return b;
        }
        return this.rhs.evaluate(c).bool();
    };

    // EqualsOperation ///////////////////////////////////////////////////////////

    EqualsOperation.prototype = new BinaryOperation();
    EqualsOperation.prototype.constructor = EqualsOperation;
    EqualsOperation.superclass = BinaryOperation.prototype;

    function EqualsOperation(lhs, rhs) {
        if (arguments.length > 0) {
            this.init(lhs, rhs);
        }
    }

    EqualsOperation.prototype.init = function (lhs, rhs) {
        EqualsOperation.superclass.init.call(this, lhs, rhs);
    };

    EqualsOperation.prototype.toString = function () {
        return "(" + this.lhs.toString() + " = " + this.rhs.toString() + ")";
    };

    EqualsOperation.prototype.evaluate = function (c) {
        return this.lhs.evaluate(c).equals(this.rhs.evaluate(c));
    };

    // NotEqualOperation /////////////////////////////////////////////////////////

    NotEqualOperation.prototype = new BinaryOperation();
    NotEqualOperation.prototype.constructor = NotEqualOperation;
    NotEqualOperation.superclass = BinaryOperation.prototype;

    function NotEqualOperation(lhs, rhs) {
        if (arguments.length > 0) {
            this.init(lhs, rhs);
        }
    }

    NotEqualOperation.prototype.init = function (lhs, rhs) {
        NotEqualOperation.superclass.init.call(this, lhs, rhs);
    };

    NotEqualOperation.prototype.toString = function () {
        return "(" + this.lhs.toString() + " != " + this.rhs.toString() + ")";
    };

    NotEqualOperation.prototype.evaluate = function (c) {
        return this.lhs.evaluate(c).notequal(this.rhs.evaluate(c));
    };

    // LessThanOperation /////////////////////////////////////////////////////////

    LessThanOperation.prototype = new BinaryOperation();
    LessThanOperation.prototype.constructor = LessThanOperation;
    LessThanOperation.superclass = BinaryOperation.prototype;

    function LessThanOperation(lhs, rhs) {
        if (arguments.length > 0) {
            this.init(lhs, rhs);
        }
    }

    LessThanOperation.prototype.init = function (lhs, rhs) {
        LessThanOperation.superclass.init.call(this, lhs, rhs);
    };

    LessThanOperation.prototype.evaluate = function (c) {
        return this.lhs.evaluate(c).lessthan(this.rhs.evaluate(c));
    };

    LessThanOperation.prototype.toString = function () {
        return "(" + this.lhs.toString() + " < " + this.rhs.toString() + ")";
    };

    // GreaterThanOperation //////////////////////////////////////////////////////

    GreaterThanOperation.prototype = new BinaryOperation();
    GreaterThanOperation.prototype.constructor = GreaterThanOperation;
    GreaterThanOperation.superclass = BinaryOperation.prototype;

    function GreaterThanOperation(lhs, rhs) {
        if (arguments.length > 0) {
            this.init(lhs, rhs);
        }
    }

    GreaterThanOperation.prototype.init = function (lhs, rhs) {
        GreaterThanOperation.superclass.init.call(this, lhs, rhs);
    };

    GreaterThanOperation.prototype.evaluate = function (c) {
        return this.lhs.evaluate(c).greaterthan(this.rhs.evaluate(c));
    };

    GreaterThanOperation.prototype.toString = function () {
        return "(" + this.lhs.toString() + " > " + this.rhs.toString() + ")";
    };

    // LessThanOrEqualOperation //////////////////////////////////////////////////

    LessThanOrEqualOperation.prototype = new BinaryOperation();
    LessThanOrEqualOperation.prototype.constructor = LessThanOrEqualOperation;
    LessThanOrEqualOperation.superclass = BinaryOperation.prototype;

    function LessThanOrEqualOperation(lhs, rhs) {
        if (arguments.length > 0) {
            this.init(lhs, rhs);
        }
    }

    LessThanOrEqualOperation.prototype.init = function (lhs, rhs) {
        LessThanOrEqualOperation.superclass.init.call(this, lhs, rhs);
    };

    LessThanOrEqualOperation.prototype.evaluate = function (c) {
        return this.lhs.evaluate(c).lessthanorequal(this.rhs.evaluate(c));
    };

    LessThanOrEqualOperation.prototype.toString = function () {
        return "(" + this.lhs.toString() + " <= " + this.rhs.toString() + ")";
    };

    // GreaterThanOrEqualOperation ///////////////////////////////////////////////

    GreaterThanOrEqualOperation.prototype = new BinaryOperation();
    GreaterThanOrEqualOperation.prototype.constructor = GreaterThanOrEqualOperation;
    GreaterThanOrEqualOperation.superclass = BinaryOperation.prototype;

    function GreaterThanOrEqualOperation(lhs, rhs) {
        if (arguments.length > 0) {
            this.init(lhs, rhs);
        }
    }

    GreaterThanOrEqualOperation.prototype.init = function (lhs, rhs) {
        GreaterThanOrEqualOperation.superclass.init.call(this, lhs, rhs);
    };

    GreaterThanOrEqualOperation.prototype.evaluate = function (c) {
        return this.lhs.evaluate(c).greaterthanorequal(this.rhs.evaluate(c));
    };

    GreaterThanOrEqualOperation.prototype.toString = function () {
        return "(" + this.lhs.toString() + " >= " + this.rhs.toString() + ")";
    };

    // PlusOperation /////////////////////////////////////////////////////////////

    PlusOperation.prototype = new BinaryOperation();
    PlusOperation.prototype.constructor = PlusOperation;
    PlusOperation.superclass = BinaryOperation.prototype;

    function PlusOperation(lhs, rhs) {
        if (arguments.length > 0) {
            this.init(lhs, rhs);
        }
    }

    PlusOperation.prototype.init = function (lhs, rhs) {
        PlusOperation.superclass.init.call(this, lhs, rhs);
    };

    PlusOperation.prototype.evaluate = function (c) {
        return this.lhs.evaluate(c).number().plus(this.rhs.evaluate(c).number());
    };

    PlusOperation.prototype.toString = function () {
        return "(" + this.lhs.toString() + " + " + this.rhs.toString() + ")";
    };

    // MinusOperation ////////////////////////////////////////////////////////////

    MinusOperation.prototype = new BinaryOperation();
    MinusOperation.prototype.constructor = MinusOperation;
    MinusOperation.superclass = BinaryOperation.prototype;

    function MinusOperation(lhs, rhs) {
        if (arguments.length > 0) {
            this.init(lhs, rhs);
        }
    }

    MinusOperation.prototype.init = function (lhs, rhs) {
        MinusOperation.superclass.init.call(this, lhs, rhs);
    };

    MinusOperation.prototype.evaluate = function (c) {
        return this.lhs.evaluate(c).number().minus(this.rhs.evaluate(c).number());
    };

    MinusOperation.prototype.toString = function () {
        return "(" + this.lhs.toString() + " - " + this.rhs.toString() + ")";
    };

    // MultiplyOperation /////////////////////////////////////////////////////////

    MultiplyOperation.prototype = new BinaryOperation();
    MultiplyOperation.prototype.constructor = MultiplyOperation;
    MultiplyOperation.superclass = BinaryOperation.prototype;

    function MultiplyOperation(lhs, rhs) {
        if (arguments.length > 0) {
            this.init(lhs, rhs);
        }
    }

    MultiplyOperation.prototype.init = function (lhs, rhs) {
        MultiplyOperation.superclass.init.call(this, lhs, rhs);
    };

    MultiplyOperation.prototype.evaluate = function (c) {
        return this.lhs.evaluate(c).number().multiply(this.rhs.evaluate(c).number());
    };

    MultiplyOperation.prototype.toString = function () {
        return "(" + this.lhs.toString() + " * " + this.rhs.toString() + ")";
    };

    // DivOperation //////////////////////////////////////////////////////////////

    DivOperation.prototype = new BinaryOperation();
    DivOperation.prototype.constructor = DivOperation;
    DivOperation.superclass = BinaryOperation.prototype;

    function DivOperation(lhs, rhs) {
        if (arguments.length > 0) {
            this.init(lhs, rhs);
        }
    }

    DivOperation.prototype.init = function (lhs, rhs) {
        DivOperation.superclass.init.call(this, lhs, rhs);
    };

    DivOperation.prototype.evaluate = function (c) {
        return this.lhs.evaluate(c).number().div(this.rhs.evaluate(c).number());
    };

    DivOperation.prototype.toString = function () {
        return "(" + this.lhs.toString() + " div " + this.rhs.toString() + ")";
    };

    // ModOperation //////////////////////////////////////////////////////////////

    ModOperation.prototype = new BinaryOperation();
    ModOperation.prototype.constructor = ModOperation;
    ModOperation.superclass = BinaryOperation.prototype;

    function ModOperation(lhs, rhs) {
        if (arguments.length > 0) {
            this.init(lhs, rhs);
        }
    }

    ModOperation.prototype.init = function (lhs, rhs) {
        ModOperation.superclass.init.call(this, lhs, rhs);
    };

    ModOperation.prototype.evaluate = function (c) {
        return this.lhs.evaluate(c).number().mod(this.rhs.evaluate(c).number());
    };

    ModOperation.prototype.toString = function () {
        return "(" + this.lhs.toString() + " mod " + this.rhs.toString() + ")";
    };

    // BarOperation //////////////////////////////////////////////////////////////

    BarOperation.prototype = new BinaryOperation();
    BarOperation.prototype.constructor = BarOperation;
    BarOperation.superclass = BinaryOperation.prototype;

    function BarOperation(lhs, rhs) {
        if (arguments.length > 0) {
            this.init(lhs, rhs);
        }
    }

    BarOperation.prototype.init = function (lhs, rhs) {
        BarOperation.superclass.init.call(this, lhs, rhs);
    };

    BarOperation.prototype.evaluate = function (c) {
        return this.lhs.evaluate(c).nodeset().union(this.rhs.evaluate(c).nodeset());
    };

    BarOperation.prototype.toString = function () {
        return map(toString, [this.lhs, this.rhs]).join(' | ');
    };

    // PathExpr //////////////////////////////////////////////////////////////////

    PathExpr.prototype = new Expression();
    PathExpr.prototype.constructor = PathExpr;
    PathExpr.superclass = Expression.prototype;

    function PathExpr(filter, filterPreds, locpath) {
        if (arguments.length > 0) {
            this.init(filter, filterPreds, locpath);
        }
    }

    PathExpr.prototype.init = function (filter, filterPreds, locpath) {
        PathExpr.superclass.init.call(this);
        this.filter = filter;
        this.filterPredicates = filterPreds;
        this.locationPath = locpath;
    };

    /**
     * Returns the topmost node of the tree containing node
     */
    function findRoot(node) {
        while (node && node.parentNode) {
            node = node.parentNode;
        }

        return node;
    }

    PathExpr.applyPredicates = function (predicates, c, nodes) {
        if (predicates.length === 0) {
            return nodes;
        }

        var ctx = c.extend({});

        return reduce(
            function (inNodes, pred) {
                ctx.contextSize = inNodes.length;

                return filter(
                    function (node, i) {
                        ctx.contextNode = node;
                        ctx.contextPosition = i + 1;

                        return PathExpr.predicateMatches(pred, ctx);
                    },
                    inNodes
                );
            },
            nodes,
            predicates
        );
    };

    PathExpr.getRoot = function (xpc, nodes) {
        var firstNode = nodes[0];

        if (firstNode.nodeType === 9 /*Node.DOCUMENT_NODE*/) {
            return firstNode;
        }

        if (xpc.virtualRoot) {
            return xpc.virtualRoot;
        }

        var ownerDoc = firstNode.ownerDocument;

        if (ownerDoc) {
            return ownerDoc;
        }

        // IE 5.5 doesn't have ownerDocument?
        var n = firstNode;
        while (n.parentNode != null) {
            n = n.parentNode;
        }
        return n;
    }

    PathExpr.applyStep = function (step, xpc, node) {
        var self = this;
        var newNodes = [];
        xpc.contextNode = node;

        switch (step.axis) {
            case Step.ANCESTOR:
                // look at all the ancestor nodes
                if (xpc.contextNode === xpc.virtualRoot) {
                    break;
                }
                var m;
                if (xpc.contextNode.nodeType == 2 /*Node.ATTRIBUTE_NODE*/) {
                    m = PathExpr.getOwnerElement(xpc.contextNode);
                } else {
                    m = xpc.contextNode.parentNode;
                }
                while (m != null) {
                    if (step.nodeTest.matches(m, xpc)) {
                        newNodes.push(m);
                    }
                    if (m === xpc.virtualRoot) {
                        break;
                    }
                    m = m.parentNode;
                }
                break;

            case Step.ANCESTORORSELF:
                // look at all the ancestor nodes and the current node
                for (var m = xpc.contextNode; m != null; m = m.nodeType == 2 /*Node.ATTRIBUTE_NODE*/ ? PathExpr.getOwnerElement(m) : m.parentNode) {
                    if (step.nodeTest.matches(m, xpc)) {
                        newNodes.push(m);
                    }
                    if (m === xpc.virtualRoot) {
                        break;
                    }
                }
                break;

            case Step.ATTRIBUTE:
                // look at the attributes
                var nnm = xpc.contextNode.attributes;
                if (nnm != null) {
                    for (var k = 0; k < nnm.length; k++) {
                        var m = nnm.item(k);
                        if (step.nodeTest.matches(m, xpc)) {
                            newNodes.push(m);
                        }
                    }
                }
                break;

            case Step.CHILD:
                // look at all child elements
                for (var m = xpc.contextNode.firstChild; m != null; m = m.nextSibling) {
                    if (step.nodeTest.matches(m, xpc)) {
                        newNodes.push(m);
                    }
                }
                break;

            case Step.DESCENDANT:
                // look at all descendant nodes
                var st = [xpc.contextNode.firstChild];
                while (st.length > 0) {
                    for (var m = st.pop(); m != null;) {
                        if (step.nodeTest.matches(m, xpc)) {
                            newNodes.push(m);
                        }
                        if (m.firstChild != null) {
                            st.push(m.nextSibling);
                            m = m.firstChild;
                        } else {
                            m = m.nextSibling;
                        }
                    }
                }
                break;

            case Step.DESCENDANTORSELF:
                // look at self
                if (step.nodeTest.matches(xpc.contextNode, xpc)) {
                    newNodes.push(xpc.contextNode);
                }
                // look at all descendant nodes
                var st = [xpc.contextNode.firstChild];
                while (st.length > 0) {
                    for (var m = st.pop(); m != null;) {
                        if (step.nodeTest.matches(m, xpc)) {
                            newNodes.push(m);
                        }
                        if (m.firstChild != null) {
                            st.push(m.nextSibling);
                            m = m.firstChild;
                        } else {
                            m = m.nextSibling;
                        }
                    }
                }
                break;

            case Step.FOLLOWING:
                if (xpc.contextNode === xpc.virtualRoot) {
                    break;
                }
                var st = [];
                if (xpc.contextNode.firstChild != null) {
                    st.unshift(xpc.contextNode.firstChild);
                } else {
                    st.unshift(xpc.contextNode.nextSibling);
                }
                for (var m = xpc.contextNode.parentNode; m != null && m.nodeType != 9 /*Node.DOCUMENT_NODE*/ && m !== xpc.virtualRoot; m = m.parentNode) {
                    st.unshift(m.nextSibling);
                }
                do {
                    for (var m = st.pop(); m != null;) {
                        if (step.nodeTest.matches(m, xpc)) {
                            newNodes.push(m);
                        }
                        if (m.firstChild != null) {
                            st.push(m.nextSibling);
                            m = m.firstChild;
                        } else {
                            m = m.nextSibling;
                        }
                    }
                } while (st.length > 0);
                break;

            case Step.FOLLOWINGSIBLING:
                if (xpc.contextNode === xpc.virtualRoot) {
                    break;
                }
                for (var m = xpc.contextNode.nextSibling; m != null; m = m.nextSibling) {
                    if (step.nodeTest.matches(m, xpc)) {
                        newNodes.push(m);
                    }
                }
                break;

            case Step.NAMESPACE:
                var n = {};
                if (xpc.contextNode.nodeType == 1 /*Node.ELEMENT_NODE*/) {
                    n["xml"] = XPath.XML_NAMESPACE_URI;
                    n["xmlns"] = XPath.XMLNS_NAMESPACE_URI;
                    for (var m = xpc.contextNode; m != null && m.nodeType == 1 /*Node.ELEMENT_NODE*/; m = m.parentNode) {
                        for (var k = 0; k < m.attributes.length; k++) {
                            var attr = m.attributes.item(k);
                            var nm = String(attr.name);
                            if (nm == "xmlns") {
                                if (n[""] == undefined) {
                                    n[""] = attr.value;
                                }
                            } else if (nm.length > 6 && nm.substring(0, 6) == "xmlns:") {
                                var pre = nm.substring(6, nm.length);
                                if (n[pre] == undefined) {
                                    n[pre] = attr.value;
                                }
                            }
                        }
                    }
                    for (var pre in n) {
                        var nsn = new XPathNamespace(pre, n[pre], xpc.contextNode);
                        if (step.nodeTest.matches(nsn, xpc)) {
                            newNodes.push(nsn);
                        }
                    }
                }
                break;

            case Step.PARENT:
                m = null;
                if (xpc.contextNode !== xpc.virtualRoot) {
                    if (xpc.contextNode.nodeType == 2 /*Node.ATTRIBUTE_NODE*/) {
                        m = PathExpr.getOwnerElement(xpc.contextNode);
                    } else {
                        m = xpc.contextNode.parentNode;
                    }
                }
                if (m != null && step.nodeTest.matches(m, xpc)) {
                    newNodes.push(m);
                }
                break;

            case Step.PRECEDING:
                var st;
                if (xpc.virtualRoot != null) {
                    st = [xpc.virtualRoot];
                } else {
                    // cannot rely on .ownerDocument because the node may be in a document fragment
                    st = [findRoot(xpc.contextNode)];
                }
                outer: while (st.length > 0) {
                    for (var m = st.pop(); m != null;) {
                        if (m == xpc.contextNode) {
                            break outer;
                        }
                        if (step.nodeTest.matches(m, xpc)) {
                            newNodes.unshift(m);
                        }
                        if (m.firstChild != null) {
                            st.push(m.nextSibling);
                            m = m.firstChild;
                        } else {
                            m = m.nextSibling;
                        }
                    }
                }
                break;

            case Step.PRECEDINGSIBLING:
                if (xpc.contextNode === xpc.virtualRoot) {
                    break;
                }
                for (var m = xpc.contextNode.previousSibling; m != null; m = m.previousSibling) {
                    if (step.nodeTest.matches(m, xpc)) {
                        newNodes.push(m);
                    }
                }
                break;

            case Step.SELF:
                if (step.nodeTest.matches(xpc.contextNode, xpc)) {
                    newNodes.push(xpc.contextNode);
                }
                break;

            default:
        }

        return newNodes;
    };

    function applyStepWithPredicates(step, xpc, node) {
        return PathExpr.applyPredicates(
            step.predicates,
            xpc,
            PathExpr.applyStep(step, xpc, node)
        );
    }

    function applyStepToNodes(context, nodes, step) {
        return flatten(
            map(
                applyStepWithPredicates.bind(null, step, context),
                nodes
            )
        );
    }

    PathExpr.applySteps = function (steps, xpc, nodes) {
        return reduce(
            applyStepToNodes.bind(null, xpc),
            nodes,
            steps
        );
    }

    PathExpr.prototype.applyFilter = function (c, xpc) {
        if (!this.filter) {
            return { nodes: [c.contextNode] };
        }

        var ns = this.filter.evaluate(c);

        if (!Utilities.instance_of(ns, XNodeSet)) {
            if (this.filterPredicates != null && this.filterPredicates.length > 0 || this.locationPath != null) {
                throw new Error("Path expression filter must evaluate to a nodeset if predicates or location path are used");
            }

            return { nonNodes: ns };
        }

        return {
            nodes: PathExpr.applyPredicates(this.filterPredicates || [], xpc, ns.toUnsortedArray())
        };
    };

    PathExpr.applyLocationPath = function (locationPath, xpc, nodes) {
        if (!locationPath) {
            return nodes;
        }

        var startNodes = locationPath.absolute ? [PathExpr.getRoot(xpc, nodes)] : nodes;

        return PathExpr.applySteps(locationPath.steps, xpc, startNodes);
    };

    PathExpr.prototype.evaluate = function (c) {
        var xpc = assign(new XPathContext(), c);

        var filterResult = this.applyFilter(c, xpc);

        if ('nonNodes' in filterResult) {
            return filterResult.nonNodes;
        }

        var ns = new XNodeSet();
        ns.addArray(PathExpr.applyLocationPath(this.locationPath, xpc, filterResult.nodes));
        return ns;
    };

    PathExpr.predicateMatches = function (pred, c) {
        var res = pred.evaluate(c);

        return Utilities.instance_of(res, XNumber)
            ? c.contextPosition === res.numberValue()
            : res.booleanValue();
    };

    PathExpr.predicateString = function (predicate) {
        return wrap('[', ']', predicate.toString());
    }

    PathExpr.predicatesString = function (predicates) {
        return join(
            '',
            map(PathExpr.predicateString, predicates)
        );
    }

    PathExpr.prototype.toString = function () {
        if (this.filter != undefined) {
            var filterStr = toString(this.filter);

            if (Utilities.instance_of(this.filter, XString)) {
                return wrap("'", "'", filterStr);
            }
            if (this.filterPredicates != undefined && this.filterPredicates.length) {
                return wrap('(', ')', filterStr) +
                    PathExpr.predicatesString(this.filterPredicates);
            }
            if (this.locationPath != undefined) {
                return filterStr +
                    (this.locationPath.absolute ? '' : '/') +
                    toString(this.locationPath);
            }

            return filterStr;
        }

        return toString(this.locationPath);
    };

    PathExpr.getOwnerElement = function (n) {
        // DOM 2 has ownerElement
        if (n.ownerElement) {
            return n.ownerElement;
        }
        // DOM 1 Internet Explorer can use selectSingleNode (ironically)
        try {
            if (n.selectSingleNode) {
                return n.selectSingleNode("..");
            }
        } catch (e) {
        }
        // Other DOM 1 implementations must use this egregious search
        var doc = n.nodeType == 9 /*Node.DOCUMENT_NODE*/
            ? n
            : n.ownerDocument;
        var elts = doc.getElementsByTagName("*");
        for (var i = 0; i < elts.length; i++) {
            var elt = elts.item(i);
            var nnm = elt.attributes;
            for (var j = 0; j < nnm.length; j++) {
                var an = nnm.item(j);
                if (an === n) {
                    return elt;
                }
            }
        }
        return null;
    };

    // LocationPath //////////////////////////////////////////////////////////////

    LocationPath.prototype = new Object();
    LocationPath.prototype.constructor = LocationPath;
    LocationPath.superclass = Object.prototype;

    function LocationPath(abs, steps) {
        if (arguments.length > 0) {
            this.init(abs, steps);
        }
    }

    LocationPath.prototype.init = function (abs, steps) {
        this.absolute = abs;
        this.steps = steps;
    };

    LocationPath.prototype.toString = function () {
        return (
            (this.absolute ? '/' : '') +
            map(toString, this.steps).join('/')
        );
    };

    // Step //////////////////////////////////////////////////////////////////////

    Step.prototype = new Object();
    Step.prototype.constructor = Step;
    Step.superclass = Object.prototype;

    function Step(axis, nodetest, preds) {
        if (arguments.length > 0) {
            this.init(axis, nodetest, preds);
        }
    }

    Step.prototype.init = function (axis, nodetest, preds) {
        this.axis = axis;
        this.nodeTest = nodetest;
        this.predicates = preds;
    };

    Step.prototype.toString = function () {
        return Step.STEPNAMES[this.axis] +
            "::" +
            this.nodeTest.toString() +
            PathExpr.predicatesString(this.predicates);
    };


    Step.ANCESTOR = 0;
    Step.ANCESTORORSELF = 1;
    Step.ATTRIBUTE = 2;
    Step.CHILD = 3;
    Step.DESCENDANT = 4;
    Step.DESCENDANTORSELF = 5;
    Step.FOLLOWING = 6;
    Step.FOLLOWINGSIBLING = 7;
    Step.NAMESPACE = 8;
    Step.PARENT = 9;
    Step.PRECEDING = 10;
    Step.PRECEDINGSIBLING = 11;
    Step.SELF = 12;

    Step.STEPNAMES = reduce(function (acc, x) { return acc[x[0]] = x[1], acc; }, {}, [
        [Step.ANCESTOR, 'ancestor'],
        [Step.ANCESTORORSELF, 'ancestor-or-self'],
        [Step.ATTRIBUTE, 'attribute'],
        [Step.CHILD, 'child'],
        [Step.DESCENDANT, 'descendant'],
        [Step.DESCENDANTORSELF, 'descendant-or-self'],
        [Step.FOLLOWING, 'following'],
        [Step.FOLLOWINGSIBLING, 'following-sibling'],
        [Step.NAMESPACE, 'namespace'],
        [Step.PARENT, 'parent'],
        [Step.PRECEDING, 'preceding'],
        [Step.PRECEDINGSIBLING, 'preceding-sibling'],
        [Step.SELF, 'self']
    ]);

    // NodeTest //////////////////////////////////////////////////////////////////

    NodeTest.prototype = new Object();
    NodeTest.prototype.constructor = NodeTest;
    NodeTest.superclass = Object.prototype;

    function NodeTest(type, value) {
        if (arguments.length > 0) {
            this.init(type, value);
        }
    }

    NodeTest.prototype.init = function (type, value) {
        this.type = type;
        this.value = value;
    };

    NodeTest.prototype.toString = function () {
        return "<unknown nodetest type>";
    };

    NodeTest.prototype.matches = function (n, xpc) {
        console.warn('unknown node test type');
    };

    NodeTest.NAMETESTANY = 0;
    NodeTest.NAMETESTPREFIXANY = 1;
    NodeTest.NAMETESTQNAME = 2;
    NodeTest.COMMENT = 3;
    NodeTest.TEXT = 4;
    NodeTest.PI = 5;
    NodeTest.NODE = 6;

    NodeTest.isNodeType = function (types) {
        return function (node) {
            return includes(types, node.nodeType);
        };
    };

    NodeTest.makeNodeTestType = function (type, members, ctor) {
        var newType = ctor || function () { };

        newType.prototype = new NodeTest(type);
        newType.prototype.constructor = newType;

        assign(newType.prototype, members);

        return newType;
    };
    // create invariant node test for certain node types
    NodeTest.makeNodeTypeTest = function (type, nodeTypes, stringVal) {
        return new (NodeTest.makeNodeTestType(type, {
            matches: NodeTest.isNodeType(nodeTypes),
            toString: always(stringVal)
        }))();
    };

    NodeTest.hasPrefix = function (node) {
        return node.prefix || (node.nodeName || node.tagName).indexOf(':') !== -1;
    };

    NodeTest.isElementOrAttribute = NodeTest.isNodeType([1, 2]);
    NodeTest.nameSpaceMatches = function (prefix, xpc, n) {
        var nNamespace = (n.namespaceURI || '');

        if (!prefix) {
            return !nNamespace || (xpc.allowAnyNamespaceForNoPrefix && !NodeTest.hasPrefix(n));
        }

        var ns = xpc.namespaceResolver.getNamespace(prefix, xpc.expressionContextNode);

        if (ns == null) {
            throw new Error("Cannot resolve QName " + prefix);
        }

        return ns === nNamespace;
    };
    NodeTest.localNameMatches = function (localName, xpc, n) {
        var nLocalName = (n.localName || n.nodeName);

        return xpc.caseInsensitive
            ? localName.toLowerCase() === nLocalName.toLowerCase()
            : localName === nLocalName;
    };

    NodeTest.NameTestPrefixAny = NodeTest.makeNodeTestType(
        NodeTest.NAMETESTPREFIXANY,
        {
            matches: function (n, xpc) {
                return NodeTest.isElementOrAttribute(n) &&
                    NodeTest.nameSpaceMatches(this.prefix, xpc, n);
            },
            toString: function () {
                return this.prefix + ":*";
            }
        },
        function NameTestPrefixAny(prefix) { this.prefix = prefix; }
    );

    NodeTest.NameTestQName = NodeTest.makeNodeTestType(
        NodeTest.NAMETESTQNAME,
        {
            matches: function (n, xpc) {
                return NodeTest.isNodeType([1, 2, XPathNamespace.XPATH_NAMESPACE_NODE])(n) &&
                    NodeTest.nameSpaceMatches(this.prefix, xpc, n) &&
                    NodeTest.localNameMatches(this.localName, xpc, n);
            },
            toString: function () {
                return this.name;
            }
        },
        function NameTestQName(name) {
            var nameParts = name.split(':');

            this.name = name;
            this.prefix = nameParts.length > 1 ? nameParts[0] : null;
            this.localName = nameParts[nameParts.length > 1 ? 1 : 0];
        }
    );

    NodeTest.PITest = NodeTest.makeNodeTestType(NodeTest.PI, {
        matches: function (n, xpc) {
            return NodeTest.isNodeType([7])(n) && (n.target || n.nodeName) === this.name;
        },
        toString: function () {
            return wrap('processing-instruction("', '")', this.name);
        }
    }, function (name) { this.name = name; })

    // singletons

    // elements, attributes, namespaces
    NodeTest.nameTestAny = NodeTest.makeNodeTypeTest(NodeTest.NAMETESTANY, [1, 2, XPathNamespace.XPATH_NAMESPACE_NODE], '*');
    // text, cdata
    NodeTest.textTest = NodeTest.makeNodeTypeTest(NodeTest.TEXT, [3, 4], 'text()');
    NodeTest.commentTest = NodeTest.makeNodeTypeTest(NodeTest.COMMENT, [8], 'comment()');
    // elements, attributes, text, cdata, PIs, comments, document nodes
    NodeTest.nodeTest = NodeTest.makeNodeTypeTest(NodeTest.NODE, [1, 2, 3, 4, 7, 8, 9], 'node()');
    NodeTest.anyPiTest = NodeTest.makeNodeTypeTest(NodeTest.PI, [7], 'processing-instruction()');

    // VariableReference /////////////////////////////////////////////////////////

    VariableReference.prototype = new Expression();
    VariableReference.prototype.constructor = VariableReference;
    VariableReference.superclass = Expression.prototype;

    function VariableReference(v) {
        if (arguments.length > 0) {
            this.init(v);
        }
    }

    VariableReference.prototype.init = function (v) {
        this.variable = v;
    };

    VariableReference.prototype.toString = function () {
        return "$" + this.variable;
    };

    VariableReference.prototype.evaluate = function (c) {
        var parts = Utilities.resolveQName(this.variable, c.namespaceResolver, c.contextNode, false);

        if (parts[0] == null) {
            throw new Error("Cannot resolve QName " + fn);
        }
        var result = c.variableResolver.getVariable(parts[1], parts[0]);
        if (!result) {
            throw XPathException.fromMessage("Undeclared variable: " + this.toString());
        }
        return result;
    };

    // FunctionCall //////////////////////////////////////////////////////////////

    FunctionCall.prototype = new Expression();
    FunctionCall.prototype.constructor = FunctionCall;
    FunctionCall.superclass = Expression.prototype;

    function FunctionCall(fn, args) {
        if (arguments.length > 0) {
            this.init(fn, args);
        }
    }

    FunctionCall.prototype.init = function (fn, args) {
        this.functionName = fn;
        this.arguments = args;
    };

    FunctionCall.prototype.toString = function () {
        var s = this.functionName + "(";
        for (var i = 0; i < this.arguments.length; i++) {
            if (i > 0) {
                s += ", ";
            }
            s += this.arguments[i].toString();
        }
        return s + ")";
    };

    FunctionCall.prototype.evaluate = function (c) {
        var f = FunctionResolver.getFunctionFromContext(this.functionName, c);

        if (!f) {
            throw new Error("Unknown function " + this.functionName);
        }

        var a = [c].concat(this.arguments);
        return f.apply(c.functionResolver.thisArg, a);
    };

    // Operators /////////////////////////////////////////////////////////////////

    var Operators = new Object();

    Operators.equals = function (l, r) {
        return l.equals(r);
    };

    Operators.notequal = function (l, r) {
        return l.notequal(r);
    };

    Operators.lessthan = function (l, r) {
        return l.lessthan(r);
    };

    Operators.greaterthan = function (l, r) {
        return l.greaterthan(r);
    };

    Operators.lessthanorequal = function (l, r) {
        return l.lessthanorequal(r);
    };

    Operators.greaterthanorequal = function (l, r) {
        return l.greaterthanorequal(r);
    };

    // XString ///////////////////////////////////////////////////////////////////

    XString.prototype = new Expression();
    XString.prototype.constructor = XString;
    XString.superclass = Expression.prototype;

    function XString(s) {
        if (arguments.length > 0) {
            this.init(s);
        }
    }

    XString.prototype.init = function (s) {
        this.str = String(s);
    };

    XString.prototype.toString = function () {
        return this.str;
    };

    XString.prototype.evaluate = function (c) {
        return this;
    };

    XString.prototype.string = function () {
        return this;
    };

    XString.prototype.number = function () {
        return new XNumber(this.str);
    };

    XString.prototype.bool = function () {
        return new XBoolean(this.str);
    };

    XString.prototype.nodeset = function () {
        throw new Error("Cannot convert string to nodeset");
    };

    XString.prototype.stringValue = function () {
        return this.str;
    };

    XString.prototype.numberValue = function () {
        return this.number().numberValue();
    };

    XString.prototype.booleanValue = function () {
        return this.bool().booleanValue();
    };

    XString.prototype.equals = function (r) {
        if (Utilities.instance_of(r, XBoolean)) {
            return this.bool().equals(r);
        }
        if (Utilities.instance_of(r, XNumber)) {
            return this.number().equals(r);
        }
        if (Utilities.instance_of(r, XNodeSet)) {
            return r.compareWithString(this, Operators.equals);
        }
        return new XBoolean(this.str == r.str);
    };

    XString.prototype.notequal = function (r) {
        if (Utilities.instance_of(r, XBoolean)) {
            return this.bool().notequal(r);
        }
        if (Utilities.instance_of(r, XNumber)) {
            return this.number().notequal(r);
        }
        if (Utilities.instance_of(r, XNodeSet)) {
            return r.compareWithString(this, Operators.notequal);
        }
        return new XBoolean(this.str != r.str);
    };

    XString.prototype.lessthan = function (r) {
        return this.number().lessthan(r);
    };

    XString.prototype.greaterthan = function (r) {
        return this.number().greaterthan(r);
    };

    XString.prototype.lessthanorequal = function (r) {
        return this.number().lessthanorequal(r);
    };

    XString.prototype.greaterthanorequal = function (r) {
        return this.number().greaterthanorequal(r);
    };

    // XNumber ///////////////////////////////////////////////////////////////////

    XNumber.prototype = new Expression();
    XNumber.prototype.constructor = XNumber;
    XNumber.superclass = Expression.prototype;

    function XNumber(n) {
        if (arguments.length > 0) {
            this.init(n);
        }
    }

    XNumber.prototype.init = function (n) {
        this.num = typeof n === "string" ? this.parse(n) : Number(n);
    };

    XNumber.prototype.numberFormat = /^\s*-?[0-9]*\.?[0-9]+\s*$/;

    XNumber.prototype.parse = function (s) {
        // XPath representation of numbers is more restrictive than what Number() or parseFloat() allow
        return this.numberFormat.test(s) ? parseFloat(s) : Number.NaN;
    };

    function padSmallNumber(numberStr) {
        var parts = numberStr.split('e-');
        var base = parts[0].replace('.', '');
        var exponent = Number(parts[1]);

        for (var i = 0; i < exponent - 1; i += 1) {
            base = '0' + base;
        }

        return '0.' + base;
    }

    function padLargeNumber(numberStr) {
        var parts = numberStr.split('e');
        var base = parts[0].replace('.', '');
        var exponent = Number(parts[1]);
        var zerosToAppend = exponent + 1 - base.length;

        for (var i = 0; i < zerosToAppend; i += 1) {
            base += '0';
        }

        return base;
    }

    XNumber.prototype.toString = function () {
        var strValue = this.num.toString();

        if (strValue.indexOf('e-') !== -1) {
            return padSmallNumber(strValue);
        }

        if (strValue.indexOf('e') !== -1) {
            return padLargeNumber(strValue);
        }

        return strValue;
    };

    XNumber.prototype.evaluate = function (c) {
        return this;
    };

    XNumber.prototype.string = function () {


        return new XString(this.toString());
    };

    XNumber.prototype.number = function () {
        return this;
    };

    XNumber.prototype.bool = function () {
        return new XBoolean(this.num);
    };

    XNumber.prototype.nodeset = function () {
        throw new Error("Cannot convert number to nodeset");
    };

    XNumber.prototype.stringValue = function () {
        return this.string().stringValue();
    };

    XNumber.prototype.numberValue = function () {
        return this.num;
    };

    XNumber.prototype.booleanValue = function () {
        return this.bool().booleanValue();
    };

    XNumber.prototype.negate = function () {
        return new XNumber(-this.num);
    };

    XNumber.prototype.equals = function (r) {
        if (Utilities.instance_of(r, XBoolean)) {
            return this.bool().equals(r);
        }
        if (Utilities.instance_of(r, XString)) {
            return this.equals(r.number());
        }
        if (Utilities.instance_of(r, XNodeSet)) {
            return r.compareWithNumber(this, Operators.equals);
        }
        return new XBoolean(this.num == r.num);
    };

    XNumber.prototype.notequal = function (r) {
        if (Utilities.instance_of(r, XBoolean)) {
            return this.bool().notequal(r);
        }
        if (Utilities.instance_of(r, XString)) {
            return this.notequal(r.number());
        }
        if (Utilities.instance_of(r, XNodeSet)) {
            return r.compareWithNumber(this, Operators.notequal);
        }
        return new XBoolean(this.num != r.num);
    };

    XNumber.prototype.lessthan = function (r) {
        if (Utilities.instance_of(r, XNodeSet)) {
            return r.compareWithNumber(this, Operators.greaterthan);
        }
        if (Utilities.instance_of(r, XBoolean) || Utilities.instance_of(r, XString)) {
            return this.lessthan(r.number());
        }
        return new XBoolean(this.num < r.num);
    };

    XNumber.prototype.greaterthan = function (r) {
        if (Utilities.instance_of(r, XNodeSet)) {
            return r.compareWithNumber(this, Operators.lessthan);
        }
        if (Utilities.instance_of(r, XBoolean) || Utilities.instance_of(r, XString)) {
            return this.greaterthan(r.number());
        }
        return new XBoolean(this.num > r.num);
    };

    XNumber.prototype.lessthanorequal = function (r) {
        if (Utilities.instance_of(r, XNodeSet)) {
            return r.compareWithNumber(this, Operators.greaterthanorequal);
        }
        if (Utilities.instance_of(r, XBoolean) || Utilities.instance_of(r, XString)) {
            return this.lessthanorequal(r.number());
        }
        return new XBoolean(this.num <= r.num);
    };

    XNumber.prototype.greaterthanorequal = function (r) {
        if (Utilities.instance_of(r, XNodeSet)) {
            return r.compareWithNumber(this, Operators.lessthanorequal);
        }
        if (Utilities.instance_of(r, XBoolean) || Utilities.instance_of(r, XString)) {
            return this.greaterthanorequal(r.number());
        }
        return new XBoolean(this.num >= r.num);
    };

    XNumber.prototype.plus = function (r) {
        return new XNumber(this.num + r.num);
    };

    XNumber.prototype.minus = function (r) {
        return new XNumber(this.num - r.num);
    };

    XNumber.prototype.multiply = function (r) {
        return new XNumber(this.num * r.num);
    };

    XNumber.prototype.div = function (r) {
        return new XNumber(this.num / r.num);
    };

    XNumber.prototype.mod = function (r) {
        return new XNumber(this.num % r.num);
    };

    // XBoolean //////////////////////////////////////////////////////////////////

    XBoolean.prototype = new Expression();
    XBoolean.prototype.constructor = XBoolean;
    XBoolean.superclass = Expression.prototype;

    function XBoolean(b) {
        if (arguments.length > 0) {
            this.init(b);
        }
    }

    XBoolean.prototype.init = function (b) {
        this.b = Boolean(b);
    };

    XBoolean.prototype.toString = function () {
        return this.b.toString();
    };

    XBoolean.prototype.evaluate = function (c) {
        return this;
    };

    XBoolean.prototype.string = function () {
        return new XString(this.b);
    };

    XBoolean.prototype.number = function () {
        return new XNumber(this.b);
    };

    XBoolean.prototype.bool = function () {
        return this;
    };

    XBoolean.prototype.nodeset = function () {
        throw new Error("Cannot convert boolean to nodeset");
    };

    XBoolean.prototype.stringValue = function () {
        return this.string().stringValue();
    };

    XBoolean.prototype.numberValue = function () {
        return this.number().numberValue();
    };

    XBoolean.prototype.booleanValue = function () {
        return this.b;
    };

    XBoolean.prototype.not = function () {
        return new XBoolean(!this.b);
    };

    XBoolean.prototype.equals = function (r) {
        if (Utilities.instance_of(r, XString) || Utilities.instance_of(r, XNumber)) {
            return this.equals(r.bool());
        }
        if (Utilities.instance_of(r, XNodeSet)) {
            return r.compareWithBoolean(this, Operators.equals);
        }
        return new XBoolean(this.b == r.b);
    };

    XBoolean.prototype.notequal = function (r) {
        if (Utilities.instance_of(r, XString) || Utilities.instance_of(r, XNumber)) {
            return this.notequal(r.bool());
        }
        if (Utilities.instance_of(r, XNodeSet)) {
            return r.compareWithBoolean(this, Operators.notequal);
        }
        return new XBoolean(this.b != r.b);
    };

    XBoolean.prototype.lessthan = function (r) {
        return this.number().lessthan(r);
    };

    XBoolean.prototype.greaterthan = function (r) {
        return this.number().greaterthan(r);
    };

    XBoolean.prototype.lessthanorequal = function (r) {
        return this.number().lessthanorequal(r);
    };

    XBoolean.prototype.greaterthanorequal = function (r) {
        return this.number().greaterthanorequal(r);
    };

    XBoolean.true_ = new XBoolean(true);
    XBoolean.false_ = new XBoolean(false);

    // AVLTree ///////////////////////////////////////////////////////////////////

    AVLTree.prototype = new Object();
    AVLTree.prototype.constructor = AVLTree;
    AVLTree.superclass = Object.prototype;

    function AVLTree(n) {
        this.init(n);
    }

    AVLTree.prototype.init = function (n) {
        this.left = null;
        this.right = null;
        this.node = n;
        this.depth = 1;
    };

    AVLTree.prototype.balance = function () {
        var ldepth = this.left == null ? 0 : this.left.depth;
        var rdepth = this.right == null ? 0 : this.right.depth;

        if (ldepth > rdepth + 1) {
            // LR or LL rotation
            var lldepth = this.left.left == null ? 0 : this.left.left.depth;
            var lrdepth = this.left.right == null ? 0 : this.left.right.depth;

            if (lldepth < lrdepth) {
                // LR rotation consists of a RR rotation of the left child
                this.left.rotateRR();
                // plus a LL rotation of this node, which happens anyway
            }
            this.rotateLL();
        } else if (ldepth + 1 < rdepth) {
            // RR or RL rorarion
            var rrdepth = this.right.right == null ? 0 : this.right.right.depth;
            var rldepth = this.right.left == null ? 0 : this.right.left.depth;

            if (rldepth > rrdepth) {
                // RR rotation consists of a LL rotation of the right child
                this.right.rotateLL();
                // plus a RR rotation of this node, which happens anyway
            }
            this.rotateRR();
        }
    };

    AVLTree.prototype.rotateLL = function () {
        // the left side is too long => rotate from the left (_not_ leftwards)
        var nodeBefore = this.node;
        var rightBefore = this.right;
        this.node = this.left.node;
        this.right = this.left;
        this.left = this.left.left;
        this.right.left = this.right.right;
        this.right.right = rightBefore;
        this.right.node = nodeBefore;
        this.right.updateInNewLocation();
        this.updateInNewLocation();
    };

    AVLTree.prototype.rotateRR = function () {
        // the right side is too long => rotate from the right (_not_ rightwards)
        var nodeBefore = this.node;
        var leftBefore = this.left;
        this.node = this.right.node;
        this.left = this.right;
        this.right = this.right.right;
        this.left.right = this.left.left;
        this.left.left = leftBefore;
        this.left.node = nodeBefore;
        this.left.updateInNewLocation();
        this.updateInNewLocation();
    };

    AVLTree.prototype.updateInNewLocation = function () {
        this.getDepthFromChildren();
    };

    AVLTree.prototype.getDepthFromChildren = function () {
        this.depth = this.node == null ? 0 : 1;
        if (this.left != null) {
            this.depth = this.left.depth + 1;
        }
        if (this.right != null && this.depth <= this.right.depth) {
            this.depth = this.right.depth + 1;
        }
    };

    function nodeOrder(n1, n2) {
        if (n1 === n2) {
            return 0;
        }

        if (n1.compareDocumentPosition) {
            var cpos = n1.compareDocumentPosition(n2);

            if (cpos & 0x01) {
                // not in the same document; return an arbitrary result (is there a better way to do this)
                return 1;
            }
            if (cpos & 0x0A) {
                // n2 precedes or contains n1
                return 1;
            }
            if (cpos & 0x14) {
                // n2 follows or is contained by n1
                return -1;
            }

            return 0;
        }

        var d1 = 0,
            d2 = 0;
        for (var m1 = n1; m1 != null; m1 = m1.parentNode || m1.ownerElement) {
            d1++;
        }
        for (var m2 = n2; m2 != null; m2 = m2.parentNode || m2.ownerElement) {
            d2++;
        }

        // step up to same depth
        if (d1 > d2) {
            while (d1 > d2) {
                n1 = n1.parentNode || n1.ownerElement;
                d1--;
            }
            if (n1 === n2) {
                return 1;
            }
        } else if (d2 > d1) {
            while (d2 > d1) {
                n2 = n2.parentNode || n2.ownerElement;
                d2--;
            }
            if (n1 === n2) {
                return -1;
            }
        }

        var n1Par = n1.parentNode || n1.ownerElement,
            n2Par = n2.parentNode || n2.ownerElement;

        // find common parent
        while (n1Par !== n2Par) {
            n1 = n1Par;
            n2 = n2Par;
            n1Par = n1.parentNode || n1.ownerElement;
            n2Par = n2.parentNode || n2.ownerElement;
        }

        var n1isAttr = Utilities.isAttribute(n1);
        var n2isAttr = Utilities.isAttribute(n2);

        if (n1isAttr && !n2isAttr) {
            return -1;
        }
        if (!n1isAttr && n2isAttr) {
            return 1;
        }

        if (n1Par) {
            var cn = n1isAttr ? n1Par.attributes : n1Par.childNodes,
                len = cn.length;
            for (var i = 0; i < len; i += 1) {
                var n = cn[i];
                if (n === n1) {
                    return -1;
                }
                if (n === n2) {
                    return 1;
                }
            }
        }

        throw new Error('Unexpected: could not determine node order');
    }

    AVLTree.prototype.add = function (n) {
        if (n === this.node) {
            return false;
        }

        var o = nodeOrder(n, this.node);

        var ret = false;
        if (o == -1) {
            if (this.left == null) {
                this.left = new AVLTree(n);
                ret = true;
            } else {
                ret = this.left.add(n);
                if (ret) {
                    this.balance();
                }
            }
        } else if (o == 1) {
            if (this.right == null) {
                this.right = new AVLTree(n);
                ret = true;
            } else {
                ret = this.right.add(n);
                if (ret) {
                    this.balance();
                }
            }
        }

        if (ret) {
            this.getDepthFromChildren();
        }
        return ret;
    };

    // XNodeSet //////////////////////////////////////////////////////////////////

    XNodeSet.prototype = new Expression();
    XNodeSet.prototype.constructor = XNodeSet;
    XNodeSet.superclass = Expression.prototype;

    function XNodeSet() {
        this.init();
    }

    XNodeSet.prototype.init = function () {
        this.tree = null;
        this.nodes = [];
        this.size = 0;
    };

    XNodeSet.prototype.toString = function () {
        var p = this.first();
        if (p == null) {
            return "";
        }
        return this.stringForNode(p);
    };

    XNodeSet.prototype.evaluate = function (c) {
        return this;
    };

    XNodeSet.prototype.string = function () {
        return new XString(this.toString());
    };

    XNodeSet.prototype.stringValue = function () {
        return this.toString();
    };

    XNodeSet.prototype.number = function () {
        return new XNumber(this.string());
    };

    XNodeSet.prototype.numberValue = function () {
        return Number(this.string());
    };

    XNodeSet.prototype.bool = function () {
        return new XBoolean(this.booleanValue());
    };

    XNodeSet.prototype.booleanValue = function () {
        return !!this.size;
    };

    XNodeSet.prototype.nodeset = function () {
        return this;
    };

    XNodeSet.prototype.stringForNode = function (n) {
        if (n.nodeType == 9   /*Node.DOCUMENT_NODE*/ ||
            n.nodeType == 1   /*Node.ELEMENT_NODE */ ||
            n.nodeType === 11 /*Node.DOCUMENT_FRAGMENT*/) {
            return this.stringForContainerNode(n);
        }
        if (n.nodeType === 2 /* Node.ATTRIBUTE_NODE */) {
            return n.value || n.nodeValue;
        }
        if (n.isNamespaceNode) {
            return n.namespace;
        }
        return n.nodeValue;
    };

    XNodeSet.prototype.stringForContainerNode = function (n) {
        var s = "";
        for (var n2 = n.firstChild; n2 != null; n2 = n2.nextSibling) {
            var nt = n2.nodeType;
            //  Element,    Text,       CDATA,      Document,   Document Fragment
            if (nt === 1 || nt === 3 || nt === 4 || nt === 9 || nt === 11) {
                s += this.stringForNode(n2);
            }
        }
        return s;
    };

    XNodeSet.prototype.buildTree = function () {
        if (!this.tree && this.nodes.length) {
            this.tree = new AVLTree(this.nodes[0]);
            for (var i = 1; i < this.nodes.length; i += 1) {
                this.tree.add(this.nodes[i]);
            }
        }

        return this.tree;
    };

    XNodeSet.prototype.first = function () {
        var p = this.buildTree();
        if (p == null) {
            return null;
        }
        while (p.left != null) {
            p = p.left;
        }
        return p.node;
    };

    XNodeSet.prototype.add = function (n) {
        for (var i = 0; i < this.nodes.length; i += 1) {
            if (n === this.nodes[i]) {
                return;
            }
        }

        this.tree = null;
        this.nodes.push(n);
        this.size += 1;
    };

    XNodeSet.prototype.addArray = function (ns) {
        var self = this;

        forEach(function (x) { self.add(x); }, ns);
    };

    /**
     * Returns an array of the node set's contents in document order
     */
    XNodeSet.prototype.toArray = function () {
        var a = [];
        this.toArrayRec(this.buildTree(), a);
        return a;
    };

    XNodeSet.prototype.toArrayRec = function (t, a) {
        if (t != null) {
            this.toArrayRec(t.left, a);
            a.push(t.node);
            this.toArrayRec(t.right, a);
        }
    };

    /**
     * Returns an array of the node set's contents in arbitrary order
     */
    XNodeSet.prototype.toUnsortedArray = function () {
        return this.nodes.slice();
    };

    XNodeSet.prototype.compareWithString = function (r, o) {
        var a = this.toUnsortedArray();
        for (var i = 0; i < a.length; i++) {
            var n = a[i];
            var l = new XString(this.stringForNode(n));
            var res = o(l, r);
            if (res.booleanValue()) {
                return res;
            }
        }
        return new XBoolean(false);
    };

    XNodeSet.prototype.compareWithNumber = function (r, o) {
        var a = this.toUnsortedArray();
        for (var i = 0; i < a.length; i++) {
            var n = a[i];
            var l = new XNumber(this.stringForNode(n));
            var res = o(l, r);
            if (res.booleanValue()) {
                return res;
            }
        }
        return new XBoolean(false);
    };

    XNodeSet.prototype.compareWithBoolean = function (r, o) {
        return o(this.bool(), r);
    };

    XNodeSet.prototype.compareWithNodeSet = function (r, o) {
        var arr = this.toUnsortedArray();
        var oInvert = function (lop, rop) { return o(rop, lop); };

        for (var i = 0; i < arr.length; i++) {
            var l = new XString(this.stringForNode(arr[i]));

            var res = r.compareWithString(l, oInvert);
            if (res.booleanValue()) {
                return res;
            }
        }

        return new XBoolean(false);
    };

    XNodeSet.compareWith = curry(function (o, r) {
        if (Utilities.instance_of(r, XString)) {
            return this.compareWithString(r, o);
        }
        if (Utilities.instance_of(r, XNumber)) {
            return this.compareWithNumber(r, o);
        }
        if (Utilities.instance_of(r, XBoolean)) {
            return this.compareWithBoolean(r, o);
        }
        return this.compareWithNodeSet(r, o);
    });

    XNodeSet.prototype.equals = XNodeSet.compareWith(Operators.equals);
    XNodeSet.prototype.notequal = XNodeSet.compareWith(Operators.notequal);
    XNodeSet.prototype.lessthan = XNodeSet.compareWith(Operators.lessthan);
    XNodeSet.prototype.greaterthan = XNodeSet.compareWith(Operators.greaterthan);
    XNodeSet.prototype.lessthanorequal = XNodeSet.compareWith(Operators.lessthanorequal);
    XNodeSet.prototype.greaterthanorequal = XNodeSet.compareWith(Operators.greaterthanorequal);

    XNodeSet.prototype.union = function (r) {
        var ns = new XNodeSet();
        ns.addArray(this.toUnsortedArray());
        ns.addArray(r.toUnsortedArray());
        return ns;
    };

    // XPathNamespace ////////////////////////////////////////////////////////////

    XPathNamespace.prototype = new Object();
    XPathNamespace.prototype.constructor = XPathNamespace;
    XPathNamespace.superclass = Object.prototype;

    function XPathNamespace(pre, ns, p) {
        this.isXPathNamespace = true;
        this.ownerDocument = p.ownerDocument;
        this.nodeName = "#namespace";
        this.prefix = pre;
        this.localName = pre;
        this.namespaceURI = ns;
        this.nodeValue = ns;
        this.ownerElement = p;
        this.nodeType = XPathNamespace.XPATH_NAMESPACE_NODE;
    }

    XPathNamespace.prototype.toString = function () {
        return "{ \"" + this.prefix + "\", \"" + this.namespaceURI + "\" }";
    };

    // XPathContext //////////////////////////////////////////////////////////////

    XPathContext.prototype = new Object();
    XPathContext.prototype.constructor = XPathContext;
    XPathContext.superclass = Object.prototype;

    function XPathContext(vr, nr, fr) {
        this.variableResolver = vr != null ? vr : new VariableResolver();
        this.namespaceResolver = nr != null ? nr : new NamespaceResolver();
        this.functionResolver = fr != null ? fr : new FunctionResolver();
    }

    XPathContext.prototype.extend = function (newProps) {
        return assign(new XPathContext(), this, newProps);
    };

    // VariableResolver //////////////////////////////////////////////////////////

    VariableResolver.prototype = new Object();
    VariableResolver.prototype.constructor = VariableResolver;
    VariableResolver.superclass = Object.prototype;

    function VariableResolver() {
    }

    VariableResolver.prototype.getVariable = function (ln, ns) {
        return null;
    };

    // FunctionResolver //////////////////////////////////////////////////////////

    FunctionResolver.prototype = new Object();
    FunctionResolver.prototype.constructor = FunctionResolver;
    FunctionResolver.superclass = Object.prototype;

    function FunctionResolver(thisArg) {
        this.thisArg = thisArg != null ? thisArg : Functions;
        this.functions = new Object();
        this.addStandardFunctions();
    }

    FunctionResolver.prototype.addStandardFunctions = function () {
        this.functions["{}last"] = Functions.last;
        this.functions["{}position"] = Functions.position;
        this.functions["{}count"] = Functions.count;
        this.functions["{}id"] = Functions.id;
        this.functions["{}local-name"] = Functions.localName;
        this.functions["{}namespace-uri"] = Functions.namespaceURI;
        this.functions["{}name"] = Functions.name;
        this.functions["{}string"] = Functions.string;
        this.functions["{}concat"] = Functions.concat;
        this.functions["{}starts-with"] = Functions.startsWith;
        this.functions["{}contains"] = Functions.contains;
        this.functions["{}substring-before"] = Functions.substringBefore;
        this.functions["{}substring-after"] = Functions.substringAfter;
        this.functions["{}substring"] = Functions.substring;
        this.functions["{}string-length"] = Functions.stringLength;
        this.functions["{}normalize-space"] = Functions.normalizeSpace;
        this.functions["{}translate"] = Functions.translate;
        this.functions["{}boolean"] = Functions.boolean_;
        this.functions["{}not"] = Functions.not;
        this.functions["{}true"] = Functions.true_;
        this.functions["{}false"] = Functions.false_;
        this.functions["{}lang"] = Functions.lang;
        this.functions["{}number"] = Functions.number;
        this.functions["{}sum"] = Functions.sum;
        this.functions["{}floor"] = Functions.floor;
        this.functions["{}ceiling"] = Functions.ceiling;
        this.functions["{}round"] = Functions.round;
    };

    FunctionResolver.prototype.addFunction = function (ns, ln, f) {
        this.functions["{" + ns + "}" + ln] = f;
    };

    FunctionResolver.getFunctionFromContext = function (qName, context) {
        var parts = Utilities.resolveQName(qName, context.namespaceResolver, context.contextNode, false);

        if (parts[0] === null) {
            throw new Error("Cannot resolve QName " + name);
        }

        return context.functionResolver.getFunction(parts[1], parts[0]);
    };

    FunctionResolver.prototype.getFunction = function (localName, namespace) {
        return this.functions["{" + namespace + "}" + localName];
    };

    // NamespaceResolver /////////////////////////////////////////////////////////

    NamespaceResolver.prototype = new Object();
    NamespaceResolver.prototype.constructor = NamespaceResolver;
    NamespaceResolver.superclass = Object.prototype;

    function NamespaceResolver() {
    }

    NamespaceResolver.prototype.getNamespace = function (prefix, n) {
        if (prefix == "xml") {
            return XPath.XML_NAMESPACE_URI;
        } else if (prefix == "xmlns") {
            return XPath.XMLNS_NAMESPACE_URI;
        }
        if (n.nodeType == 9 /*Node.DOCUMENT_NODE*/) {
            n = n.documentElement;
        } else if (n.nodeType == 2 /*Node.ATTRIBUTE_NODE*/) {
            n = PathExpr.getOwnerElement(n);
        } else if (n.nodeType != 1 /*Node.ELEMENT_NODE*/) {
            n = n.parentNode;
        }
        while (n != null && n.nodeType == 1 /*Node.ELEMENT_NODE*/) {
            var nnm = n.attributes;
            for (var i = 0; i < nnm.length; i++) {
                var a = nnm.item(i);
                var aname = a.name || a.nodeName;
                if ((aname === "xmlns" && prefix === "")
                    || aname === "xmlns:" + prefix) {
                    return String(a.value || a.nodeValue);
                }
            }
            n = n.parentNode;
        }
        return null;
    };

    // Functions /////////////////////////////////////////////////////////////////

    var Functions = new Object();

    Functions.last = function (c) {
        if (arguments.length != 1) {
            throw new Error("Function last expects ()");
        }

        return new XNumber(c.contextSize);
    };

    Functions.position = function (c) {
        if (arguments.length != 1) {
            throw new Error("Function position expects ()");
        }

        return new XNumber(c.contextPosition);
    };

    Functions.count = function () {
        var c = arguments[0];
        var ns;
        if (arguments.length != 2 || !Utilities.instance_of(ns = arguments[1].evaluate(c), XNodeSet)) {
            throw new Error("Function count expects (node-set)");
        }
        return new XNumber(ns.size);
    };

    Functions.id = function () {
        var c = arguments[0];
        var id;
        if (arguments.length != 2) {
            throw new Error("Function id expects (object)");
        }
        id = arguments[1].evaluate(c);
        if (Utilities.instance_of(id, XNodeSet)) {
            id = id.toArray().join(" ");
        } else {
            id = id.stringValue();
        }
        var ids = id.split(/[\x0d\x0a\x09\x20]+/);
        var count = 0;
        var ns = new XNodeSet();
        var doc = c.contextNode.nodeType == 9 /*Node.DOCUMENT_NODE*/
            ? c.contextNode
            : c.contextNode.ownerDocument;
        for (var i = 0; i < ids.length; i++) {
            var n;
            if (doc.getElementById) {
                n = doc.getElementById(ids[i]);
            } else {
                n = Utilities.getElementById(doc, ids[i]);
            }
            if (n != null) {
                ns.add(n);
                count++;
            }
        }
        return ns;
    };

    Functions.localName = function (c, eNode) {
        var n;

        if (arguments.length == 1) {
            n = c.contextNode;
        } else if (arguments.length == 2) {
            n = eNode.evaluate(c).first();
        } else {
            throw new Error("Function local-name expects (node-set?)");
        }

        if (n == null) {
            return new XString("");
        }

        return new XString(
            n.localName ||     //  standard elements and attributes
            n.baseName ||     //  IE
            n.target ||     //  processing instructions
            n.nodeName ||     //  DOM1 elements
            ""                 //  fallback
        );
    };

    Functions.namespaceURI = function () {
        var c = arguments[0];
        var n;
        if (arguments.length == 1) {
            n = c.contextNode;
        } else if (arguments.length == 2) {
            n = arguments[1].evaluate(c).first();
        } else {
            throw new Error("Function namespace-uri expects (node-set?)");
        }
        if (n == null) {
            return new XString("");
        }
        return new XString(n.namespaceURI);
    };

    Functions.name = function () {
        var c = arguments[0];
        var n;
        if (arguments.length == 1) {
            n = c.contextNode;
        } else if (arguments.length == 2) {
            n = arguments[1].evaluate(c).first();
        } else {
            throw new Error("Function name expects (node-set?)");
        }
        if (n == null) {
            return new XString("");
        }
        if (n.nodeType == 1 /*Node.ELEMENT_NODE*/) {
            return new XString(n.nodeName);
        } else if (n.nodeType == 2 /*Node.ATTRIBUTE_NODE*/) {
            return new XString(n.name || n.nodeName);
        } else if (n.nodeType === 7 /*Node.PROCESSING_INSTRUCTION_NODE*/) {
            return new XString(n.target || n.nodeName);
        } else if (n.localName == null) {
            return new XString("");
        } else {
            return new XString(n.localName);
        }
    };

    Functions.string = function () {
        var c = arguments[0];
        if (arguments.length == 1) {
            return new XString(XNodeSet.prototype.stringForNode(c.contextNode));
        } else if (arguments.length == 2) {
            return arguments[1].evaluate(c).string();
        }
        throw new Error("Function string expects (object?)");
    };

    Functions.concat = function (c) {
        if (arguments.length < 3) {
            throw new Error("Function concat expects (string, string[, string]*)");
        }
        var s = "";
        for (var i = 1; i < arguments.length; i++) {
            s += arguments[i].evaluate(c).stringValue();
        }
        return new XString(s);
    };

    Functions.startsWith = function () {
        var c = arguments[0];
        if (arguments.length != 3) {
            throw new Error("Function startsWith expects (string, string)");
        }
        var s1 = arguments[1].evaluate(c).stringValue();
        var s2 = arguments[2].evaluate(c).stringValue();
        return new XBoolean(s1.substring(0, s2.length) == s2);
    };

    Functions.contains = function () {
        var c = arguments[0];
        if (arguments.length != 3) {
            throw new Error("Function contains expects (string, string)");
        }
        var s1 = arguments[1].evaluate(c).stringValue();
        var s2 = arguments[2].evaluate(c).stringValue();
        return new XBoolean(s1.indexOf(s2) !== -1);
    };

    Functions.substringBefore = function () {
        var c = arguments[0];
        if (arguments.length != 3) {
            throw new Error("Function substring-before expects (string, string)");
        }
        var s1 = arguments[1].evaluate(c).stringValue();
        var s2 = arguments[2].evaluate(c).stringValue();
        return new XString(s1.substring(0, s1.indexOf(s2)));
    };

    Functions.substringAfter = function () {
        var c = arguments[0];
        if (arguments.length != 3) {
            throw new Error("Function substring-after expects (string, string)");
        }
        var s1 = arguments[1].evaluate(c).stringValue();
        var s2 = arguments[2].evaluate(c).stringValue();
        if (s2.length == 0) {
            return new XString(s1);
        }
        var i = s1.indexOf(s2);
        if (i == -1) {
            return new XString("");
        }
        return new XString(s1.substring(i + s2.length));
    };

    Functions.substring = function () {
        var c = arguments[0];
        if (!(arguments.length == 3 || arguments.length == 4)) {
            throw new Error("Function substring expects (string, number, number?)");
        }
        var s = arguments[1].evaluate(c).stringValue();
        var n1 = Math.round(arguments[2].evaluate(c).numberValue()) - 1;
        var n2 = arguments.length == 4 ? n1 + Math.round(arguments[3].evaluate(c).numberValue()) : undefined;
        return new XString(s.substring(n1, n2));
    };

    Functions.stringLength = function () {
        var c = arguments[0];
        var s;
        if (arguments.length == 1) {
            s = XNodeSet.prototype.stringForNode(c.contextNode);
        } else if (arguments.length == 2) {
            s = arguments[1].evaluate(c).stringValue();
        } else {
            throw new Error("Function string-length expects (string?)");
        }
        return new XNumber(s.length);
    };

    Functions.normalizeSpace = function () {
        var c = arguments[0];
        var s;
        if (arguments.length == 1) {
            s = XNodeSet.prototype.stringForNode(c.contextNode);
        } else if (arguments.length == 2) {
            s = arguments[1].evaluate(c).stringValue();
        } else {
            throw new Error("Function normalize-space expects (string?)");
        }
        var i = 0;
        var j = s.length - 1;
        while (Utilities.isSpace(s.charCodeAt(j))) {
            j--;
        }
        var t = "";
        while (i <= j && Utilities.isSpace(s.charCodeAt(i))) {
            i++;
        }
        while (i <= j) {
            if (Utilities.isSpace(s.charCodeAt(i))) {
                t += " ";
                while (i <= j && Utilities.isSpace(s.charCodeAt(i))) {
                    i++;
                }
            } else {
                t += s.charAt(i);
                i++;
            }
        }
        return new XString(t);
    };

    Functions.translate = function (c, eValue, eFrom, eTo) {
        if (arguments.length != 4) {
            throw new Error("Function translate expects (string, string, string)");
        }

        var value = eValue.evaluate(c).stringValue();
        var from = eFrom.evaluate(c).stringValue();
        var to = eTo.evaluate(c).stringValue();

        var cMap = reduce(function (acc, ch, i) {
            if (!(ch in acc)) {
                acc[ch] = i > to.length ? '' : to[i];
            }
            return acc;
        }, {}, from);

        var t = join(
            '',
            map(function (ch) {
                return ch in cMap ? cMap[ch] : ch;
            }, value)
        );

        return new XString(t);
    };

    Functions.boolean_ = function () {
        var c = arguments[0];
        if (arguments.length != 2) {
            throw new Error("Function boolean expects (object)");
        }
        return arguments[1].evaluate(c).bool();
    };

    Functions.not = function (c, eValue) {
        if (arguments.length != 2) {
            throw new Error("Function not expects (object)");
        }
        return eValue.evaluate(c).bool().not();
    };

    Functions.true_ = function () {
        if (arguments.length != 1) {
            throw new Error("Function true expects ()");
        }
        return XBoolean.true_;
    };

    Functions.false_ = function () {
        if (arguments.length != 1) {
            throw new Error("Function false expects ()");
        }
        return XBoolean.false_;
    };

    Functions.lang = function () {
        var c = arguments[0];
        if (arguments.length != 2) {
            throw new Error("Function lang expects (string)");
        }
        var lang;
        for (var n = c.contextNode; n != null && n.nodeType != 9 /*Node.DOCUMENT_NODE*/; n = n.parentNode) {
            var a = n.getAttributeNS(XPath.XML_NAMESPACE_URI, "lang");
            if (a != null) {
                lang = String(a);
                break;
            }
        }
        if (lang == null) {
            return XBoolean.false_;
        }
        var s = arguments[1].evaluate(c).stringValue();
        return new XBoolean(lang.substring(0, s.length) == s
            && (lang.length == s.length || lang.charAt(s.length) == '-'));
    };

    Functions.number = function () {
        var c = arguments[0];
        if (!(arguments.length == 1 || arguments.length == 2)) {
            throw new Error("Function number expects (object?)");
        }
        if (arguments.length == 1) {
            return new XNumber(XNodeSet.prototype.stringForNode(c.contextNode));
        }
        return arguments[1].evaluate(c).number();
    };

    Functions.sum = function () {
        var c = arguments[0];
        var ns;
        if (arguments.length != 2 || !Utilities.instance_of((ns = arguments[1].evaluate(c)), XNodeSet)) {
            throw new Error("Function sum expects (node-set)");
        }
        ns = ns.toUnsortedArray();
        var n = 0;
        for (var i = 0; i < ns.length; i++) {
            n += new XNumber(XNodeSet.prototype.stringForNode(ns[i])).numberValue();
        }
        return new XNumber(n);
    };

    Functions.floor = function () {
        var c = arguments[0];
        if (arguments.length != 2) {
            throw new Error("Function floor expects (number)");
        }
        return new XNumber(Math.floor(arguments[1].evaluate(c).numberValue()));
    };

    Functions.ceiling = function () {
        var c = arguments[0];
        if (arguments.length != 2) {
            throw new Error("Function ceiling expects (number)");
        }
        return new XNumber(Math.ceil(arguments[1].evaluate(c).numberValue()));
    };

    Functions.round = function () {
        var c = arguments[0];
        if (arguments.length != 2) {
            throw new Error("Function round expects (number)");
        }
        return new XNumber(Math.round(arguments[1].evaluate(c).numberValue()));
    };

    // Utilities /////////////////////////////////////////////////////////////////

    var Utilities = new Object();

    Utilities.isAttribute = function (val) {
        return val && (val.nodeType === 2 || val.ownerElement);
    }

    Utilities.splitQName = function (qn) {
        var i = qn.indexOf(":");
        if (i == -1) {
            return [null, qn];
        }
        return [qn.substring(0, i), qn.substring(i + 1)];
    };

    Utilities.resolveQName = function (qn, nr, n, useDefault) {
        var parts = Utilities.splitQName(qn);
        if (parts[0] != null) {
            parts[0] = nr.getNamespace(parts[0], n);
        } else {
            if (useDefault) {
                parts[0] = nr.getNamespace("", n);
                if (parts[0] == null) {
                    parts[0] = "";
                }
            } else {
                parts[0] = "";
            }
        }
        return parts;
    };

    Utilities.isSpace = function (c) {
        return c == 0x9 || c == 0xd || c == 0xa || c == 0x20;
    };

    Utilities.isLetter = function (c) {
        return c >= 0x0041 && c <= 0x005A ||
            c >= 0x0061 && c <= 0x007A ||
            c >= 0x00C0 && c <= 0x00D6 ||
            c >= 0x00D8 && c <= 0x00F6 ||
            c >= 0x00F8 && c <= 0x00FF ||
            c >= 0x0100 && c <= 0x0131 ||
            c >= 0x0134 && c <= 0x013E ||
            c >= 0x0141 && c <= 0x0148 ||
            c >= 0x014A && c <= 0x017E ||
            c >= 0x0180 && c <= 0x01C3 ||
            c >= 0x01CD && c <= 0x01F0 ||
            c >= 0x01F4 && c <= 0x01F5 ||
            c >= 0x01FA && c <= 0x0217 ||
            c >= 0x0250 && c <= 0x02A8 ||
            c >= 0x02BB && c <= 0x02C1 ||
            c == 0x0386 ||
            c >= 0x0388 && c <= 0x038A ||
            c == 0x038C ||
            c >= 0x038E && c <= 0x03A1 ||
            c >= 0x03A3 && c <= 0x03CE ||
            c >= 0x03D0 && c <= 0x03D6 ||
            c == 0x03DA ||
            c == 0x03DC ||
            c == 0x03DE ||
            c == 0x03E0 ||
            c >= 0x03E2 && c <= 0x03F3 ||
            c >= 0x0401 && c <= 0x040C ||
            c >= 0x040E && c <= 0x044F ||
            c >= 0x0451 && c <= 0x045C ||
            c >= 0x045E && c <= 0x0481 ||
            c >= 0x0490 && c <= 0x04C4 ||
            c >= 0x04C7 && c <= 0x04C8 ||
            c >= 0x04CB && c <= 0x04CC ||
            c >= 0x04D0 && c <= 0x04EB ||
            c >= 0x04EE && c <= 0x04F5 ||
            c >= 0x04F8 && c <= 0x04F9 ||
            c >= 0x0531 && c <= 0x0556 ||
            c == 0x0559 ||
            c >= 0x0561 && c <= 0x0586 ||
            c >= 0x05D0 && c <= 0x05EA ||
            c >= 0x05F0 && c <= 0x05F2 ||
            c >= 0x0621 && c <= 0x063A ||
            c >= 0x0641 && c <= 0x064A ||
            c >= 0x0671 && c <= 0x06B7 ||
            c >= 0x06BA && c <= 0x06BE ||
            c >= 0x06C0 && c <= 0x06CE ||
            c >= 0x06D0 && c <= 0x06D3 ||
            c == 0x06D5 ||
            c >= 0x06E5 && c <= 0x06E6 ||
            c >= 0x0905 && c <= 0x0939 ||
            c == 0x093D ||
            c >= 0x0958 && c <= 0x0961 ||
            c >= 0x0985 && c <= 0x098C ||
            c >= 0x098F && c <= 0x0990 ||
            c >= 0x0993 && c <= 0x09A8 ||
            c >= 0x09AA && c <= 0x09B0 ||
            c == 0x09B2 ||
            c >= 0x09B6 && c <= 0x09B9 ||
            c >= 0x09DC && c <= 0x09DD ||
            c >= 0x09DF && c <= 0x09E1 ||
            c >= 0x09F0 && c <= 0x09F1 ||
            c >= 0x0A05 && c <= 0x0A0A ||
            c >= 0x0A0F && c <= 0x0A10 ||
            c >= 0x0A13 && c <= 0x0A28 ||
            c >= 0x0A2A && c <= 0x0A30 ||
            c >= 0x0A32 && c <= 0x0A33 ||
            c >= 0x0A35 && c <= 0x0A36 ||
            c >= 0x0A38 && c <= 0x0A39 ||
            c >= 0x0A59 && c <= 0x0A5C ||
            c == 0x0A5E ||
            c >= 0x0A72 && c <= 0x0A74 ||
            c >= 0x0A85 && c <= 0x0A8B ||
            c == 0x0A8D ||
            c >= 0x0A8F && c <= 0x0A91 ||
            c >= 0x0A93 && c <= 0x0AA8 ||
            c >= 0x0AAA && c <= 0x0AB0 ||
            c >= 0x0AB2 && c <= 0x0AB3 ||
            c >= 0x0AB5 && c <= 0x0AB9 ||
            c == 0x0ABD ||
            c == 0x0AE0 ||
            c >= 0x0B05 && c <= 0x0B0C ||
            c >= 0x0B0F && c <= 0x0B10 ||
            c >= 0x0B13 && c <= 0x0B28 ||
            c >= 0x0B2A && c <= 0x0B30 ||
            c >= 0x0B32 && c <= 0x0B33 ||
            c >= 0x0B36 && c <= 0x0B39 ||
            c == 0x0B3D ||
            c >= 0x0B5C && c <= 0x0B5D ||
            c >= 0x0B5F && c <= 0x0B61 ||
            c >= 0x0B85 && c <= 0x0B8A ||
            c >= 0x0B8E && c <= 0x0B90 ||
            c >= 0x0B92 && c <= 0x0B95 ||
            c >= 0x0B99 && c <= 0x0B9A ||
            c == 0x0B9C ||
            c >= 0x0B9E && c <= 0x0B9F ||
            c >= 0x0BA3 && c <= 0x0BA4 ||
            c >= 0x0BA8 && c <= 0x0BAA ||
            c >= 0x0BAE && c <= 0x0BB5 ||
            c >= 0x0BB7 && c <= 0x0BB9 ||
            c >= 0x0C05 && c <= 0x0C0C ||
            c >= 0x0C0E && c <= 0x0C10 ||
            c >= 0x0C12 && c <= 0x0C28 ||
            c >= 0x0C2A && c <= 0x0C33 ||
            c >= 0x0C35 && c <= 0x0C39 ||
            c >= 0x0C60 && c <= 0x0C61 ||
            c >= 0x0C85 && c <= 0x0C8C ||
            c >= 0x0C8E && c <= 0x0C90 ||
            c >= 0x0C92 && c <= 0x0CA8 ||
            c >= 0x0CAA && c <= 0x0CB3 ||
            c >= 0x0CB5 && c <= 0x0CB9 ||
            c == 0x0CDE ||
            c >= 0x0CE0 && c <= 0x0CE1 ||
            c >= 0x0D05 && c <= 0x0D0C ||
            c >= 0x0D0E && c <= 0x0D10 ||
            c >= 0x0D12 && c <= 0x0D28 ||
            c >= 0x0D2A && c <= 0x0D39 ||
            c >= 0x0D60 && c <= 0x0D61 ||
            c >= 0x0E01 && c <= 0x0E2E ||
            c == 0x0E30 ||
            c >= 0x0E32 && c <= 0x0E33 ||
            c >= 0x0E40 && c <= 0x0E45 ||
            c >= 0x0E81 && c <= 0x0E82 ||
            c == 0x0E84 ||
            c >= 0x0E87 && c <= 0x0E88 ||
            c == 0x0E8A ||
            c == 0x0E8D ||
            c >= 0x0E94 && c <= 0x0E97 ||
            c >= 0x0E99 && c <= 0x0E9F ||
            c >= 0x0EA1 && c <= 0x0EA3 ||
            c == 0x0EA5 ||
            c == 0x0EA7 ||
            c >= 0x0EAA && c <= 0x0EAB ||
            c >= 0x0EAD && c <= 0x0EAE ||
            c == 0x0EB0 ||
            c >= 0x0EB2 && c <= 0x0EB3 ||
            c == 0x0EBD ||
            c >= 0x0EC0 && c <= 0x0EC4 ||
            c >= 0x0F40 && c <= 0x0F47 ||
            c >= 0x0F49 && c <= 0x0F69 ||
            c >= 0x10A0 && c <= 0x10C5 ||
            c >= 0x10D0 && c <= 0x10F6 ||
            c == 0x1100 ||
            c >= 0x1102 && c <= 0x1103 ||
            c >= 0x1105 && c <= 0x1107 ||
            c == 0x1109 ||
            c >= 0x110B && c <= 0x110C ||
            c >= 0x110E && c <= 0x1112 ||
            c == 0x113C ||
            c == 0x113E ||
            c == 0x1140 ||
            c == 0x114C ||
            c == 0x114E ||
            c == 0x1150 ||
            c >= 0x1154 && c <= 0x1155 ||
            c == 0x1159 ||
            c >= 0x115F && c <= 0x1161 ||
            c == 0x1163 ||
            c == 0x1165 ||
            c == 0x1167 ||
            c == 0x1169 ||
            c >= 0x116D && c <= 0x116E ||
            c >= 0x1172 && c <= 0x1173 ||
            c == 0x1175 ||
            c == 0x119E ||
            c == 0x11A8 ||
            c == 0x11AB ||
            c >= 0x11AE && c <= 0x11AF ||
            c >= 0x11B7 && c <= 0x11B8 ||
            c == 0x11BA ||
            c >= 0x11BC && c <= 0x11C2 ||
            c == 0x11EB ||
            c == 0x11F0 ||
            c == 0x11F9 ||
            c >= 0x1E00 && c <= 0x1E9B ||
            c >= 0x1EA0 && c <= 0x1EF9 ||
            c >= 0x1F00 && c <= 0x1F15 ||
            c >= 0x1F18 && c <= 0x1F1D ||
            c >= 0x1F20 && c <= 0x1F45 ||
            c >= 0x1F48 && c <= 0x1F4D ||
            c >= 0x1F50 && c <= 0x1F57 ||
            c == 0x1F59 ||
            c == 0x1F5B ||
            c == 0x1F5D ||
            c >= 0x1F5F && c <= 0x1F7D ||
            c >= 0x1F80 && c <= 0x1FB4 ||
            c >= 0x1FB6 && c <= 0x1FBC ||
            c == 0x1FBE ||
            c >= 0x1FC2 && c <= 0x1FC4 ||
            c >= 0x1FC6 && c <= 0x1FCC ||
            c >= 0x1FD0 && c <= 0x1FD3 ||
            c >= 0x1FD6 && c <= 0x1FDB ||
            c >= 0x1FE0 && c <= 0x1FEC ||
            c >= 0x1FF2 && c <= 0x1FF4 ||
            c >= 0x1FF6 && c <= 0x1FFC ||
            c == 0x2126 ||
            c >= 0x212A && c <= 0x212B ||
            c == 0x212E ||
            c >= 0x2180 && c <= 0x2182 ||
            c >= 0x3041 && c <= 0x3094 ||
            c >= 0x30A1 && c <= 0x30FA ||
            c >= 0x3105 && c <= 0x312C ||
            c >= 0xAC00 && c <= 0xD7A3 ||
            c >= 0x4E00 && c <= 0x9FA5 ||
            c == 0x3007 ||
            c >= 0x3021 && c <= 0x3029;
    };

    Utilities.isNCNameChar = function (c) {
        return c >= 0x0030 && c <= 0x0039
            || c >= 0x0660 && c <= 0x0669
            || c >= 0x06F0 && c <= 0x06F9
            || c >= 0x0966 && c <= 0x096F
            || c >= 0x09E6 && c <= 0x09EF
            || c >= 0x0A66 && c <= 0x0A6F
            || c >= 0x0AE6 && c <= 0x0AEF
            || c >= 0x0B66 && c <= 0x0B6F
            || c >= 0x0BE7 && c <= 0x0BEF
            || c >= 0x0C66 && c <= 0x0C6F
            || c >= 0x0CE6 && c <= 0x0CEF
            || c >= 0x0D66 && c <= 0x0D6F
            || c >= 0x0E50 && c <= 0x0E59
            || c >= 0x0ED0 && c <= 0x0ED9
            || c >= 0x0F20 && c <= 0x0F29
            || c == 0x002E
            || c == 0x002D
            || c == 0x005F
            || Utilities.isLetter(c)
            || c >= 0x0300 && c <= 0x0345
            || c >= 0x0360 && c <= 0x0361
            || c >= 0x0483 && c <= 0x0486
            || c >= 0x0591 && c <= 0x05A1
            || c >= 0x05A3 && c <= 0x05B9
            || c >= 0x05BB && c <= 0x05BD
            || c == 0x05BF
            || c >= 0x05C1 && c <= 0x05C2
            || c == 0x05C4
            || c >= 0x064B && c <= 0x0652
            || c == 0x0670
            || c >= 0x06D6 && c <= 0x06DC
            || c >= 0x06DD && c <= 0x06DF
            || c >= 0x06E0 && c <= 0x06E4
            || c >= 0x06E7 && c <= 0x06E8
            || c >= 0x06EA && c <= 0x06ED
            || c >= 0x0901 && c <= 0x0903
            || c == 0x093C
            || c >= 0x093E && c <= 0x094C
            || c == 0x094D
            || c >= 0x0951 && c <= 0x0954
            || c >= 0x0962 && c <= 0x0963
            || c >= 0x0981 && c <= 0x0983
            || c == 0x09BC
            || c == 0x09BE
            || c == 0x09BF
            || c >= 0x09C0 && c <= 0x09C4
            || c >= 0x09C7 && c <= 0x09C8
            || c >= 0x09CB && c <= 0x09CD
            || c == 0x09D7
            || c >= 0x09E2 && c <= 0x09E3
            || c == 0x0A02
            || c == 0x0A3C
            || c == 0x0A3E
            || c == 0x0A3F
            || c >= 0x0A40 && c <= 0x0A42
            || c >= 0x0A47 && c <= 0x0A48
            || c >= 0x0A4B && c <= 0x0A4D
            || c >= 0x0A70 && c <= 0x0A71
            || c >= 0x0A81 && c <= 0x0A83
            || c == 0x0ABC
            || c >= 0x0ABE && c <= 0x0AC5
            || c >= 0x0AC7 && c <= 0x0AC9
            || c >= 0x0ACB && c <= 0x0ACD
            || c >= 0x0B01 && c <= 0x0B03
            || c == 0x0B3C
            || c >= 0x0B3E && c <= 0x0B43
            || c >= 0x0B47 && c <= 0x0B48
            || c >= 0x0B4B && c <= 0x0B4D
            || c >= 0x0B56 && c <= 0x0B57
            || c >= 0x0B82 && c <= 0x0B83
            || c >= 0x0BBE && c <= 0x0BC2
            || c >= 0x0BC6 && c <= 0x0BC8
            || c >= 0x0BCA && c <= 0x0BCD
            || c == 0x0BD7
            || c >= 0x0C01 && c <= 0x0C03
            || c >= 0x0C3E && c <= 0x0C44
            || c >= 0x0C46 && c <= 0x0C48
            || c >= 0x0C4A && c <= 0x0C4D
            || c >= 0x0C55 && c <= 0x0C56
            || c >= 0x0C82 && c <= 0x0C83
            || c >= 0x0CBE && c <= 0x0CC4
            || c >= 0x0CC6 && c <= 0x0CC8
            || c >= 0x0CCA && c <= 0x0CCD
            || c >= 0x0CD5 && c <= 0x0CD6
            || c >= 0x0D02 && c <= 0x0D03
            || c >= 0x0D3E && c <= 0x0D43
            || c >= 0x0D46 && c <= 0x0D48
            || c >= 0x0D4A && c <= 0x0D4D
            || c == 0x0D57
            || c == 0x0E31
            || c >= 0x0E34 && c <= 0x0E3A
            || c >= 0x0E47 && c <= 0x0E4E
            || c == 0x0EB1
            || c >= 0x0EB4 && c <= 0x0EB9
            || c >= 0x0EBB && c <= 0x0EBC
            || c >= 0x0EC8 && c <= 0x0ECD
            || c >= 0x0F18 && c <= 0x0F19
            || c == 0x0F35
            || c == 0x0F37
            || c == 0x0F39
            || c == 0x0F3E
            || c == 0x0F3F
            || c >= 0x0F71 && c <= 0x0F84
            || c >= 0x0F86 && c <= 0x0F8B
            || c >= 0x0F90 && c <= 0x0F95
            || c == 0x0F97
            || c >= 0x0F99 && c <= 0x0FAD
            || c >= 0x0FB1 && c <= 0x0FB7
            || c == 0x0FB9
            || c >= 0x20D0 && c <= 0x20DC
            || c == 0x20E1
            || c >= 0x302A && c <= 0x302F
            || c == 0x3099
            || c == 0x309A
            || c == 0x00B7
            || c == 0x02D0
            || c == 0x02D1
            || c == 0x0387
            || c == 0x0640
            || c == 0x0E46
            || c == 0x0EC6
            || c == 0x3005
            || c >= 0x3031 && c <= 0x3035
            || c >= 0x309D && c <= 0x309E
            || c >= 0x30FC && c <= 0x30FE;
    };

    Utilities.coalesceText = function (n) {
        for (var m = n.firstChild; m != null; m = m.nextSibling) {
            if (m.nodeType == 3 /*Node.TEXT_NODE*/ || m.nodeType == 4 /*Node.CDATA_SECTION_NODE*/) {
                var s = m.nodeValue;
                var first = m;
                m = m.nextSibling;
                while (m != null && (m.nodeType == 3 /*Node.TEXT_NODE*/ || m.nodeType == 4 /*Node.CDATA_SECTION_NODE*/)) {
                    s += m.nodeValue;
                    var del = m;
                    m = m.nextSibling;
                    del.parentNode.removeChild(del);
                }
                if (first.nodeType == 4 /*Node.CDATA_SECTION_NODE*/) {
                    var p = first.parentNode;
                    if (first.nextSibling == null) {
                        p.removeChild(first);
                        p.appendChild(p.ownerDocument.createTextNode(s));
                    } else {
                        var next = first.nextSibling;
                        p.removeChild(first);
                        p.insertBefore(p.ownerDocument.createTextNode(s), next);
                    }
                } else {
                    first.nodeValue = s;
                }
                if (m == null) {
                    break;
                }
            } else if (m.nodeType == 1 /*Node.ELEMENT_NODE*/) {
                Utilities.coalesceText(m);
            }
        }
    };

    Utilities.instance_of = function (o, c) {
        while (o != null) {
            if (o.constructor === c) {
                return true;
            }
            if (o === Object) {
                return false;
            }
            o = o.constructor.superclass;
        }
        return false;
    };

    Utilities.getElementById = function (n, id) {
        // Note that this does not check the DTD to check for actual
        // attributes of type ID, so this may be a bit wrong.
        if (n.nodeType == 1 /*Node.ELEMENT_NODE*/) {
            if (n.getAttribute("id") == id
                || n.getAttributeNS(null, "id") == id) {
                return n;
            }
        }
        for (var m = n.firstChild; m != null; m = m.nextSibling) {
            var res = Utilities.getElementById(m, id);
            if (res != null) {
                return res;
            }
        }
        return null;
    };

    // XPathException ////////////////////////////////////////////////////////////

    var XPathException = (function () {
        function getMessage(code, exception) {
            var msg = exception ? ": " + exception.toString() : "";
            switch (code) {
                case XPathException.INVALID_EXPRESSION_ERR:
                    return "Invalid expression" + msg;
                case XPathException.TYPE_ERR:
                    return "Type error" + msg;
            }
            return null;
        }

        function XPathException(code, error, message) {
            var err = Error.call(this, getMessage(code, error) || message);

            err.code = code;
            err.exception = error;

            return err;
        }

        XPathException.prototype = Object.create(Error.prototype);
        XPathException.prototype.constructor = XPathException;
        XPathException.superclass = Error;

        XPathException.prototype.toString = function () {
            return this.message;
        };

        XPathException.fromMessage = function (message, error) {
            return new XPathException(null, error, message);
        };

        XPathException.INVALID_EXPRESSION_ERR = 51;
        XPathException.TYPE_ERR = 52;

        return XPathException;
    })();

    // XPathExpression ///////////////////////////////////////////////////////////

    XPathExpression.prototype = {};
    XPathExpression.prototype.constructor = XPathExpression;
    XPathExpression.superclass = Object.prototype;

    function XPathExpression(e, r, p) {
        this.xpath = p.parse(e);
        this.context = new XPathContext();
        this.context.namespaceResolver = new XPathNSResolverWrapper(r);
    }

    XPathExpression.getOwnerDocument = function (n) {
        return n.nodeType === 9 /*Node.DOCUMENT_NODE*/ ? n : n.ownerDocument;
    }

    XPathExpression.detectHtmlDom = function (n) {
        if (!n) { return false; }

        var doc = XPathExpression.getOwnerDocument(n);

        try {
            return doc.implementation.hasFeature("HTML", "2.0");
        } catch (e) {
            return true;
        }
    }

    XPathExpression.prototype.evaluate = function (n, t, res) {
        this.context.expressionContextNode = n;
        // backward compatibility - no reliable way to detect whether the DOM is HTML, but
        // this library has been using this method up until now, so we will continue to use it
        // ONLY when using an XPathExpression
        this.context.caseInsensitive = XPathExpression.detectHtmlDom(n);

        var result = this.xpath.evaluate(this.context);
        return new XPathResult(result, t);
    }

    // XPathNSResolverWrapper ////////////////////////////////////////////////////

    XPathNSResolverWrapper.prototype = {};
    XPathNSResolverWrapper.prototype.constructor = XPathNSResolverWrapper;
    XPathNSResolverWrapper.superclass = Object.prototype;

    function XPathNSResolverWrapper(r) {
        this.xpathNSResolver = r;
    }

    XPathNSResolverWrapper.prototype.getNamespace = function (prefix, n) {
        if (this.xpathNSResolver == null) {
            return null;
        }
        return this.xpathNSResolver.lookupNamespaceURI(prefix);
    };

    // NodeXPathNSResolver ///////////////////////////////////////////////////////

    NodeXPathNSResolver.prototype = {};
    NodeXPathNSResolver.prototype.constructor = NodeXPathNSResolver;
    NodeXPathNSResolver.superclass = Object.prototype;

    function NodeXPathNSResolver(n) {
        this.node = n;
        this.namespaceResolver = new NamespaceResolver();
    }

    NodeXPathNSResolver.prototype.lookupNamespaceURI = function (prefix) {
        return this.namespaceResolver.getNamespace(prefix, this.node);
    };

    // XPathResult ///////////////////////////////////////////////////////////////

    XPathResult.prototype = {};
    XPathResult.prototype.constructor = XPathResult;
    XPathResult.superclass = Object.prototype;

    function XPathResult(v, t) {
        if (t == XPathResult.ANY_TYPE) {
            if (v.constructor === XString) {
                t = XPathResult.STRING_TYPE;
            } else if (v.constructor === XNumber) {
                t = XPathResult.NUMBER_TYPE;
            } else if (v.constructor === XBoolean) {
                t = XPathResult.BOOLEAN_TYPE;
            } else if (v.constructor === XNodeSet) {
                t = XPathResult.UNORDERED_NODE_ITERATOR_TYPE;
            }
        }
        this.resultType = t;
        switch (t) {
            case XPathResult.NUMBER_TYPE:
                this.numberValue = v.numberValue();
                return;
            case XPathResult.STRING_TYPE:
                this.stringValue = v.stringValue();
                return;
            case XPathResult.BOOLEAN_TYPE:
                this.booleanValue = v.booleanValue();
                return;
            case XPathResult.ANY_UNORDERED_NODE_TYPE:
            case XPathResult.FIRST_ORDERED_NODE_TYPE:
                if (v.constructor === XNodeSet) {
                    this.singleNodeValue = v.first();
                    return;
                }
                break;
            case XPathResult.UNORDERED_NODE_ITERATOR_TYPE:
            case XPathResult.ORDERED_NODE_ITERATOR_TYPE:
                if (v.constructor === XNodeSet) {
                    this.invalidIteratorState = false;
                    this.nodes = v.toArray();
                    this.iteratorIndex = 0;
                    return;
                }
                break;
            case XPathResult.UNORDERED_NODE_SNAPSHOT_TYPE:
            case XPathResult.ORDERED_NODE_SNAPSHOT_TYPE:
                if (v.constructor === XNodeSet) {
                    this.nodes = v.toArray();
                    this.snapshotLength = this.nodes.length;
                    return;
                }
                break;
        }
        throw new XPathException(XPathException.TYPE_ERR);
    };

    XPathResult.prototype.iterateNext = function () {
        if (this.resultType != XPathResult.UNORDERED_NODE_ITERATOR_TYPE
            && this.resultType != XPathResult.ORDERED_NODE_ITERATOR_TYPE) {
            throw new XPathException(XPathException.TYPE_ERR);
        }
        return this.nodes[this.iteratorIndex++];
    };

    XPathResult.prototype.snapshotItem = function (i) {
        if (this.resultType != XPathResult.UNORDERED_NODE_SNAPSHOT_TYPE
            && this.resultType != XPathResult.ORDERED_NODE_SNAPSHOT_TYPE) {
            throw new XPathException(XPathException.TYPE_ERR);
        }
        return this.nodes[i];
    };

    XPathResult.ANY_TYPE = 0;
    XPathResult.NUMBER_TYPE = 1;
    XPathResult.STRING_TYPE = 2;
    XPathResult.BOOLEAN_TYPE = 3;
    XPathResult.UNORDERED_NODE_ITERATOR_TYPE = 4;
    XPathResult.ORDERED_NODE_ITERATOR_TYPE = 5;
    XPathResult.UNORDERED_NODE_SNAPSHOT_TYPE = 6;
    XPathResult.ORDERED_NODE_SNAPSHOT_TYPE = 7;
    XPathResult.ANY_UNORDERED_NODE_TYPE = 8;
    XPathResult.FIRST_ORDERED_NODE_TYPE = 9;

    // DOM 3 XPath support ///////////////////////////////////////////////////////

    function installDOM3XPathSupport(doc, p) {
        doc.createExpression = function (e, r) {
            try {
                return new XPathExpression(e, r, p);
            } catch (e) {
                throw new XPathException(XPathException.INVALID_EXPRESSION_ERR, e);
            }
        };
        doc.createNSResolver = function (n) {
            return new NodeXPathNSResolver(n);
        };
        doc.evaluate = function (e, cn, r, t, res) {
            if (t < 0 || t > 9) {
                throw { code: 0, toString: function () { return "Request type not supported"; } };
            }
            return doc.createExpression(e, r, p).evaluate(cn, t, res);
        };
    };

    // ---------------------------------------------------------------------------

    // Install DOM 3 XPath support for the current document.
    try {
        var shouldInstall = true;
        try {
            if (document.implementation
                && document.implementation.hasFeature
                && document.implementation.hasFeature("XPath", null)) {
                shouldInstall = false;
            }
        } catch (e) {
        }
        if (shouldInstall) {
            installDOM3XPathSupport(document, new XPathParser());
        }
    } catch (e) {
    }

    // ---------------------------------------------------------------------------
    // exports for node.js

    installDOM3XPathSupport(exports, new XPathParser());

    (function () {
        var parser = new XPathParser();

        var defaultNSResolver = new NamespaceResolver();
        var defaultFunctionResolver = new FunctionResolver();
        var defaultVariableResolver = new VariableResolver();

        function makeNSResolverFromFunction(func) {
            return {
                getNamespace: function (prefix, node) {
                    var ns = func(prefix, node);

                    return ns || defaultNSResolver.getNamespace(prefix, node);
                }
            };
        }

        function makeNSResolverFromObject(obj) {
            return makeNSResolverFromFunction(obj.getNamespace.bind(obj));
        }

        function makeNSResolverFromMap(map) {
            return makeNSResolverFromFunction(function (prefix) {
                return map[prefix];
            });
        }

        function makeNSResolver(resolver) {
            if (resolver && typeof resolver.getNamespace === "function") {
                return makeNSResolverFromObject(resolver);
            }

            if (typeof resolver === "function") {
                return makeNSResolverFromFunction(resolver);
            }

            // assume prefix -> uri mapping
            if (typeof resolver === "object") {
                return makeNSResolverFromMap(resolver);
            }

            return defaultNSResolver;
        }

        /** Converts native JavaScript types to their XPath library equivalent */
        function convertValue(value) {
            if (value === null ||
                typeof value === "undefined" ||
                value instanceof XString ||
                value instanceof XBoolean ||
                value instanceof XNumber ||
                value instanceof XNodeSet) {
                return value;
            }

            switch (typeof value) {
                case "string": return new XString(value);
                case "boolean": return new XBoolean(value);
                case "number": return new XNumber(value);
            }

            // assume node(s)
            var ns = new XNodeSet();
            ns.addArray([].concat(value));
            return ns;
        }

        function makeEvaluator(func) {
            return function (context) {
                var args = Array.prototype.slice.call(arguments, 1).map(function (arg) {
                    return arg.evaluate(context);
                });
                var result = func.apply(this, [].concat(context, args));
                return convertValue(result);
            };
        }

        function makeFunctionResolverFromFunction(func) {
            return {
                getFunction: function (name, namespace) {
                    var found = func(name, namespace);
                    if (found) {
                        return makeEvaluator(found);
                    }
                    return defaultFunctionResolver.getFunction(name, namespace);
                }
            };
        }

        function makeFunctionResolverFromObject(obj) {
            return makeFunctionResolverFromFunction(obj.getFunction.bind(obj));
        }

        function makeFunctionResolverFromMap(map) {
            return makeFunctionResolverFromFunction(function (name) {
                return map[name];
            });
        }

        function makeFunctionResolver(resolver) {
            if (resolver && typeof resolver.getFunction === "function") {
                return makeFunctionResolverFromObject(resolver);
            }

            if (typeof resolver === "function") {
                return makeFunctionResolverFromFunction(resolver);
            }

            // assume map
            if (typeof resolver === "object") {
                return makeFunctionResolverFromMap(resolver);
            }

            return defaultFunctionResolver;
        }

        function makeVariableResolverFromFunction(func) {
            return {
                getVariable: function (name, namespace) {
                    var value = func(name, namespace);
                    return convertValue(value);
                }
            };
        }

        function makeVariableResolver(resolver) {
            if (resolver) {
                if (typeof resolver.getVariable === "function") {
                    return makeVariableResolverFromFunction(resolver.getVariable.bind(resolver));
                }

                if (typeof resolver === "function") {
                    return makeVariableResolverFromFunction(resolver);
                }

                // assume map
                if (typeof resolver === "object") {
                    return makeVariableResolverFromFunction(function (name) {
                        return resolver[name];
                    });
                }
            }

            return defaultVariableResolver;
        }

        function copyIfPresent(prop, dest, source) {
            if (prop in source) { dest[prop] = source[prop]; }
        }

        function makeContext(options) {
            var context = new XPathContext();

            if (options) {
                context.namespaceResolver = makeNSResolver(options.namespaces);
                context.functionResolver = makeFunctionResolver(options.functions);
                context.variableResolver = makeVariableResolver(options.variables);
                context.expressionContextNode = options.node;
                copyIfPresent('allowAnyNamespaceForNoPrefix', context, options);
                copyIfPresent('isHtml', context, options);
            } else {
                context.namespaceResolver = defaultNSResolver;
            }

            return context;
        }

        function evaluate(parsedExpression, options) {
            var context = makeContext(options);

            return parsedExpression.evaluate(context);
        }

        var evaluatorPrototype = {
            evaluate: function (options) {
                return evaluate(this.expression, options);
            }

            , evaluateNumber: function (options) {
                return this.evaluate(options).numberValue();
            }

            , evaluateString: function (options) {
                return this.evaluate(options).stringValue();
            }

            , evaluateBoolean: function (options) {
                return this.evaluate(options).booleanValue();
            }

            , evaluateNodeSet: function (options) {
                return this.evaluate(options).nodeset();
            }

            , select: function (options) {
                return this.evaluateNodeSet(options).toArray()
            }

            , select1: function (options) {
                return this.select(options)[0];
            }
        };

        function parse(xpath) {
            var parsed = parser.parse(xpath);

            return Object.create(evaluatorPrototype, {
                expression: {
                    value: parsed
                }
            });
        }

        exports.parse = parse;
    })();

    assign(
        exports,
        {
            XPath,
            XPathParser,
            XPathResult,

            Step,
            PathExpr,
            NodeTest,
            LocationPath,

            OrOperation,
            AndOperation,

            BarOperation,

            EqualsOperation,
            NotEqualOperation,
            LessThanOperation,
            GreaterThanOperation,
            LessThanOrEqualOperation,
            GreaterThanOrEqualOperation,

            PlusOperation,
            MinusOperation,
            MultiplyOperation,
            DivOperation,
            ModOperation,
            UnaryMinusOperation,

            FunctionCall,
            VariableReference,

            XPathContext,

            XNodeSet,
            XBoolean,
            XString,
            XNumber,

            NamespaceResolver,
            FunctionResolver,
            VariableResolver,

            Utilities,
        }
    );

    // helper
    exports.select = function (e, doc, single) {
        return exports.selectWithResolver(e, doc, null, single);
    };

    exports.useNamespaces = function (mappings) {
        var resolver = {
            mappings: mappings || {},
            lookupNamespaceURI: function (prefix) {
                return this.mappings[prefix];
            }
        };

        return function (e, doc, single) {
            return exports.selectWithResolver(e, doc, resolver, single);
        };
    };

    exports.selectWithResolver = function (e, doc, resolver, single) {
        var expression = new XPathExpression(e, resolver, new XPathParser());
        var type = XPathResult.ANY_TYPE;

        var result = expression.evaluate(doc, type, null);

        if (result.resultType == XPathResult.STRING_TYPE) {
            result = result.stringValue;
        }
        else if (result.resultType == XPathResult.NUMBER_TYPE) {
            result = result.numberValue;
        }
        else if (result.resultType == XPathResult.BOOLEAN_TYPE) {
            result = result.booleanValue;
        }
        else {
            result = result.nodes;
            if (single) {
                result = result[0];
            }
        }

        return result;
    };

    exports.select1 = function (e, doc) {
        return exports.select(e, doc, true);
    };

    // end non-node wrapper
})(xpath);


/***/ }),

/***/ 5670:
/***/ ((module) => {

function webpackEmptyContext(req) {
	var e = new Error("Cannot find module '" + req + "'");
	e.code = 'MODULE_NOT_FOUND';
	throw e;
}
webpackEmptyContext.keys = () => ([]);
webpackEmptyContext.resolve = webpackEmptyContext;
webpackEmptyContext.id = 5670;
module.exports = webpackEmptyContext;

/***/ }),

/***/ 9167:
/***/ ((module) => {

function webpackEmptyContext(req) {
	var e = new Error("Cannot find module '" + req + "'");
	e.code = 'MODULE_NOT_FOUND';
	throw e;
}
webpackEmptyContext.keys = () => ([]);
webpackEmptyContext.resolve = webpackEmptyContext;
webpackEmptyContext.id = 9167;
module.exports = webpackEmptyContext;

/***/ }),

/***/ 4907:
/***/ ((module) => {

function webpackEmptyContext(req) {
	var e = new Error("Cannot find module '" + req + "'");
	e.code = 'MODULE_NOT_FOUND';
	throw e;
}
webpackEmptyContext.keys = () => ([]);
webpackEmptyContext.resolve = webpackEmptyContext;
webpackEmptyContext.id = 4907;
module.exports = webpackEmptyContext;

/***/ }),

/***/ 9491:
/***/ ((module) => {

"use strict";
module.exports = require("assert");

/***/ }),

/***/ 6113:
/***/ ((module) => {

"use strict";
module.exports = require("crypto");

/***/ }),

/***/ 2361:
/***/ ((module) => {

"use strict";
module.exports = require("events");

/***/ }),

/***/ 7147:
/***/ ((module) => {

"use strict";
module.exports = require("fs");

/***/ }),

/***/ 3685:
/***/ ((module) => {

"use strict";
module.exports = require("http");

/***/ }),

/***/ 5687:
/***/ ((module) => {

"use strict";
module.exports = require("https");

/***/ }),

/***/ 1808:
/***/ ((module) => {

"use strict";
module.exports = require("net");

/***/ }),

/***/ 2037:
/***/ ((module) => {

"use strict";
module.exports = require("os");

/***/ }),

/***/ 1017:
/***/ ((module) => {

"use strict";
module.exports = require("path");

/***/ }),

/***/ 7282:
/***/ ((module) => {

"use strict";
module.exports = require("process");

/***/ }),

/***/ 4404:
/***/ ((module) => {

"use strict";
module.exports = require("tls");

/***/ }),

/***/ 3837:
/***/ ((module) => {

"use strict";
module.exports = require("util");

/***/ }),

/***/ 6144:
/***/ ((module) => {

"use strict";
module.exports = require("vm");

/***/ }),

/***/ 6658:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const {
  applyExtends,
  cjsPlatformShim,
  Parser,
  processArgv,
} = __nccwpck_require__(9562);

module.exports = {
  applyExtends: (config, cwd, mergeExtends) => {
    return applyExtends(config, cwd, mergeExtends, cjsPlatformShim);
  },
  hideBin: processArgv.hideBin,
  Parser,
};


/***/ }),

/***/ 7059:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const align = {
    right: alignRight,
    center: alignCenter
};
const top = 0;
const right = 1;
const bottom = 2;
const left = 3;
class UI {
    constructor(opts) {
        var _a;
        this.width = opts.width;
        this.wrap = (_a = opts.wrap) !== null && _a !== void 0 ? _a : true;
        this.rows = [];
    }
    span(...args) {
        const cols = this.div(...args);
        cols.span = true;
    }
    resetOutput() {
        this.rows = [];
    }
    div(...args) {
        if (args.length === 0) {
            this.div('');
        }
        if (this.wrap && this.shouldApplyLayoutDSL(...args) && typeof args[0] === 'string') {
            return this.applyLayoutDSL(args[0]);
        }
        const cols = args.map(arg => {
            if (typeof arg === 'string') {
                return this.colFromString(arg);
            }
            return arg;
        });
        this.rows.push(cols);
        return cols;
    }
    shouldApplyLayoutDSL(...args) {
        return args.length === 1 && typeof args[0] === 'string' &&
            /[\t\n]/.test(args[0]);
    }
    applyLayoutDSL(str) {
        const rows = str.split('\n').map(row => row.split('\t'));
        let leftColumnWidth = 0;
        // simple heuristic for layout, make sure the
        // second column lines up along the left-hand.
        // don't allow the first column to take up more
        // than 50% of the screen.
        rows.forEach(columns => {
            if (columns.length > 1 && mixin.stringWidth(columns[0]) > leftColumnWidth) {
                leftColumnWidth = Math.min(Math.floor(this.width * 0.5), mixin.stringWidth(columns[0]));
            }
        });
        // generate a table:
        //  replacing ' ' with padding calculations.
        //  using the algorithmically generated width.
        rows.forEach(columns => {
            this.div(...columns.map((r, i) => {
                return {
                    text: r.trim(),
                    padding: this.measurePadding(r),
                    width: (i === 0 && columns.length > 1) ? leftColumnWidth : undefined
                };
            }));
        });
        return this.rows[this.rows.length - 1];
    }
    colFromString(text) {
        return {
            text,
            padding: this.measurePadding(text)
        };
    }
    measurePadding(str) {
        // measure padding without ansi escape codes
        const noAnsi = mixin.stripAnsi(str);
        return [0, noAnsi.match(/\s*$/)[0].length, 0, noAnsi.match(/^\s*/)[0].length];
    }
    toString() {
        const lines = [];
        this.rows.forEach(row => {
            this.rowToString(row, lines);
        });
        // don't display any lines with the
        // hidden flag set.
        return lines
            .filter(line => !line.hidden)
            .map(line => line.text)
            .join('\n');
    }
    rowToString(row, lines) {
        this.rasterize(row).forEach((rrow, r) => {
            let str = '';
            rrow.forEach((col, c) => {
                const { width } = row[c]; // the width with padding.
                const wrapWidth = this.negatePadding(row[c]); // the width without padding.
                let ts = col; // temporary string used during alignment/padding.
                if (wrapWidth > mixin.stringWidth(col)) {
                    ts += ' '.repeat(wrapWidth - mixin.stringWidth(col));
                }
                // align the string within its column.
                if (row[c].align && row[c].align !== 'left' && this.wrap) {
                    const fn = align[row[c].align];
                    ts = fn(ts, wrapWidth);
                    if (mixin.stringWidth(ts) < wrapWidth) {
                        ts += ' '.repeat((width || 0) - mixin.stringWidth(ts) - 1);
                    }
                }
                // apply border and padding to string.
                const padding = row[c].padding || [0, 0, 0, 0];
                if (padding[left]) {
                    str += ' '.repeat(padding[left]);
                }
                str += addBorder(row[c], ts, '| ');
                str += ts;
                str += addBorder(row[c], ts, ' |');
                if (padding[right]) {
                    str += ' '.repeat(padding[right]);
                }
                // if prior row is span, try to render the
                // current row on the prior line.
                if (r === 0 && lines.length > 0) {
                    str = this.renderInline(str, lines[lines.length - 1]);
                }
            });
            // remove trailing whitespace.
            lines.push({
                text: str.replace(/ +$/, ''),
                span: row.span
            });
        });
        return lines;
    }
    // if the full 'source' can render in
    // the target line, do so.
    renderInline(source, previousLine) {
        const match = source.match(/^ */);
        const leadingWhitespace = match ? match[0].length : 0;
        const target = previousLine.text;
        const targetTextWidth = mixin.stringWidth(target.trimRight());
        if (!previousLine.span) {
            return source;
        }
        // if we're not applying wrapping logic,
        // just always append to the span.
        if (!this.wrap) {
            previousLine.hidden = true;
            return target + source;
        }
        if (leadingWhitespace < targetTextWidth) {
            return source;
        }
        previousLine.hidden = true;
        return target.trimRight() + ' '.repeat(leadingWhitespace - targetTextWidth) + source.trimLeft();
    }
    rasterize(row) {
        const rrows = [];
        const widths = this.columnWidths(row);
        let wrapped;
        // word wrap all columns, and create
        // a data-structure that is easy to rasterize.
        row.forEach((col, c) => {
            // leave room for left and right padding.
            col.width = widths[c];
            if (this.wrap) {
                wrapped = mixin.wrap(col.text, this.negatePadding(col), { hard: true }).split('\n');
            }
            else {
                wrapped = col.text.split('\n');
            }
            if (col.border) {
                wrapped.unshift('.' + '-'.repeat(this.negatePadding(col) + 2) + '.');
                wrapped.push("'" + '-'.repeat(this.negatePadding(col) + 2) + "'");
            }
            // add top and bottom padding.
            if (col.padding) {
                wrapped.unshift(...new Array(col.padding[top] || 0).fill(''));
                wrapped.push(...new Array(col.padding[bottom] || 0).fill(''));
            }
            wrapped.forEach((str, r) => {
                if (!rrows[r]) {
                    rrows.push([]);
                }
                const rrow = rrows[r];
                for (let i = 0; i < c; i++) {
                    if (rrow[i] === undefined) {
                        rrow.push('');
                    }
                }
                rrow.push(str);
            });
        });
        return rrows;
    }
    negatePadding(col) {
        let wrapWidth = col.width || 0;
        if (col.padding) {
            wrapWidth -= (col.padding[left] || 0) + (col.padding[right] || 0);
        }
        if (col.border) {
            wrapWidth -= 4;
        }
        return wrapWidth;
    }
    columnWidths(row) {
        if (!this.wrap) {
            return row.map(col => {
                return col.width || mixin.stringWidth(col.text);
            });
        }
        let unset = row.length;
        let remainingWidth = this.width;
        // column widths can be set in config.
        const widths = row.map(col => {
            if (col.width) {
                unset--;
                remainingWidth -= col.width;
                return col.width;
            }
            return undefined;
        });
        // any unset widths should be calculated.
        const unsetWidth = unset ? Math.floor(remainingWidth / unset) : 0;
        return widths.map((w, i) => {
            if (w === undefined) {
                return Math.max(unsetWidth, _minWidth(row[i]));
            }
            return w;
        });
    }
}
function addBorder(col, ts, style) {
    if (col.border) {
        if (/[.']-+[.']/.test(ts)) {
            return '';
        }
        if (ts.trim().length !== 0) {
            return style;
        }
        return '  ';
    }
    return '';
}
// calculates the minimum width of
// a column, based on padding preferences.
function _minWidth(col) {
    const padding = col.padding || [];
    const minWidth = 1 + (padding[left] || 0) + (padding[right] || 0);
    if (col.border) {
        return minWidth + 4;
    }
    return minWidth;
}
function getWindowWidth() {
    /* istanbul ignore next: depends on terminal */
    if (typeof process === 'object' && process.stdout && process.stdout.columns) {
        return process.stdout.columns;
    }
    return 80;
}
function alignRight(str, width) {
    str = str.trim();
    const strWidth = mixin.stringWidth(str);
    if (strWidth < width) {
        return ' '.repeat(width - strWidth) + str;
    }
    return str;
}
function alignCenter(str, width) {
    str = str.trim();
    const strWidth = mixin.stringWidth(str);
    /* istanbul ignore next */
    if (strWidth >= width) {
        return str;
    }
    return ' '.repeat((width - strWidth) >> 1) + str;
}
let mixin;
function cliui(opts, _mixin) {
    mixin = _mixin;
    return new UI({
        width: (opts === null || opts === void 0 ? void 0 : opts.width) || getWindowWidth(),
        wrap: opts === null || opts === void 0 ? void 0 : opts.wrap
    });
}

// Bootstrap cliui with CommonJS dependencies:
const stringWidth = __nccwpck_require__(2577);
const stripAnsi = __nccwpck_require__(5591);
const wrap = __nccwpck_require__(9824);
function ui(opts) {
    return cliui(opts, {
        stringWidth,
        stripAnsi,
        wrap
    });
}

module.exports = ui;


/***/ }),

/***/ 4697:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({ value: true }));

var vm = __nccwpck_require__(6144);

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var vm__default = /*#__PURE__*/_interopDefaultLegacy(vm);

const {
  hasOwnProperty: hasOwnProp
} = Object.prototype;
/**
 * @typedef {null|boolean|number|string|PlainObject|GenericArray} JSONObject
 */

/**
 * @typedef {any} AnyItem
 */

/**
 * @typedef {any} AnyResult
 */

/**
 * Copies array and then pushes item into it.
 * @param {GenericArray} arr Array to copy and into which to push
 * @param {AnyItem} item Array item to add (to end)
 * @returns {GenericArray} Copy of the original array
 */

function push(arr, item) {
  arr = arr.slice();
  arr.push(item);
  return arr;
}
/**
 * Copies array and then unshifts item into it.
 * @param {AnyItem} item Array item to add (to beginning)
 * @param {GenericArray} arr Array to copy and into which to unshift
 * @returns {GenericArray} Copy of the original array
 */


function unshift(item, arr) {
  arr = arr.slice();
  arr.unshift(item);
  return arr;
}
/**
 * Caught when JSONPath is used without `new` but rethrown if with `new`
 * @extends Error
 */


class NewError extends Error {
  /**
   * @param {AnyResult} value The evaluated scalar value
   */
  constructor(value) {
    super('JSONPath should not be called with "new" (it prevents return ' + 'of (unwrapped) scalar values)');
    this.avoidNew = true;
    this.value = value;
    this.name = 'NewError';
  }

}
/**
* @typedef {PlainObject} ReturnObject
* @property {string} path
* @property {JSONObject} value
* @property {PlainObject|GenericArray} parent
* @property {string} parentProperty
*/

/**
* @callback JSONPathCallback
* @param {string|PlainObject} preferredOutput
* @param {"value"|"property"} type
* @param {ReturnObject} fullRetObj
* @returns {void}
*/

/**
* @callback OtherTypeCallback
* @param {JSONObject} val
* @param {string} path
* @param {PlainObject|GenericArray} parent
* @param {string} parentPropName
* @returns {boolean}
*/

/* eslint-disable max-len -- Can make multiline type after https://github.com/syavorsky/comment-parser/issues/109 */

/**
 * @typedef {PlainObject} JSONPathOptions
 * @property {JSON} json
 * @property {string|string[]} path
 * @property {"value"|"path"|"pointer"|"parent"|"parentProperty"|"all"} [resultType="value"]
 * @property {boolean} [flatten=false]
 * @property {boolean} [wrap=true]
 * @property {PlainObject} [sandbox={}]
 * @property {boolean} [preventEval=false]
 * @property {PlainObject|GenericArray|null} [parent=null]
 * @property {string|null} [parentProperty=null]
 * @property {JSONPathCallback} [callback]
 * @property {OtherTypeCallback} [otherTypeCallback] Defaults to
 *   function which throws on encountering `@other`
 * @property {boolean} [autostart=true]
 */

/* eslint-enable max-len -- Can make multiline type after https://github.com/syavorsky/comment-parser/issues/109 */

/**
 * @param {string|JSONPathOptions} opts If a string, will be treated as `expr`
 * @param {string} [expr] JSON path to evaluate
 * @param {JSON} [obj] JSON object to evaluate against
 * @param {JSONPathCallback} [callback] Passed 3 arguments: 1) desired payload
 *     per `resultType`, 2) `"value"|"property"`, 3) Full returned object with
 *     all payloads
 * @param {OtherTypeCallback} [otherTypeCallback] If `@other()` is at the end
 *   of one's query, this will be invoked with the value of the item, its
 *   path, its parent, and its parent's property name, and it should return
 *   a boolean indicating whether the supplied value belongs to the "other"
 *   type or not (or it may handle transformations and return `false`).
 * @returns {JSONPath}
 * @class
 */


function JSONPath(opts, expr, obj, callback, otherTypeCallback) {
  // eslint-disable-next-line no-restricted-syntax
  if (!(this instanceof JSONPath)) {
    try {
      return new JSONPath(opts, expr, obj, callback, otherTypeCallback);
    } catch (e) {
      if (!e.avoidNew) {
        throw e;
      }

      return e.value;
    }
  }

  if (typeof opts === 'string') {
    otherTypeCallback = callback;
    callback = obj;
    obj = expr;
    expr = opts;
    opts = null;
  }

  const optObj = opts && typeof opts === 'object';
  opts = opts || {};
  this.json = opts.json || obj;
  this.path = opts.path || expr;
  this.resultType = opts.resultType || 'value';
  this.flatten = opts.flatten || false;
  this.wrap = hasOwnProp.call(opts, 'wrap') ? opts.wrap : true;
  this.sandbox = opts.sandbox || {};
  this.preventEval = opts.preventEval || false;
  this.parent = opts.parent || null;
  this.parentProperty = opts.parentProperty || null;
  this.callback = opts.callback || callback || null;

  this.otherTypeCallback = opts.otherTypeCallback || otherTypeCallback || function () {
    throw new TypeError('You must supply an otherTypeCallback callback option ' + 'with the @other() operator.');
  };

  if (opts.autostart !== false) {
    const args = {
      path: optObj ? opts.path : expr
    };

    if (!optObj) {
      args.json = obj;
    } else if ('json' in opts) {
      args.json = opts.json;
    }

    const ret = this.evaluate(args);

    if (!ret || typeof ret !== 'object') {
      throw new NewError(ret);
    }

    return ret;
  }
} // PUBLIC METHODS


JSONPath.prototype.evaluate = function (expr, json, callback, otherTypeCallback) {
  let currParent = this.parent,
      currParentProperty = this.parentProperty;
  let {
    flatten,
    wrap
  } = this;
  this.currResultType = this.resultType;
  this.currPreventEval = this.preventEval;
  this.currSandbox = this.sandbox;
  callback = callback || this.callback;
  this.currOtherTypeCallback = otherTypeCallback || this.otherTypeCallback;
  json = json || this.json;
  expr = expr || this.path;

  if (expr && typeof expr === 'object' && !Array.isArray(expr)) {
    if (!expr.path && expr.path !== '') {
      throw new TypeError('You must supply a "path" property when providing an object ' + 'argument to JSONPath.evaluate().');
    }

    if (!hasOwnProp.call(expr, 'json')) {
      throw new TypeError('You must supply a "json" property when providing an object ' + 'argument to JSONPath.evaluate().');
    }

    ({
      json
    } = expr);
    flatten = hasOwnProp.call(expr, 'flatten') ? expr.flatten : flatten;
    this.currResultType = hasOwnProp.call(expr, 'resultType') ? expr.resultType : this.currResultType;
    this.currSandbox = hasOwnProp.call(expr, 'sandbox') ? expr.sandbox : this.currSandbox;
    wrap = hasOwnProp.call(expr, 'wrap') ? expr.wrap : wrap;
    this.currPreventEval = hasOwnProp.call(expr, 'preventEval') ? expr.preventEval : this.currPreventEval;
    callback = hasOwnProp.call(expr, 'callback') ? expr.callback : callback;
    this.currOtherTypeCallback = hasOwnProp.call(expr, 'otherTypeCallback') ? expr.otherTypeCallback : this.currOtherTypeCallback;
    currParent = hasOwnProp.call(expr, 'parent') ? expr.parent : currParent;
    currParentProperty = hasOwnProp.call(expr, 'parentProperty') ? expr.parentProperty : currParentProperty;
    expr = expr.path;
  }

  currParent = currParent || null;
  currParentProperty = currParentProperty || null;

  if (Array.isArray(expr)) {
    expr = JSONPath.toPathString(expr);
  }

  if (!expr && expr !== '' || !json) {
    return undefined;
  }

  const exprList = JSONPath.toPathArray(expr);

  if (exprList[0] === '$' && exprList.length > 1) {
    exprList.shift();
  }

  this._hasParentSelector = null;

  const result = this._trace(exprList, json, ['$'], currParent, currParentProperty, callback).filter(function (ea) {
    return ea && !ea.isParentSelector;
  });

  if (!result.length) {
    return wrap ? [] : undefined;
  }

  if (!wrap && result.length === 1 && !result[0].hasArrExpr) {
    return this._getPreferredOutput(result[0]);
  }

  return result.reduce((rslt, ea) => {
    const valOrPath = this._getPreferredOutput(ea);

    if (flatten && Array.isArray(valOrPath)) {
      rslt = rslt.concat(valOrPath);
    } else {
      rslt.push(valOrPath);
    }

    return rslt;
  }, []);
}; // PRIVATE METHODS


JSONPath.prototype._getPreferredOutput = function (ea) {
  const resultType = this.currResultType;

  switch (resultType) {
    case 'all':
      {
        const path = Array.isArray(ea.path) ? ea.path : JSONPath.toPathArray(ea.path);
        ea.pointer = JSONPath.toPointer(path);
        ea.path = typeof ea.path === 'string' ? ea.path : JSONPath.toPathString(ea.path);
        return ea;
      }

    case 'value':
    case 'parent':
    case 'parentProperty':
      return ea[resultType];

    case 'path':
      return JSONPath.toPathString(ea[resultType]);

    case 'pointer':
      return JSONPath.toPointer(ea.path);

    default:
      throw new TypeError('Unknown result type');
  }
};

JSONPath.prototype._handleCallback = function (fullRetObj, callback, type) {
  if (callback) {
    const preferredOutput = this._getPreferredOutput(fullRetObj);

    fullRetObj.path = typeof fullRetObj.path === 'string' ? fullRetObj.path : JSONPath.toPathString(fullRetObj.path); // eslint-disable-next-line n/callback-return

    callback(preferredOutput, type, fullRetObj);
  }
};
/**
 *
 * @param {string} expr
 * @param {JSONObject} val
 * @param {string} path
 * @param {PlainObject|GenericArray} parent
 * @param {string} parentPropName
 * @param {JSONPathCallback} callback
 * @param {boolean} hasArrExpr
 * @param {boolean} literalPriority
 * @returns {ReturnObject|ReturnObject[]}
 */


JSONPath.prototype._trace = function (expr, val, path, parent, parentPropName, callback, hasArrExpr, literalPriority) {
  // No expr to follow? return path and value as the result of
  //  this trace branch
  let retObj;

  if (!expr.length) {
    retObj = {
      path,
      value: val,
      parent,
      parentProperty: parentPropName,
      hasArrExpr
    };

    this._handleCallback(retObj, callback, 'value');

    return retObj;
  }

  const loc = expr[0],
        x = expr.slice(1); // We need to gather the return value of recursive trace calls in order to
  // do the parent sel computation.

  const ret = [];
  /**
   *
   * @param {ReturnObject|ReturnObject[]} elems
   * @returns {void}
   */

  function addRet(elems) {
    if (Array.isArray(elems)) {
      // This was causing excessive stack size in Node (with or
      //  without Babel) against our performance test:
      //  `ret.push(...elems);`
      elems.forEach(t => {
        ret.push(t);
      });
    } else {
      ret.push(elems);
    }
  }

  if ((typeof loc !== 'string' || literalPriority) && val && hasOwnProp.call(val, loc)) {
    // simple case--directly follow property
    addRet(this._trace(x, val[loc], push(path, loc), val, loc, callback, hasArrExpr)); // eslint-disable-next-line unicorn/prefer-switch -- Part of larger `if`
  } else if (loc === '*') {
    // all child properties
    this._walk(val, m => {
      addRet(this._trace(x, val[m], push(path, m), val, m, callback, true, true));
    });
  } else if (loc === '..') {
    // all descendent parent properties
    // Check remaining expression with val's immediate children
    addRet(this._trace(x, val, path, parent, parentPropName, callback, hasArrExpr));

    this._walk(val, m => {
      // We don't join m and x here because we only want parents,
      //   not scalar values
      if (typeof val[m] === 'object') {
        // Keep going with recursive descent on val's
        //   object children
        addRet(this._trace(expr.slice(), val[m], push(path, m), val, m, callback, true));
      }
    }); // The parent sel computation is handled in the frame above using the
    // ancestor object of val

  } else if (loc === '^') {
    // This is not a final endpoint, so we do not invoke the callback here
    this._hasParentSelector = true;
    return {
      path: path.slice(0, -1),
      expr: x,
      isParentSelector: true
    };
  } else if (loc === '~') {
    // property name
    retObj = {
      path: push(path, loc),
      value: parentPropName,
      parent,
      parentProperty: null
    };

    this._handleCallback(retObj, callback, 'property');

    return retObj;
  } else if (loc === '$') {
    // root only
    addRet(this._trace(x, val, path, null, null, callback, hasArrExpr));
  } else if (/^(-?\d*):(-?\d*):?(\d*)$/u.test(loc)) {
    // [start:end:step]  Python slice syntax
    addRet(this._slice(loc, x, val, path, parent, parentPropName, callback));
  } else if (loc.indexOf('?(') === 0) {
    // [?(expr)] (filtering)
    if (this.currPreventEval) {
      throw new Error('Eval [?(expr)] prevented in JSONPath expression.');
    }

    const safeLoc = loc.replace(/^\?\((.*?)\)$/u, '$1');

    this._walk(val, m => {
      if (this._eval(safeLoc, val[m], m, path, parent, parentPropName)) {
        addRet(this._trace(x, val[m], push(path, m), val, m, callback, true));
      }
    });
  } else if (loc[0] === '(') {
    // [(expr)] (dynamic property/index)
    if (this.currPreventEval) {
      throw new Error('Eval [(expr)] prevented in JSONPath expression.');
    } // As this will resolve to a property name (but we don't know it
    //  yet), property and parent information is relative to the
    //  parent of the property to which this expression will resolve


    addRet(this._trace(unshift(this._eval(loc, val, path[path.length - 1], path.slice(0, -1), parent, parentPropName), x), val, path, parent, parentPropName, callback, hasArrExpr));
  } else if (loc[0] === '@') {
    // value type: @boolean(), etc.
    let addType = false;
    const valueType = loc.slice(1, -2);

    switch (valueType) {
      case 'scalar':
        if (!val || !['object', 'function'].includes(typeof val)) {
          addType = true;
        }

        break;

      case 'boolean':
      case 'string':
      case 'undefined':
      case 'function':
        // eslint-disable-next-line valid-typeof
        if (typeof val === valueType) {
          addType = true;
        }

        break;

      case 'integer':
        if (Number.isFinite(val) && !(val % 1)) {
          addType = true;
        }

        break;

      case 'number':
        if (Number.isFinite(val)) {
          addType = true;
        }

        break;

      case 'nonFinite':
        if (typeof val === 'number' && !Number.isFinite(val)) {
          addType = true;
        }

        break;

      case 'object':
        // eslint-disable-next-line valid-typeof
        if (val && typeof val === valueType) {
          addType = true;
        }

        break;

      case 'array':
        if (Array.isArray(val)) {
          addType = true;
        }

        break;

      case 'other':
        addType = this.currOtherTypeCallback(val, path, parent, parentPropName);
        break;

      case 'null':
        if (val === null) {
          addType = true;
        }

        break;

      /* c8 ignore next 2 */

      default:
        throw new TypeError('Unknown value type ' + valueType);
    }

    if (addType) {
      retObj = {
        path,
        value: val,
        parent,
        parentProperty: parentPropName
      };

      this._handleCallback(retObj, callback, 'value');

      return retObj;
    } // `-escaped property

  } else if (loc[0] === '`' && val && hasOwnProp.call(val, loc.slice(1))) {
    const locProp = loc.slice(1);
    addRet(this._trace(x, val[locProp], push(path, locProp), val, locProp, callback, hasArrExpr, true));
  } else if (loc.includes(',')) {
    // [name1,name2,...]
    const parts = loc.split(',');

    for (const part of parts) {
      addRet(this._trace(unshift(part, x), val, path, parent, parentPropName, callback, true));
    } // simple case--directly follow property

  } else if (!literalPriority && val && hasOwnProp.call(val, loc)) {
    addRet(this._trace(x, val[loc], push(path, loc), val, loc, callback, hasArrExpr, true));
  } // We check the resulting values for parent selections. For parent
  // selections we discard the value object and continue the trace with the
  // current val object


  if (this._hasParentSelector) {
    for (let t = 0; t < ret.length; t++) {
      const rett = ret[t];

      if (rett && rett.isParentSelector) {
        const tmp = this._trace(rett.expr, val, rett.path, parent, parentPropName, callback, hasArrExpr);

        if (Array.isArray(tmp)) {
          ret[t] = tmp[0];
          const tl = tmp.length;

          for (let tt = 1; tt < tl; tt++) {
            t++;
            ret.splice(t, 0, tmp[tt]);
          }
        } else {
          ret[t] = tmp;
        }
      }
    }
  }

  return ret;
};

JSONPath.prototype._walk = function (val, f) {
  if (Array.isArray(val)) {
    const n = val.length;

    for (let i = 0; i < n; i++) {
      f(i);
    }
  } else if (val && typeof val === 'object') {
    Object.keys(val).forEach(m => {
      f(m);
    });
  }
};

JSONPath.prototype._slice = function (loc, expr, val, path, parent, parentPropName, callback) {
  if (!Array.isArray(val)) {
    return undefined;
  }

  const len = val.length,
        parts = loc.split(':'),
        step = parts[2] && Number.parseInt(parts[2]) || 1;
  let start = parts[0] && Number.parseInt(parts[0]) || 0,
      end = parts[1] && Number.parseInt(parts[1]) || len;
  start = start < 0 ? Math.max(0, start + len) : Math.min(len, start);
  end = end < 0 ? Math.max(0, end + len) : Math.min(len, end);
  const ret = [];

  for (let i = start; i < end; i += step) {
    const tmp = this._trace(unshift(i, expr), val, path, parent, parentPropName, callback, true); // Should only be possible to be an array here since first part of
    //   ``unshift(i, expr)` passed in above would not be empty, nor `~`,
    //     nor begin with `@` (as could return objects)
    // This was causing excessive stack size in Node (with or
    //  without Babel) against our performance test: `ret.push(...tmp);`


    tmp.forEach(t => {
      ret.push(t);
    });
  }

  return ret;
};

JSONPath.prototype._eval = function (code, _v, _vname, path, parent, parentPropName) {
  this.currSandbox._$_parentProperty = parentPropName;
  this.currSandbox._$_parent = parent;
  this.currSandbox._$_property = _vname;
  this.currSandbox._$_root = this.json;
  this.currSandbox._$_v = _v;
  const containsPath = code.includes('@path');

  if (containsPath) {
    this.currSandbox._$_path = JSONPath.toPathString(path.concat([_vname]));
  }

  const scriptCacheKey = 'script:' + code;

  if (!JSONPath.cache[scriptCacheKey]) {
    let script = code.replace(/@parentProperty/gu, '_$_parentProperty').replace(/@parent/gu, '_$_parent').replace(/@property/gu, '_$_property').replace(/@root/gu, '_$_root').replace(/@([.\s)[])/gu, '_$_v$1');

    if (containsPath) {
      script = script.replace(/@path/gu, '_$_path');
    }

    JSONPath.cache[scriptCacheKey] = new this.vm.Script(script);
  }

  try {
    return JSONPath.cache[scriptCacheKey].runInNewContext(this.currSandbox);
  } catch (e) {
    throw new Error('jsonPath: ' + e.message + ': ' + code);
  }
}; // PUBLIC CLASS PROPERTIES AND METHODS
// Could store the cache object itself


JSONPath.cache = {};
/**
 * @param {string[]} pathArr Array to convert
 * @returns {string} The path string
 */

JSONPath.toPathString = function (pathArr) {
  const x = pathArr,
        n = x.length;
  let p = '$';

  for (let i = 1; i < n; i++) {
    if (!/^(~|\^|@.*?\(\))$/u.test(x[i])) {
      p += /^[0-9*]+$/u.test(x[i]) ? '[' + x[i] + ']' : "['" + x[i] + "']";
    }
  }

  return p;
};
/**
 * @param {string} pointer JSON Path
 * @returns {string} JSON Pointer
 */


JSONPath.toPointer = function (pointer) {
  const x = pointer,
        n = x.length;
  let p = '';

  for (let i = 1; i < n; i++) {
    if (!/^(~|\^|@.*?\(\))$/u.test(x[i])) {
      p += '/' + x[i].toString().replace(/~/gu, '~0').replace(/\//gu, '~1');
    }
  }

  return p;
};
/**
 * @param {string} expr Expression to convert
 * @returns {string[]}
 */


JSONPath.toPathArray = function (expr) {
  const {
    cache
  } = JSONPath;

  if (cache[expr]) {
    return cache[expr].concat();
  }

  const subx = [];
  const normalized = expr // Properties
  .replace(/@(?:null|boolean|number|string|integer|undefined|nonFinite|scalar|array|object|function|other)\(\)/gu, ';$&;') // Parenthetical evaluations (filtering and otherwise), directly
  //   within brackets or single quotes
  .replace(/[['](\??\(.*?\))[\]']/gu, function ($0, $1) {
    return '[#' + (subx.push($1) - 1) + ']';
  }) // Escape periods and tildes within properties
  .replace(/\[['"]([^'\]]*)['"]\]/gu, function ($0, prop) {
    return "['" + prop.replace(/\./gu, '%@%').replace(/~/gu, '%%@@%%') + "']";
  }) // Properties operator
  .replace(/~/gu, ';~;') // Split by property boundaries
  .replace(/['"]?\.['"]?(?![^[]*\])|\[['"]?/gu, ';') // Reinsert periods within properties
  .replace(/%@%/gu, '.') // Reinsert tildes within properties
  .replace(/%%@@%%/gu, '~') // Parent
  .replace(/(?:;)?(\^+)(?:;)?/gu, function ($0, ups) {
    return ';' + ups.split('').join(';') + ';';
  }) // Descendents
  .replace(/;;;|;;/gu, ';..;') // Remove trailing
  .replace(/;$|'?\]|'$/gu, '');
  const exprList = normalized.split(';').map(function (exp) {
    const match = exp.match(/#(\d+)/u);
    return !match || !match[1] ? exp : subx[match[1]];
  });
  cache[expr] = exprList;
  return cache[expr].concat();
};

JSONPath.prototype.vm = vm__default["default"];

exports.JSONPath = JSONPath;


/***/ }),

/***/ 452:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


var fs = __nccwpck_require__(7147);
var util = __nccwpck_require__(3837);
var path = __nccwpck_require__(1017);

let shim;
class Y18N {
    constructor(opts) {
        // configurable options.
        opts = opts || {};
        this.directory = opts.directory || './locales';
        this.updateFiles = typeof opts.updateFiles === 'boolean' ? opts.updateFiles : true;
        this.locale = opts.locale || 'en';
        this.fallbackToLanguage = typeof opts.fallbackToLanguage === 'boolean' ? opts.fallbackToLanguage : true;
        // internal stuff.
        this.cache = Object.create(null);
        this.writeQueue = [];
    }
    __(...args) {
        if (typeof arguments[0] !== 'string') {
            return this._taggedLiteral(arguments[0], ...arguments);
        }
        const str = args.shift();
        let cb = function () { }; // start with noop.
        if (typeof args[args.length - 1] === 'function')
            cb = args.pop();
        cb = cb || function () { }; // noop.
        if (!this.cache[this.locale])
            this._readLocaleFile();
        // we've observed a new string, update the language file.
        if (!this.cache[this.locale][str] && this.updateFiles) {
            this.cache[this.locale][str] = str;
            // include the current directory and locale,
            // since these values could change before the
            // write is performed.
            this._enqueueWrite({
                directory: this.directory,
                locale: this.locale,
                cb
            });
        }
        else {
            cb();
        }
        return shim.format.apply(shim.format, [this.cache[this.locale][str] || str].concat(args));
    }
    __n() {
        const args = Array.prototype.slice.call(arguments);
        const singular = args.shift();
        const plural = args.shift();
        const quantity = args.shift();
        let cb = function () { }; // start with noop.
        if (typeof args[args.length - 1] === 'function')
            cb = args.pop();
        if (!this.cache[this.locale])
            this._readLocaleFile();
        let str = quantity === 1 ? singular : plural;
        if (this.cache[this.locale][singular]) {
            const entry = this.cache[this.locale][singular];
            str = entry[quantity === 1 ? 'one' : 'other'];
        }
        // we've observed a new string, update the language file.
        if (!this.cache[this.locale][singular] && this.updateFiles) {
            this.cache[this.locale][singular] = {
                one: singular,
                other: plural
            };
            // include the current directory and locale,
            // since these values could change before the
            // write is performed.
            this._enqueueWrite({
                directory: this.directory,
                locale: this.locale,
                cb
            });
        }
        else {
            cb();
        }
        // if a %d placeholder is provided, add quantity
        // to the arguments expanded by util.format.
        const values = [str];
        if (~str.indexOf('%d'))
            values.push(quantity);
        return shim.format.apply(shim.format, values.concat(args));
    }
    setLocale(locale) {
        this.locale = locale;
    }
    getLocale() {
        return this.locale;
    }
    updateLocale(obj) {
        if (!this.cache[this.locale])
            this._readLocaleFile();
        for (const key in obj) {
            if (Object.prototype.hasOwnProperty.call(obj, key)) {
                this.cache[this.locale][key] = obj[key];
            }
        }
    }
    _taggedLiteral(parts, ...args) {
        let str = '';
        parts.forEach(function (part, i) {
            const arg = args[i + 1];
            str += part;
            if (typeof arg !== 'undefined') {
                str += '%s';
            }
        });
        return this.__.apply(this, [str].concat([].slice.call(args, 1)));
    }
    _enqueueWrite(work) {
        this.writeQueue.push(work);
        if (this.writeQueue.length === 1)
            this._processWriteQueue();
    }
    _processWriteQueue() {
        const _this = this;
        const work = this.writeQueue[0];
        // destructure the enqueued work.
        const directory = work.directory;
        const locale = work.locale;
        const cb = work.cb;
        const languageFile = this._resolveLocaleFile(directory, locale);
        const serializedLocale = JSON.stringify(this.cache[locale], null, 2);
        shim.fs.writeFile(languageFile, serializedLocale, 'utf-8', function (err) {
            _this.writeQueue.shift();
            if (_this.writeQueue.length > 0)
                _this._processWriteQueue();
            cb(err);
        });
    }
    _readLocaleFile() {
        let localeLookup = {};
        const languageFile = this._resolveLocaleFile(this.directory, this.locale);
        try {
            // When using a bundler such as webpack, readFileSync may not be defined:
            if (shim.fs.readFileSync) {
                localeLookup = JSON.parse(shim.fs.readFileSync(languageFile, 'utf-8'));
            }
        }
        catch (err) {
            if (err instanceof SyntaxError) {
                err.message = 'syntax error in ' + languageFile;
            }
            if (err.code === 'ENOENT')
                localeLookup = {};
            else
                throw err;
        }
        this.cache[this.locale] = localeLookup;
    }
    _resolveLocaleFile(directory, locale) {
        let file = shim.resolve(directory, './', locale + '.json');
        if (this.fallbackToLanguage && !this._fileExistsSync(file) && ~locale.lastIndexOf('_')) {
            // attempt fallback to language only
            const languageFile = shim.resolve(directory, './', locale.split('_')[0] + '.json');
            if (this._fileExistsSync(languageFile))
                file = languageFile;
        }
        return file;
    }
    _fileExistsSync(file) {
        return shim.exists(file);
    }
}
function y18n$1(opts, _shim) {
    shim = _shim;
    const y18n = new Y18N(opts);
    return {
        __: y18n.__.bind(y18n),
        __n: y18n.__n.bind(y18n),
        setLocale: y18n.setLocale.bind(y18n),
        getLocale: y18n.getLocale.bind(y18n),
        updateLocale: y18n.updateLocale.bind(y18n),
        locale: y18n.locale
    };
}

var nodePlatformShim = {
    fs: {
        readFileSync: fs.readFileSync,
        writeFile: fs.writeFile
    },
    format: util.format,
    resolve: path.resolve,
    exists: (file) => {
        try {
            return fs.statSync(file).isFile();
        }
        catch (err) {
            return false;
        }
    }
};

const y18n = (opts) => {
    return y18n$1(opts, nodePlatformShim);
};

module.exports = y18n;


/***/ }),

/***/ 1970:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


var util = __nccwpck_require__(3837);
var path = __nccwpck_require__(1017);
var fs = __nccwpck_require__(7147);

function camelCase(str) {
    const isCamelCase = str !== str.toLowerCase() && str !== str.toUpperCase();
    if (!isCamelCase) {
        str = str.toLowerCase();
    }
    if (str.indexOf('-') === -1 && str.indexOf('_') === -1) {
        return str;
    }
    else {
        let camelcase = '';
        let nextChrUpper = false;
        const leadingHyphens = str.match(/^-+/);
        for (let i = leadingHyphens ? leadingHyphens[0].length : 0; i < str.length; i++) {
            let chr = str.charAt(i);
            if (nextChrUpper) {
                nextChrUpper = false;
                chr = chr.toUpperCase();
            }
            if (i !== 0 && (chr === '-' || chr === '_')) {
                nextChrUpper = true;
            }
            else if (chr !== '-' && chr !== '_') {
                camelcase += chr;
            }
        }
        return camelcase;
    }
}
function decamelize(str, joinString) {
    const lowercase = str.toLowerCase();
    joinString = joinString || '-';
    let notCamelcase = '';
    for (let i = 0; i < str.length; i++) {
        const chrLower = lowercase.charAt(i);
        const chrString = str.charAt(i);
        if (chrLower !== chrString && i > 0) {
            notCamelcase += `${joinString}${lowercase.charAt(i)}`;
        }
        else {
            notCamelcase += chrString;
        }
    }
    return notCamelcase;
}
function looksLikeNumber(x) {
    if (x === null || x === undefined)
        return false;
    if (typeof x === 'number')
        return true;
    if (/^0x[0-9a-f]+$/i.test(x))
        return true;
    if (/^0[^.]/.test(x))
        return false;
    return /^[-]?(?:\d+(?:\.\d*)?|\.\d+)(e[-+]?\d+)?$/.test(x);
}

function tokenizeArgString(argString) {
    if (Array.isArray(argString)) {
        return argString.map(e => typeof e !== 'string' ? e + '' : e);
    }
    argString = argString.trim();
    let i = 0;
    let prevC = null;
    let c = null;
    let opening = null;
    const args = [];
    for (let ii = 0; ii < argString.length; ii++) {
        prevC = c;
        c = argString.charAt(ii);
        if (c === ' ' && !opening) {
            if (!(prevC === ' ')) {
                i++;
            }
            continue;
        }
        if (c === opening) {
            opening = null;
        }
        else if ((c === "'" || c === '"') && !opening) {
            opening = c;
        }
        if (!args[i])
            args[i] = '';
        args[i] += c;
    }
    return args;
}

var DefaultValuesForTypeKey;
(function (DefaultValuesForTypeKey) {
    DefaultValuesForTypeKey["BOOLEAN"] = "boolean";
    DefaultValuesForTypeKey["STRING"] = "string";
    DefaultValuesForTypeKey["NUMBER"] = "number";
    DefaultValuesForTypeKey["ARRAY"] = "array";
})(DefaultValuesForTypeKey || (DefaultValuesForTypeKey = {}));

let mixin;
class YargsParser {
    constructor(_mixin) {
        mixin = _mixin;
    }
    parse(argsInput, options) {
        const opts = Object.assign({
            alias: undefined,
            array: undefined,
            boolean: undefined,
            config: undefined,
            configObjects: undefined,
            configuration: undefined,
            coerce: undefined,
            count: undefined,
            default: undefined,
            envPrefix: undefined,
            narg: undefined,
            normalize: undefined,
            string: undefined,
            number: undefined,
            __: undefined,
            key: undefined
        }, options);
        const args = tokenizeArgString(argsInput);
        const inputIsString = typeof argsInput === 'string';
        const aliases = combineAliases(Object.assign(Object.create(null), opts.alias));
        const configuration = Object.assign({
            'boolean-negation': true,
            'camel-case-expansion': true,
            'combine-arrays': false,
            'dot-notation': true,
            'duplicate-arguments-array': true,
            'flatten-duplicate-arrays': true,
            'greedy-arrays': true,
            'halt-at-non-option': false,
            'nargs-eats-options': false,
            'negation-prefix': 'no-',
            'parse-numbers': true,
            'parse-positional-numbers': true,
            'populate--': false,
            'set-placeholder-key': false,
            'short-option-groups': true,
            'strip-aliased': false,
            'strip-dashed': false,
            'unknown-options-as-args': false
        }, opts.configuration);
        const defaults = Object.assign(Object.create(null), opts.default);
        const configObjects = opts.configObjects || [];
        const envPrefix = opts.envPrefix;
        const notFlagsOption = configuration['populate--'];
        const notFlagsArgv = notFlagsOption ? '--' : '_';
        const newAliases = Object.create(null);
        const defaulted = Object.create(null);
        const __ = opts.__ || mixin.format;
        const flags = {
            aliases: Object.create(null),
            arrays: Object.create(null),
            bools: Object.create(null),
            strings: Object.create(null),
            numbers: Object.create(null),
            counts: Object.create(null),
            normalize: Object.create(null),
            configs: Object.create(null),
            nargs: Object.create(null),
            coercions: Object.create(null),
            keys: []
        };
        const negative = /^-([0-9]+(\.[0-9]+)?|\.[0-9]+)$/;
        const negatedBoolean = new RegExp('^--' + configuration['negation-prefix'] + '(.+)');
        [].concat(opts.array || []).filter(Boolean).forEach(function (opt) {
            const key = typeof opt === 'object' ? opt.key : opt;
            const assignment = Object.keys(opt).map(function (key) {
                const arrayFlagKeys = {
                    boolean: 'bools',
                    string: 'strings',
                    number: 'numbers'
                };
                return arrayFlagKeys[key];
            }).filter(Boolean).pop();
            if (assignment) {
                flags[assignment][key] = true;
            }
            flags.arrays[key] = true;
            flags.keys.push(key);
        });
        [].concat(opts.boolean || []).filter(Boolean).forEach(function (key) {
            flags.bools[key] = true;
            flags.keys.push(key);
        });
        [].concat(opts.string || []).filter(Boolean).forEach(function (key) {
            flags.strings[key] = true;
            flags.keys.push(key);
        });
        [].concat(opts.number || []).filter(Boolean).forEach(function (key) {
            flags.numbers[key] = true;
            flags.keys.push(key);
        });
        [].concat(opts.count || []).filter(Boolean).forEach(function (key) {
            flags.counts[key] = true;
            flags.keys.push(key);
        });
        [].concat(opts.normalize || []).filter(Boolean).forEach(function (key) {
            flags.normalize[key] = true;
            flags.keys.push(key);
        });
        if (typeof opts.narg === 'object') {
            Object.entries(opts.narg).forEach(([key, value]) => {
                if (typeof value === 'number') {
                    flags.nargs[key] = value;
                    flags.keys.push(key);
                }
            });
        }
        if (typeof opts.coerce === 'object') {
            Object.entries(opts.coerce).forEach(([key, value]) => {
                if (typeof value === 'function') {
                    flags.coercions[key] = value;
                    flags.keys.push(key);
                }
            });
        }
        if (typeof opts.config !== 'undefined') {
            if (Array.isArray(opts.config) || typeof opts.config === 'string') {
                [].concat(opts.config).filter(Boolean).forEach(function (key) {
                    flags.configs[key] = true;
                });
            }
            else if (typeof opts.config === 'object') {
                Object.entries(opts.config).forEach(([key, value]) => {
                    if (typeof value === 'boolean' || typeof value === 'function') {
                        flags.configs[key] = value;
                    }
                });
            }
        }
        extendAliases(opts.key, aliases, opts.default, flags.arrays);
        Object.keys(defaults).forEach(function (key) {
            (flags.aliases[key] || []).forEach(function (alias) {
                defaults[alias] = defaults[key];
            });
        });
        let error = null;
        checkConfiguration();
        let notFlags = [];
        const argv = Object.assign(Object.create(null), { _: [] });
        const argvReturn = {};
        for (let i = 0; i < args.length; i++) {
            const arg = args[i];
            const truncatedArg = arg.replace(/^-{3,}/, '---');
            let broken;
            let key;
            let letters;
            let m;
            let next;
            let value;
            if (arg !== '--' && /^-/.test(arg) && isUnknownOptionAsArg(arg)) {
                pushPositional(arg);
            }
            else if (truncatedArg.match(/^---+(=|$)/)) {
                pushPositional(arg);
                continue;
            }
            else if (arg.match(/^--.+=/) || (!configuration['short-option-groups'] && arg.match(/^-.+=/))) {
                m = arg.match(/^--?([^=]+)=([\s\S]*)$/);
                if (m !== null && Array.isArray(m) && m.length >= 3) {
                    if (checkAllAliases(m[1], flags.arrays)) {
                        i = eatArray(i, m[1], args, m[2]);
                    }
                    else if (checkAllAliases(m[1], flags.nargs) !== false) {
                        i = eatNargs(i, m[1], args, m[2]);
                    }
                    else {
                        setArg(m[1], m[2], true);
                    }
                }
            }
            else if (arg.match(negatedBoolean) && configuration['boolean-negation']) {
                m = arg.match(negatedBoolean);
                if (m !== null && Array.isArray(m) && m.length >= 2) {
                    key = m[1];
                    setArg(key, checkAllAliases(key, flags.arrays) ? [false] : false);
                }
            }
            else if (arg.match(/^--.+/) || (!configuration['short-option-groups'] && arg.match(/^-[^-]+/))) {
                m = arg.match(/^--?(.+)/);
                if (m !== null && Array.isArray(m) && m.length >= 2) {
                    key = m[1];
                    if (checkAllAliases(key, flags.arrays)) {
                        i = eatArray(i, key, args);
                    }
                    else if (checkAllAliases(key, flags.nargs) !== false) {
                        i = eatNargs(i, key, args);
                    }
                    else {
                        next = args[i + 1];
                        if (next !== undefined && (!next.match(/^-/) ||
                            next.match(negative)) &&
                            !checkAllAliases(key, flags.bools) &&
                            !checkAllAliases(key, flags.counts)) {
                            setArg(key, next);
                            i++;
                        }
                        else if (/^(true|false)$/.test(next)) {
                            setArg(key, next);
                            i++;
                        }
                        else {
                            setArg(key, defaultValue(key));
                        }
                    }
                }
            }
            else if (arg.match(/^-.\..+=/)) {
                m = arg.match(/^-([^=]+)=([\s\S]*)$/);
                if (m !== null && Array.isArray(m) && m.length >= 3) {
                    setArg(m[1], m[2]);
                }
            }
            else if (arg.match(/^-.\..+/) && !arg.match(negative)) {
                next = args[i + 1];
                m = arg.match(/^-(.\..+)/);
                if (m !== null && Array.isArray(m) && m.length >= 2) {
                    key = m[1];
                    if (next !== undefined && !next.match(/^-/) &&
                        !checkAllAliases(key, flags.bools) &&
                        !checkAllAliases(key, flags.counts)) {
                        setArg(key, next);
                        i++;
                    }
                    else {
                        setArg(key, defaultValue(key));
                    }
                }
            }
            else if (arg.match(/^-[^-]+/) && !arg.match(negative)) {
                letters = arg.slice(1, -1).split('');
                broken = false;
                for (let j = 0; j < letters.length; j++) {
                    next = arg.slice(j + 2);
                    if (letters[j + 1] && letters[j + 1] === '=') {
                        value = arg.slice(j + 3);
                        key = letters[j];
                        if (checkAllAliases(key, flags.arrays)) {
                            i = eatArray(i, key, args, value);
                        }
                        else if (checkAllAliases(key, flags.nargs) !== false) {
                            i = eatNargs(i, key, args, value);
                        }
                        else {
                            setArg(key, value);
                        }
                        broken = true;
                        break;
                    }
                    if (next === '-') {
                        setArg(letters[j], next);
                        continue;
                    }
                    if (/[A-Za-z]/.test(letters[j]) &&
                        /^-?\d+(\.\d*)?(e-?\d+)?$/.test(next) &&
                        checkAllAliases(next, flags.bools) === false) {
                        setArg(letters[j], next);
                        broken = true;
                        break;
                    }
                    if (letters[j + 1] && letters[j + 1].match(/\W/)) {
                        setArg(letters[j], next);
                        broken = true;
                        break;
                    }
                    else {
                        setArg(letters[j], defaultValue(letters[j]));
                    }
                }
                key = arg.slice(-1)[0];
                if (!broken && key !== '-') {
                    if (checkAllAliases(key, flags.arrays)) {
                        i = eatArray(i, key, args);
                    }
                    else if (checkAllAliases(key, flags.nargs) !== false) {
                        i = eatNargs(i, key, args);
                    }
                    else {
                        next = args[i + 1];
                        if (next !== undefined && (!/^(-|--)[^-]/.test(next) ||
                            next.match(negative)) &&
                            !checkAllAliases(key, flags.bools) &&
                            !checkAllAliases(key, flags.counts)) {
                            setArg(key, next);
                            i++;
                        }
                        else if (/^(true|false)$/.test(next)) {
                            setArg(key, next);
                            i++;
                        }
                        else {
                            setArg(key, defaultValue(key));
                        }
                    }
                }
            }
            else if (arg.match(/^-[0-9]$/) &&
                arg.match(negative) &&
                checkAllAliases(arg.slice(1), flags.bools)) {
                key = arg.slice(1);
                setArg(key, defaultValue(key));
            }
            else if (arg === '--') {
                notFlags = args.slice(i + 1);
                break;
            }
            else if (configuration['halt-at-non-option']) {
                notFlags = args.slice(i);
                break;
            }
            else {
                pushPositional(arg);
            }
        }
        applyEnvVars(argv, true);
        applyEnvVars(argv, false);
        setConfig(argv);
        setConfigObjects();
        applyDefaultsAndAliases(argv, flags.aliases, defaults, true);
        applyCoercions(argv);
        if (configuration['set-placeholder-key'])
            setPlaceholderKeys(argv);
        Object.keys(flags.counts).forEach(function (key) {
            if (!hasKey(argv, key.split('.')))
                setArg(key, 0);
        });
        if (notFlagsOption && notFlags.length)
            argv[notFlagsArgv] = [];
        notFlags.forEach(function (key) {
            argv[notFlagsArgv].push(key);
        });
        if (configuration['camel-case-expansion'] && configuration['strip-dashed']) {
            Object.keys(argv).filter(key => key !== '--' && key.includes('-')).forEach(key => {
                delete argv[key];
            });
        }
        if (configuration['strip-aliased']) {
            [].concat(...Object.keys(aliases).map(k => aliases[k])).forEach(alias => {
                if (configuration['camel-case-expansion'] && alias.includes('-')) {
                    delete argv[alias.split('.').map(prop => camelCase(prop)).join('.')];
                }
                delete argv[alias];
            });
        }
        function pushPositional(arg) {
            const maybeCoercedNumber = maybeCoerceNumber('_', arg);
            if (typeof maybeCoercedNumber === 'string' || typeof maybeCoercedNumber === 'number') {
                argv._.push(maybeCoercedNumber);
            }
        }
        function eatNargs(i, key, args, argAfterEqualSign) {
            let ii;
            let toEat = checkAllAliases(key, flags.nargs);
            toEat = typeof toEat !== 'number' || isNaN(toEat) ? 1 : toEat;
            if (toEat === 0) {
                if (!isUndefined(argAfterEqualSign)) {
                    error = Error(__('Argument unexpected for: %s', key));
                }
                setArg(key, defaultValue(key));
                return i;
            }
            let available = isUndefined(argAfterEqualSign) ? 0 : 1;
            if (configuration['nargs-eats-options']) {
                if (args.length - (i + 1) + available < toEat) {
                    error = Error(__('Not enough arguments following: %s', key));
                }
                available = toEat;
            }
            else {
                for (ii = i + 1; ii < args.length; ii++) {
                    if (!args[ii].match(/^-[^0-9]/) || args[ii].match(negative) || isUnknownOptionAsArg(args[ii]))
                        available++;
                    else
                        break;
                }
                if (available < toEat)
                    error = Error(__('Not enough arguments following: %s', key));
            }
            let consumed = Math.min(available, toEat);
            if (!isUndefined(argAfterEqualSign) && consumed > 0) {
                setArg(key, argAfterEqualSign);
                consumed--;
            }
            for (ii = i + 1; ii < (consumed + i + 1); ii++) {
                setArg(key, args[ii]);
            }
            return (i + consumed);
        }
        function eatArray(i, key, args, argAfterEqualSign) {
            let argsToSet = [];
            let next = argAfterEqualSign || args[i + 1];
            const nargsCount = checkAllAliases(key, flags.nargs);
            if (checkAllAliases(key, flags.bools) && !(/^(true|false)$/.test(next))) {
                argsToSet.push(true);
            }
            else if (isUndefined(next) ||
                (isUndefined(argAfterEqualSign) && /^-/.test(next) && !negative.test(next) && !isUnknownOptionAsArg(next))) {
                if (defaults[key] !== undefined) {
                    const defVal = defaults[key];
                    argsToSet = Array.isArray(defVal) ? defVal : [defVal];
                }
            }
            else {
                if (!isUndefined(argAfterEqualSign)) {
                    argsToSet.push(processValue(key, argAfterEqualSign, true));
                }
                for (let ii = i + 1; ii < args.length; ii++) {
                    if ((!configuration['greedy-arrays'] && argsToSet.length > 0) ||
                        (nargsCount && typeof nargsCount === 'number' && argsToSet.length >= nargsCount))
                        break;
                    next = args[ii];
                    if (/^-/.test(next) && !negative.test(next) && !isUnknownOptionAsArg(next))
                        break;
                    i = ii;
                    argsToSet.push(processValue(key, next, inputIsString));
                }
            }
            if (typeof nargsCount === 'number' && ((nargsCount && argsToSet.length < nargsCount) ||
                (isNaN(nargsCount) && argsToSet.length === 0))) {
                error = Error(__('Not enough arguments following: %s', key));
            }
            setArg(key, argsToSet);
            return i;
        }
        function setArg(key, val, shouldStripQuotes = inputIsString) {
            if (/-/.test(key) && configuration['camel-case-expansion']) {
                const alias = key.split('.').map(function (prop) {
                    return camelCase(prop);
                }).join('.');
                addNewAlias(key, alias);
            }
            const value = processValue(key, val, shouldStripQuotes);
            const splitKey = key.split('.');
            setKey(argv, splitKey, value);
            if (flags.aliases[key]) {
                flags.aliases[key].forEach(function (x) {
                    const keyProperties = x.split('.');
                    setKey(argv, keyProperties, value);
                });
            }
            if (splitKey.length > 1 && configuration['dot-notation']) {
                (flags.aliases[splitKey[0]] || []).forEach(function (x) {
                    let keyProperties = x.split('.');
                    const a = [].concat(splitKey);
                    a.shift();
                    keyProperties = keyProperties.concat(a);
                    if (!(flags.aliases[key] || []).includes(keyProperties.join('.'))) {
                        setKey(argv, keyProperties, value);
                    }
                });
            }
            if (checkAllAliases(key, flags.normalize) && !checkAllAliases(key, flags.arrays)) {
                const keys = [key].concat(flags.aliases[key] || []);
                keys.forEach(function (key) {
                    Object.defineProperty(argvReturn, key, {
                        enumerable: true,
                        get() {
                            return val;
                        },
                        set(value) {
                            val = typeof value === 'string' ? mixin.normalize(value) : value;
                        }
                    });
                });
            }
        }
        function addNewAlias(key, alias) {
            if (!(flags.aliases[key] && flags.aliases[key].length)) {
                flags.aliases[key] = [alias];
                newAliases[alias] = true;
            }
            if (!(flags.aliases[alias] && flags.aliases[alias].length)) {
                addNewAlias(alias, key);
            }
        }
        function processValue(key, val, shouldStripQuotes) {
            if (shouldStripQuotes) {
                val = stripQuotes(val);
            }
            if (checkAllAliases(key, flags.bools) || checkAllAliases(key, flags.counts)) {
                if (typeof val === 'string')
                    val = val === 'true';
            }
            let value = Array.isArray(val)
                ? val.map(function (v) { return maybeCoerceNumber(key, v); })
                : maybeCoerceNumber(key, val);
            if (checkAllAliases(key, flags.counts) && (isUndefined(value) || typeof value === 'boolean')) {
                value = increment();
            }
            if (checkAllAliases(key, flags.normalize) && checkAllAliases(key, flags.arrays)) {
                if (Array.isArray(val))
                    value = val.map((val) => { return mixin.normalize(val); });
                else
                    value = mixin.normalize(val);
            }
            return value;
        }
        function maybeCoerceNumber(key, value) {
            if (!configuration['parse-positional-numbers'] && key === '_')
                return value;
            if (!checkAllAliases(key, flags.strings) && !checkAllAliases(key, flags.bools) && !Array.isArray(value)) {
                const shouldCoerceNumber = looksLikeNumber(value) && configuration['parse-numbers'] && (Number.isSafeInteger(Math.floor(parseFloat(`${value}`))));
                if (shouldCoerceNumber || (!isUndefined(value) && checkAllAliases(key, flags.numbers))) {
                    value = Number(value);
                }
            }
            return value;
        }
        function setConfig(argv) {
            const configLookup = Object.create(null);
            applyDefaultsAndAliases(configLookup, flags.aliases, defaults);
            Object.keys(flags.configs).forEach(function (configKey) {
                const configPath = argv[configKey] || configLookup[configKey];
                if (configPath) {
                    try {
                        let config = null;
                        const resolvedConfigPath = mixin.resolve(mixin.cwd(), configPath);
                        const resolveConfig = flags.configs[configKey];
                        if (typeof resolveConfig === 'function') {
                            try {
                                config = resolveConfig(resolvedConfigPath);
                            }
                            catch (e) {
                                config = e;
                            }
                            if (config instanceof Error) {
                                error = config;
                                return;
                            }
                        }
                        else {
                            config = mixin.require(resolvedConfigPath);
                        }
                        setConfigObject(config);
                    }
                    catch (ex) {
                        if (ex.name === 'PermissionDenied')
                            error = ex;
                        else if (argv[configKey])
                            error = Error(__('Invalid JSON config file: %s', configPath));
                    }
                }
            });
        }
        function setConfigObject(config, prev) {
            Object.keys(config).forEach(function (key) {
                const value = config[key];
                const fullKey = prev ? prev + '.' + key : key;
                if (typeof value === 'object' && value !== null && !Array.isArray(value) && configuration['dot-notation']) {
                    setConfigObject(value, fullKey);
                }
                else {
                    if (!hasKey(argv, fullKey.split('.')) || (checkAllAliases(fullKey, flags.arrays) && configuration['combine-arrays'])) {
                        setArg(fullKey, value);
                    }
                }
            });
        }
        function setConfigObjects() {
            if (typeof configObjects !== 'undefined') {
                configObjects.forEach(function (configObject) {
                    setConfigObject(configObject);
                });
            }
        }
        function applyEnvVars(argv, configOnly) {
            if (typeof envPrefix === 'undefined')
                return;
            const prefix = typeof envPrefix === 'string' ? envPrefix : '';
            const env = mixin.env();
            Object.keys(env).forEach(function (envVar) {
                if (prefix === '' || envVar.lastIndexOf(prefix, 0) === 0) {
                    const keys = envVar.split('__').map(function (key, i) {
                        if (i === 0) {
                            key = key.substring(prefix.length);
                        }
                        return camelCase(key);
                    });
                    if (((configOnly && flags.configs[keys.join('.')]) || !configOnly) && !hasKey(argv, keys)) {
                        setArg(keys.join('.'), env[envVar]);
                    }
                }
            });
        }
        function applyCoercions(argv) {
            let coerce;
            const applied = new Set();
            Object.keys(argv).forEach(function (key) {
                if (!applied.has(key)) {
                    coerce = checkAllAliases(key, flags.coercions);
                    if (typeof coerce === 'function') {
                        try {
                            const value = maybeCoerceNumber(key, coerce(argv[key]));
                            ([].concat(flags.aliases[key] || [], key)).forEach(ali => {
                                applied.add(ali);
                                argv[ali] = value;
                            });
                        }
                        catch (err) {
                            error = err;
                        }
                    }
                }
            });
        }
        function setPlaceholderKeys(argv) {
            flags.keys.forEach((key) => {
                if (~key.indexOf('.'))
                    return;
                if (typeof argv[key] === 'undefined')
                    argv[key] = undefined;
            });
            return argv;
        }
        function applyDefaultsAndAliases(obj, aliases, defaults, canLog = false) {
            Object.keys(defaults).forEach(function (key) {
                if (!hasKey(obj, key.split('.'))) {
                    setKey(obj, key.split('.'), defaults[key]);
                    if (canLog)
                        defaulted[key] = true;
                    (aliases[key] || []).forEach(function (x) {
                        if (hasKey(obj, x.split('.')))
                            return;
                        setKey(obj, x.split('.'), defaults[key]);
                    });
                }
            });
        }
        function hasKey(obj, keys) {
            let o = obj;
            if (!configuration['dot-notation'])
                keys = [keys.join('.')];
            keys.slice(0, -1).forEach(function (key) {
                o = (o[key] || {});
            });
            const key = keys[keys.length - 1];
            if (typeof o !== 'object')
                return false;
            else
                return key in o;
        }
        function setKey(obj, keys, value) {
            let o = obj;
            if (!configuration['dot-notation'])
                keys = [keys.join('.')];
            keys.slice(0, -1).forEach(function (key) {
                key = sanitizeKey(key);
                if (typeof o === 'object' && o[key] === undefined) {
                    o[key] = {};
                }
                if (typeof o[key] !== 'object' || Array.isArray(o[key])) {
                    if (Array.isArray(o[key])) {
                        o[key].push({});
                    }
                    else {
                        o[key] = [o[key], {}];
                    }
                    o = o[key][o[key].length - 1];
                }
                else {
                    o = o[key];
                }
            });
            const key = sanitizeKey(keys[keys.length - 1]);
            const isTypeArray = checkAllAliases(keys.join('.'), flags.arrays);
            const isValueArray = Array.isArray(value);
            let duplicate = configuration['duplicate-arguments-array'];
            if (!duplicate && checkAllAliases(key, flags.nargs)) {
                duplicate = true;
                if ((!isUndefined(o[key]) && flags.nargs[key] === 1) || (Array.isArray(o[key]) && o[key].length === flags.nargs[key])) {
                    o[key] = undefined;
                }
            }
            if (value === increment()) {
                o[key] = increment(o[key]);
            }
            else if (Array.isArray(o[key])) {
                if (duplicate && isTypeArray && isValueArray) {
                    o[key] = configuration['flatten-duplicate-arrays'] ? o[key].concat(value) : (Array.isArray(o[key][0]) ? o[key] : [o[key]]).concat([value]);
                }
                else if (!duplicate && Boolean(isTypeArray) === Boolean(isValueArray)) {
                    o[key] = value;
                }
                else {
                    o[key] = o[key].concat([value]);
                }
            }
            else if (o[key] === undefined && isTypeArray) {
                o[key] = isValueArray ? value : [value];
            }
            else if (duplicate && !(o[key] === undefined ||
                checkAllAliases(key, flags.counts) ||
                checkAllAliases(key, flags.bools))) {
                o[key] = [o[key], value];
            }
            else {
                o[key] = value;
            }
        }
        function extendAliases(...args) {
            args.forEach(function (obj) {
                Object.keys(obj || {}).forEach(function (key) {
                    if (flags.aliases[key])
                        return;
                    flags.aliases[key] = [].concat(aliases[key] || []);
                    flags.aliases[key].concat(key).forEach(function (x) {
                        if (/-/.test(x) && configuration['camel-case-expansion']) {
                            const c = camelCase(x);
                            if (c !== key && flags.aliases[key].indexOf(c) === -1) {
                                flags.aliases[key].push(c);
                                newAliases[c] = true;
                            }
                        }
                    });
                    flags.aliases[key].concat(key).forEach(function (x) {
                        if (x.length > 1 && /[A-Z]/.test(x) && configuration['camel-case-expansion']) {
                            const c = decamelize(x, '-');
                            if (c !== key && flags.aliases[key].indexOf(c) === -1) {
                                flags.aliases[key].push(c);
                                newAliases[c] = true;
                            }
                        }
                    });
                    flags.aliases[key].forEach(function (x) {
                        flags.aliases[x] = [key].concat(flags.aliases[key].filter(function (y) {
                            return x !== y;
                        }));
                    });
                });
            });
        }
        function checkAllAliases(key, flag) {
            const toCheck = [].concat(flags.aliases[key] || [], key);
            const keys = Object.keys(flag);
            const setAlias = toCheck.find(key => keys.includes(key));
            return setAlias ? flag[setAlias] : false;
        }
        function hasAnyFlag(key) {
            const flagsKeys = Object.keys(flags);
            const toCheck = [].concat(flagsKeys.map(k => flags[k]));
            return toCheck.some(function (flag) {
                return Array.isArray(flag) ? flag.includes(key) : flag[key];
            });
        }
        function hasFlagsMatching(arg, ...patterns) {
            const toCheck = [].concat(...patterns);
            return toCheck.some(function (pattern) {
                const match = arg.match(pattern);
                return match && hasAnyFlag(match[1]);
            });
        }
        function hasAllShortFlags(arg) {
            if (arg.match(negative) || !arg.match(/^-[^-]+/)) {
                return false;
            }
            let hasAllFlags = true;
            let next;
            const letters = arg.slice(1).split('');
            for (let j = 0; j < letters.length; j++) {
                next = arg.slice(j + 2);
                if (!hasAnyFlag(letters[j])) {
                    hasAllFlags = false;
                    break;
                }
                if ((letters[j + 1] && letters[j + 1] === '=') ||
                    next === '-' ||
                    (/[A-Za-z]/.test(letters[j]) && /^-?\d+(\.\d*)?(e-?\d+)?$/.test(next)) ||
                    (letters[j + 1] && letters[j + 1].match(/\W/))) {
                    break;
                }
            }
            return hasAllFlags;
        }
        function isUnknownOptionAsArg(arg) {
            return configuration['unknown-options-as-args'] && isUnknownOption(arg);
        }
        function isUnknownOption(arg) {
            arg = arg.replace(/^-{3,}/, '--');
            if (arg.match(negative)) {
                return false;
            }
            if (hasAllShortFlags(arg)) {
                return false;
            }
            const flagWithEquals = /^-+([^=]+?)=[\s\S]*$/;
            const normalFlag = /^-+([^=]+?)$/;
            const flagEndingInHyphen = /^-+([^=]+?)-$/;
            const flagEndingInDigits = /^-+([^=]+?\d+)$/;
            const flagEndingInNonWordCharacters = /^-+([^=]+?)\W+.*$/;
            return !hasFlagsMatching(arg, flagWithEquals, negatedBoolean, normalFlag, flagEndingInHyphen, flagEndingInDigits, flagEndingInNonWordCharacters);
        }
        function defaultValue(key) {
            if (!checkAllAliases(key, flags.bools) &&
                !checkAllAliases(key, flags.counts) &&
                `${key}` in defaults) {
                return defaults[key];
            }
            else {
                return defaultForType(guessType(key));
            }
        }
        function defaultForType(type) {
            const def = {
                [DefaultValuesForTypeKey.BOOLEAN]: true,
                [DefaultValuesForTypeKey.STRING]: '',
                [DefaultValuesForTypeKey.NUMBER]: undefined,
                [DefaultValuesForTypeKey.ARRAY]: []
            };
            return def[type];
        }
        function guessType(key) {
            let type = DefaultValuesForTypeKey.BOOLEAN;
            if (checkAllAliases(key, flags.strings))
                type = DefaultValuesForTypeKey.STRING;
            else if (checkAllAliases(key, flags.numbers))
                type = DefaultValuesForTypeKey.NUMBER;
            else if (checkAllAliases(key, flags.bools))
                type = DefaultValuesForTypeKey.BOOLEAN;
            else if (checkAllAliases(key, flags.arrays))
                type = DefaultValuesForTypeKey.ARRAY;
            return type;
        }
        function isUndefined(num) {
            return num === undefined;
        }
        function checkConfiguration() {
            Object.keys(flags.counts).find(key => {
                if (checkAllAliases(key, flags.arrays)) {
                    error = Error(__('Invalid configuration: %s, opts.count excludes opts.array.', key));
                    return true;
                }
                else if (checkAllAliases(key, flags.nargs)) {
                    error = Error(__('Invalid configuration: %s, opts.count excludes opts.narg.', key));
                    return true;
                }
                return false;
            });
        }
        return {
            aliases: Object.assign({}, flags.aliases),
            argv: Object.assign(argvReturn, argv),
            configuration: configuration,
            defaulted: Object.assign({}, defaulted),
            error: error,
            newAliases: Object.assign({}, newAliases)
        };
    }
}
function combineAliases(aliases) {
    const aliasArrays = [];
    const combined = Object.create(null);
    let change = true;
    Object.keys(aliases).forEach(function (key) {
        aliasArrays.push([].concat(aliases[key], key));
    });
    while (change) {
        change = false;
        for (let i = 0; i < aliasArrays.length; i++) {
            for (let ii = i + 1; ii < aliasArrays.length; ii++) {
                const intersect = aliasArrays[i].filter(function (v) {
                    return aliasArrays[ii].indexOf(v) !== -1;
                });
                if (intersect.length) {
                    aliasArrays[i] = aliasArrays[i].concat(aliasArrays[ii]);
                    aliasArrays.splice(ii, 1);
                    change = true;
                    break;
                }
            }
        }
    }
    aliasArrays.forEach(function (aliasArray) {
        aliasArray = aliasArray.filter(function (v, i, self) {
            return self.indexOf(v) === i;
        });
        const lastAlias = aliasArray.pop();
        if (lastAlias !== undefined && typeof lastAlias === 'string') {
            combined[lastAlias] = aliasArray;
        }
    });
    return combined;
}
function increment(orig) {
    return orig !== undefined ? orig + 1 : 1;
}
function sanitizeKey(key) {
    if (key === '__proto__')
        return '___proto___';
    return key;
}
function stripQuotes(val) {
    return (typeof val === 'string' &&
        (val[0] === "'" || val[0] === '"') &&
        val[val.length - 1] === val[0])
        ? val.substring(1, val.length - 1)
        : val;
}

var _a, _b, _c;
const minNodeVersion = (process && process.env && process.env.YARGS_MIN_NODE_VERSION)
    ? Number(process.env.YARGS_MIN_NODE_VERSION)
    : 12;
const nodeVersion = (_b = (_a = process === null || process === void 0 ? void 0 : process.versions) === null || _a === void 0 ? void 0 : _a.node) !== null && _b !== void 0 ? _b : (_c = process === null || process === void 0 ? void 0 : process.version) === null || _c === void 0 ? void 0 : _c.slice(1);
if (nodeVersion) {
    const major = Number(nodeVersion.match(/^([^.]+)/)[1]);
    if (major < minNodeVersion) {
        throw Error(`yargs parser supports a minimum Node.js version of ${minNodeVersion}. Read our version support policy: https://github.com/yargs/yargs-parser#supported-nodejs-versions`);
    }
}
const env = process ? process.env : {};
const parser = new YargsParser({
    cwd: process.cwd,
    env: () => {
        return env;
    },
    format: util.format,
    normalize: path.normalize,
    resolve: path.resolve,
    require: (path) => {
        if (true) {
            return __nccwpck_require__(5670)(path);
        }
        else {}
    }
});
const yargsParser = function Parser(args, opts) {
    const result = parser.parse(args.slice(), opts);
    return result.argv;
};
yargsParser.detailed = function (args, opts) {
    return parser.parse(args.slice(), opts);
};
yargsParser.camelCase = camelCase;
yargsParser.decamelize = decamelize;
yargsParser.looksLikeNumber = looksLikeNumber;

module.exports = yargsParser;


/***/ }),

/***/ 9562:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";
var t=__nccwpck_require__(9491);class e extends Error{constructor(t){super(t||"yargs error"),this.name="YError",Error.captureStackTrace&&Error.captureStackTrace(this,e)}}let s,i=[];function n(t,o,a,h){s=h;let l={};if(Object.prototype.hasOwnProperty.call(t,"extends")){if("string"!=typeof t.extends)return l;const r=/\.json|\..*rc$/.test(t.extends);let h=null;if(r)h=function(t,e){return s.path.resolve(t,e)}(o,t.extends);else try{h=/*require.resolve*/(__nccwpck_require__(9167).resolve(t.extends))}catch(e){return t}!function(t){if(i.indexOf(t)>-1)throw new e(`Circular extended configurations: '${t}'.`)}(h),i.push(h),l=r?JSON.parse(s.readFileSync(h,"utf8")):__nccwpck_require__(9167)(t.extends),delete t.extends,l=n(l,s.path.dirname(h),a,s)}return i=[],a?r(l,t):Object.assign({},l,t)}function r(t,e){const s={};function i(t){return t&&"object"==typeof t&&!Array.isArray(t)}Object.assign(s,t);for(const n of Object.keys(e))i(e[n])&&i(s[n])?s[n]=r(t[n],e[n]):s[n]=e[n];return s}function o(t){const e=t.replace(/\s{2,}/g," ").split(/\s+(?![^[]*]|[^<]*>)/),s=/\.*[\][<>]/g,i=e.shift();if(!i)throw new Error(`No command found in: ${t}`);const n={cmd:i.replace(s,""),demanded:[],optional:[]};return e.forEach(((t,i)=>{let r=!1;t=t.replace(/\s/g,""),/\.+[\]>]/.test(t)&&i===e.length-1&&(r=!0),/^\[/.test(t)?n.optional.push({cmd:t.replace(s,"").split("|"),variadic:r}):n.demanded.push({cmd:t.replace(s,"").split("|"),variadic:r})})),n}const a=["first","second","third","fourth","fifth","sixth"];function h(t,s,i){try{let n=0;const[r,a,h]="object"==typeof t?[{demanded:[],optional:[]},t,s]:[o(`cmd ${t}`),s,i],f=[].slice.call(a);for(;f.length&&void 0===f[f.length-1];)f.pop();const d=h||f.length;if(d<r.demanded.length)throw new e(`Not enough arguments provided. Expected ${r.demanded.length} but received ${f.length}.`);const u=r.demanded.length+r.optional.length;if(d>u)throw new e(`Too many arguments provided. Expected max ${u} but received ${d}.`);r.demanded.forEach((t=>{const e=l(f.shift());0===t.cmd.filter((t=>t===e||"*"===t)).length&&c(e,t.cmd,n),n+=1})),r.optional.forEach((t=>{if(0===f.length)return;const e=l(f.shift());0===t.cmd.filter((t=>t===e||"*"===t)).length&&c(e,t.cmd,n),n+=1}))}catch(t){console.warn(t.stack)}}function l(t){return Array.isArray(t)?"array":null===t?"null":typeof t}function c(t,s,i){throw new e(`Invalid ${a[i]||"manyith"} argument. Expected ${s.join(" or ")} but received ${t}.`)}function f(t){return!!t&&!!t.then&&"function"==typeof t.then}function d(t,e,s,i){s.assert.notStrictEqual(t,e,i)}function u(t,e){e.assert.strictEqual(typeof t,"string")}function p(t){return Object.keys(t)}function g(t={},e=(()=>!0)){const s={};return p(t).forEach((i=>{e(i,t[i])&&(s[i]=t[i])})),s}function m(){return process.versions.electron&&!process.defaultApp?0:1}function y(){return process.argv[m()]}var b=Object.freeze({__proto__:null,hideBin:function(t){return t.slice(m()+1)},getProcessArgvBin:y});function v(t,e,s,i){if("a"===s&&!i)throw new TypeError("Private accessor was defined without a getter");if("function"==typeof e?t!==e||!i:!e.has(t))throw new TypeError("Cannot read private member from an object whose class did not declare it");return"m"===s?i:"a"===s?i.call(t):i?i.value:e.get(t)}function O(t,e,s,i,n){if("m"===i)throw new TypeError("Private method is not writable");if("a"===i&&!n)throw new TypeError("Private accessor was defined without a setter");if("function"==typeof e?t!==e||!n:!e.has(t))throw new TypeError("Cannot write private member to an object whose class did not declare it");return"a"===i?n.call(t,s):n?n.value=s:e.set(t,s),s}class w{constructor(t){this.globalMiddleware=[],this.frozens=[],this.yargs=t}addMiddleware(t,e,s=!0,i=!1){if(h("<array|function> [boolean] [boolean] [boolean]",[t,e,s],arguments.length),Array.isArray(t)){for(let i=0;i<t.length;i++){if("function"!=typeof t[i])throw Error("middleware must be a function");const n=t[i];n.applyBeforeValidation=e,n.global=s}Array.prototype.push.apply(this.globalMiddleware,t)}else if("function"==typeof t){const n=t;n.applyBeforeValidation=e,n.global=s,n.mutates=i,this.globalMiddleware.push(t)}return this.yargs}addCoerceMiddleware(t,e){const s=this.yargs.getAliases();return this.globalMiddleware=this.globalMiddleware.filter((t=>{const i=[...s[e]||[],e];return!t.option||!i.includes(t.option)})),t.option=e,this.addMiddleware(t,!0,!0,!0)}getMiddleware(){return this.globalMiddleware}freeze(){this.frozens.push([...this.globalMiddleware])}unfreeze(){const t=this.frozens.pop();void 0!==t&&(this.globalMiddleware=t)}reset(){this.globalMiddleware=this.globalMiddleware.filter((t=>t.global))}}function C(t,e,s,i){return s.reduce(((t,s)=>{if(s.applyBeforeValidation!==i)return t;if(s.mutates){if(s.applied)return t;s.applied=!0}if(f(t))return t.then((t=>Promise.all([t,s(t,e)]))).then((([t,e])=>Object.assign(t,e)));{const i=s(t,e);return f(i)?i.then((e=>Object.assign(t,e))):Object.assign(t,i)}}),t)}function j(t,e,s=(t=>{throw t})){try{const s="function"==typeof t?t():t;return f(s)?s.then((t=>e(t))):e(s)}catch(t){return s(t)}}const M=/(^\*)|(^\$0)/;class _{constructor(t,e,s,i){this.requireCache=new Set,this.handlers={},this.aliasMap={},this.frozens=[],this.shim=i,this.usage=t,this.globalMiddleware=s,this.validation=e}addDirectory(t,e,s,i){"boolean"!=typeof(i=i||{}).recurse&&(i.recurse=!1),Array.isArray(i.extensions)||(i.extensions=["js"]);const n="function"==typeof i.visit?i.visit:t=>t;i.visit=(t,e,s)=>{const i=n(t,e,s);if(i){if(this.requireCache.has(e))return i;this.requireCache.add(e),this.addHandler(i)}return i},this.shim.requireDirectory({require:e,filename:s},t,i)}addHandler(t,e,s,i,n,r){let a=[];const h=function(t){return t?t.map((t=>(t.applyBeforeValidation=!1,t))):[]}(n);if(i=i||(()=>{}),Array.isArray(t))if(function(t){return t.every((t=>"string"==typeof t))}(t))[t,...a]=t;else for(const e of t)this.addHandler(e);else{if(function(t){return"object"==typeof t&&!Array.isArray(t)}(t)){let e=Array.isArray(t.command)||"string"==typeof t.command?t.command:this.moduleName(t);return t.aliases&&(e=[].concat(e).concat(t.aliases)),void this.addHandler(e,this.extractDesc(t),t.builder,t.handler,t.middlewares,t.deprecated)}if(k(s))return void this.addHandler([t].concat(a),e,s.builder,s.handler,s.middlewares,s.deprecated)}if("string"==typeof t){const n=o(t);a=a.map((t=>o(t).cmd));let l=!1;const c=[n.cmd].concat(a).filter((t=>!M.test(t)||(l=!0,!1)));0===c.length&&l&&c.push("$0"),l&&(n.cmd=c[0],a=c.slice(1),t=t.replace(M,n.cmd)),a.forEach((t=>{this.aliasMap[t]=n.cmd})),!1!==e&&this.usage.command(t,e,l,a,r),this.handlers[n.cmd]={original:t,description:e,handler:i,builder:s||{},middlewares:h,deprecated:r,demanded:n.demanded,optional:n.optional},l&&(this.defaultCommand=this.handlers[n.cmd])}}getCommandHandlers(){return this.handlers}getCommands(){return Object.keys(this.handlers).concat(Object.keys(this.aliasMap))}hasDefaultCommand(){return!!this.defaultCommand}runCommand(t,e,s,i,n,r){const o=this.handlers[t]||this.handlers[this.aliasMap[t]]||this.defaultCommand,a=e.getInternalMethods().getContext(),h=a.commands.slice(),l=!t;t&&(a.commands.push(t),a.fullCommands.push(o.original));const c=this.applyBuilderUpdateUsageAndParse(l,o,e,s.aliases,h,i,n,r);return f(c)?c.then((t=>this.applyMiddlewareAndGetResult(l,o,t.innerArgv,a,n,t.aliases,e))):this.applyMiddlewareAndGetResult(l,o,c.innerArgv,a,n,c.aliases,e)}applyBuilderUpdateUsageAndParse(t,e,s,i,n,r,o,a){const h=e.builder;let l=s;if(x(h)){s.getInternalMethods().getUsageInstance().freeze();const c=h(s.getInternalMethods().reset(i),a);if(f(c))return c.then((i=>{var a;return l=(a=i)&&"function"==typeof a.getInternalMethods?i:s,this.parseAndUpdateUsage(t,e,l,n,r,o)}))}else(function(t){return"object"==typeof t})(h)&&(s.getInternalMethods().getUsageInstance().freeze(),l=s.getInternalMethods().reset(i),Object.keys(e.builder).forEach((t=>{l.option(t,h[t])})));return this.parseAndUpdateUsage(t,e,l,n,r,o)}parseAndUpdateUsage(t,e,s,i,n,r){t&&s.getInternalMethods().getUsageInstance().unfreeze(!0),this.shouldUpdateUsage(s)&&s.getInternalMethods().getUsageInstance().usage(this.usageFromParentCommandsCommandHandler(i,e),e.description);const o=s.getInternalMethods().runYargsParserAndExecuteCommands(null,void 0,!0,n,r);return f(o)?o.then((t=>({aliases:s.parsed.aliases,innerArgv:t}))):{aliases:s.parsed.aliases,innerArgv:o}}shouldUpdateUsage(t){return!t.getInternalMethods().getUsageInstance().getUsageDisabled()&&0===t.getInternalMethods().getUsageInstance().getUsage().length}usageFromParentCommandsCommandHandler(t,e){const s=M.test(e.original)?e.original.replace(M,"").trim():e.original,i=t.filter((t=>!M.test(t)));return i.push(s),`$0 ${i.join(" ")}`}handleValidationAndGetResult(t,e,s,i,n,r,o,a){if(!r.getInternalMethods().getHasOutput()){const e=r.getInternalMethods().runValidation(n,a,r.parsed.error,t);s=j(s,(t=>(e(t),t)))}if(e.handler&&!r.getInternalMethods().getHasOutput()){r.getInternalMethods().setHasOutput();const i=!!r.getOptions().configuration["populate--"];r.getInternalMethods().postProcess(s,i,!1,!1),s=j(s=C(s,r,o,!1),(t=>{const s=e.handler(t);return f(s)?s.then((()=>t)):t})),t||r.getInternalMethods().getUsageInstance().cacheHelpMessage(),f(s)&&!r.getInternalMethods().hasParseCallback()&&s.catch((t=>{try{r.getInternalMethods().getUsageInstance().fail(null,t)}catch(t){}}))}return t||(i.commands.pop(),i.fullCommands.pop()),s}applyMiddlewareAndGetResult(t,e,s,i,n,r,o){let a={};if(n)return s;o.getInternalMethods().getHasOutput()||(a=this.populatePositionals(e,s,i,o));const h=this.globalMiddleware.getMiddleware().slice(0).concat(e.middlewares),l=C(s,o,h,!0);return f(l)?l.then((s=>this.handleValidationAndGetResult(t,e,s,i,r,o,h,a))):this.handleValidationAndGetResult(t,e,l,i,r,o,h,a)}populatePositionals(t,e,s,i){e._=e._.slice(s.commands.length);const n=t.demanded.slice(0),r=t.optional.slice(0),o={};for(this.validation.positionalCount(n.length,e._.length);n.length;){const t=n.shift();this.populatePositional(t,e,o)}for(;r.length;){const t=r.shift();this.populatePositional(t,e,o)}return e._=s.commands.concat(e._.map((t=>""+t))),this.postProcessPositionals(e,o,this.cmdToParseOptions(t.original),i),o}populatePositional(t,e,s){const i=t.cmd[0];t.variadic?s[i]=e._.splice(0).map(String):e._.length&&(s[i]=[String(e._.shift())])}cmdToParseOptions(t){const e={array:[],default:{},alias:{},demand:{}},s=o(t);return s.demanded.forEach((t=>{const[s,...i]=t.cmd;t.variadic&&(e.array.push(s),e.default[s]=[]),e.alias[s]=i,e.demand[s]=!0})),s.optional.forEach((t=>{const[s,...i]=t.cmd;t.variadic&&(e.array.push(s),e.default[s]=[]),e.alias[s]=i})),e}postProcessPositionals(t,e,s,i){const n=Object.assign({},i.getOptions());n.default=Object.assign(s.default,n.default);for(const t of Object.keys(s.alias))n.alias[t]=(n.alias[t]||[]).concat(s.alias[t]);n.array=n.array.concat(s.array),n.config={};const r=[];if(Object.keys(e).forEach((t=>{e[t].map((e=>{n.configuration["unknown-options-as-args"]&&(n.key[t]=!0),r.push(`--${t}`),r.push(e)}))})),!r.length)return;const o=Object.assign({},n.configuration,{"populate--":!1}),a=this.shim.Parser.detailed(r,Object.assign({},n,{configuration:o}));if(a.error)i.getInternalMethods().getUsageInstance().fail(a.error.message,a.error);else{const s=Object.keys(e);Object.keys(e).forEach((t=>{s.push(...a.aliases[t])})),Object.keys(a.argv).forEach((n=>{s.includes(n)&&(e[n]||(e[n]=a.argv[n]),!this.isInConfigs(i,n)&&!this.isDefaulted(i,n)&&Object.prototype.hasOwnProperty.call(t,n)&&Object.prototype.hasOwnProperty.call(a.argv,n)&&(Array.isArray(t[n])||Array.isArray(a.argv[n]))?t[n]=[].concat(t[n],a.argv[n]):t[n]=a.argv[n])}))}}isDefaulted(t,e){const{default:s}=t.getOptions();return Object.prototype.hasOwnProperty.call(s,e)||Object.prototype.hasOwnProperty.call(s,this.shim.Parser.camelCase(e))}isInConfigs(t,e){const{configObjects:s}=t.getOptions();return s.some((t=>Object.prototype.hasOwnProperty.call(t,e)))||s.some((t=>Object.prototype.hasOwnProperty.call(t,this.shim.Parser.camelCase(e))))}runDefaultBuilderOn(t){if(!this.defaultCommand)return;if(this.shouldUpdateUsage(t)){const e=M.test(this.defaultCommand.original)?this.defaultCommand.original:this.defaultCommand.original.replace(/^[^[\]<>]*/,"$0 ");t.getInternalMethods().getUsageInstance().usage(e,this.defaultCommand.description)}const e=this.defaultCommand.builder;if(x(e))return e(t,!0);k(e)||Object.keys(e).forEach((s=>{t.option(s,e[s])}))}moduleName(t){const e=function(t){if(false){}for(let e,s=0,i=Object.keys(__nccwpck_require__.c);s<i.length;s++)if(e=__nccwpck_require__.c[i[s]],e.exports===t)return e;return null}(t);if(!e)throw new Error(`No command name given for module: ${this.shim.inspect(t)}`);return this.commandFromFilename(e.filename)}commandFromFilename(t){return this.shim.path.basename(t,this.shim.path.extname(t))}extractDesc({describe:t,description:e,desc:s}){for(const i of[t,e,s]){if("string"==typeof i||!1===i)return i;d(i,!0,this.shim)}return!1}freeze(){this.frozens.push({handlers:this.handlers,aliasMap:this.aliasMap,defaultCommand:this.defaultCommand})}unfreeze(){const t=this.frozens.pop();d(t,void 0,this.shim),({handlers:this.handlers,aliasMap:this.aliasMap,defaultCommand:this.defaultCommand}=t)}reset(){return this.handlers={},this.aliasMap={},this.defaultCommand=void 0,this.requireCache=new Set,this}}function k(t){return"object"==typeof t&&!!t.builder&&"function"==typeof t.handler}function x(t){return"function"==typeof t}function E(t){"undefined"!=typeof process&&[process.stdout,process.stderr].forEach((e=>{const s=e;s._handle&&s.isTTY&&"function"==typeof s._handle.setBlocking&&s._handle.setBlocking(t)}))}function A(t){return"boolean"==typeof t}function P(t,s){const i=s.y18n.__,n={},r=[];n.failFn=function(t){r.push(t)};let o=null,a=null,h=!0;n.showHelpOnFail=function(e=!0,s){const[i,r]="string"==typeof e?[!0,e]:[e,s];return t.getInternalMethods().isGlobalContext()&&(a=r),o=r,h=i,n};let l=!1;n.fail=function(s,i){const c=t.getInternalMethods().getLoggerInstance();if(!r.length){if(t.getExitProcess()&&E(!0),!l){l=!0,h&&(t.showHelp("error"),c.error()),(s||i)&&c.error(s||i);const e=o||a;e&&((s||i)&&c.error(""),c.error(e))}if(i=i||new e(s),t.getExitProcess())return t.exit(1);if(t.getInternalMethods().hasParseCallback())return t.exit(1,i);throw i}for(let t=r.length-1;t>=0;--t){const e=r[t];if(A(e)){if(i)throw i;if(s)throw Error(s)}else e(s,i,n)}};let c=[],f=!1;n.usage=(t,e)=>null===t?(f=!0,c=[],n):(f=!1,c.push([t,e||""]),n),n.getUsage=()=>c,n.getUsageDisabled=()=>f,n.getPositionalGroupName=()=>i("Positionals:");let d=[];n.example=(t,e)=>{d.push([t,e||""])};let u=[];n.command=function(t,e,s,i,n=!1){s&&(u=u.map((t=>(t[2]=!1,t)))),u.push([t,e||"",s,i,n])},n.getCommands=()=>u;let p={};n.describe=function(t,e){Array.isArray(t)?t.forEach((t=>{n.describe(t,e)})):"object"==typeof t?Object.keys(t).forEach((e=>{n.describe(e,t[e])})):p[t]=e},n.getDescriptions=()=>p;let m=[];n.epilog=t=>{m.push(t)};let y,b=!1;n.wrap=t=>{b=!0,y=t},n.getWrap=()=>s.getEnv("YARGS_DISABLE_WRAP")?null:(b||(y=function(){const t=80;return s.process.stdColumns?Math.min(t,s.process.stdColumns):t}(),b=!0),y);const v="__yargsString__:";function O(t,e,i){let n=0;return Array.isArray(t)||(t=Object.values(t).map((t=>[t]))),t.forEach((t=>{n=Math.max(s.stringWidth(i?`${i} ${I(t[0])}`:I(t[0]))+$(t[0]),n)})),e&&(n=Math.min(n,parseInt((.5*e).toString(),10))),n}let w;function C(e){return t.getOptions().hiddenOptions.indexOf(e)<0||t.parsed.argv[t.getOptions().showHiddenOpt]}function j(t,e){let s=`[${i("default:")} `;if(void 0===t&&!e)return null;if(e)s+=e;else switch(typeof t){case"string":s+=`"${t}"`;break;case"object":s+=JSON.stringify(t);break;default:s+=t}return`${s}]`}n.deferY18nLookup=t=>v+t,n.help=function(){if(w)return w;!function(){const e=t.getDemandedOptions(),s=t.getOptions();(Object.keys(s.alias)||[]).forEach((i=>{s.alias[i].forEach((r=>{p[r]&&n.describe(i,p[r]),r in e&&t.demandOption(i,e[r]),s.boolean.includes(r)&&t.boolean(i),s.count.includes(r)&&t.count(i),s.string.includes(r)&&t.string(i),s.normalize.includes(r)&&t.normalize(i),s.array.includes(r)&&t.array(i),s.number.includes(r)&&t.number(i)}))}))}();const e=t.customScriptName?t.$0:s.path.basename(t.$0),r=t.getDemandedOptions(),o=t.getDemandedCommands(),a=t.getDeprecatedOptions(),h=t.getGroups(),l=t.getOptions();let g=[];g=g.concat(Object.keys(p)),g=g.concat(Object.keys(r)),g=g.concat(Object.keys(o)),g=g.concat(Object.keys(l.default)),g=g.filter(C),g=Object.keys(g.reduce(((t,e)=>("_"!==e&&(t[e]=!0),t)),{}));const y=n.getWrap(),b=s.cliui({width:y,wrap:!!y});if(!f)if(c.length)c.forEach((t=>{b.div({text:`${t[0].replace(/\$0/g,e)}`}),t[1]&&b.div({text:`${t[1]}`,padding:[1,0,0,0]})})),b.div();else if(u.length){let t=null;t=o._?`${e} <${i("command")}>\n`:`${e} [${i("command")}]\n`,b.div(`${t}`)}if(u.length>1||1===u.length&&!u[0][2]){b.div(i("Commands:"));const s=t.getInternalMethods().getContext(),n=s.commands.length?`${s.commands.join(" ")} `:"";!0===t.getInternalMethods().getParserConfiguration()["sort-commands"]&&(u=u.sort(((t,e)=>t[0].localeCompare(e[0]))));const r=e?`${e} `:"";u.forEach((t=>{const s=`${r}${n}${t[0].replace(/^\$0 ?/,"")}`;b.span({text:s,padding:[0,2,0,2],width:O(u,y,`${e}${n}`)+4},{text:t[1]});const o=[];t[2]&&o.push(`[${i("default")}]`),t[3]&&t[3].length&&o.push(`[${i("aliases:")} ${t[3].join(", ")}]`),t[4]&&("string"==typeof t[4]?o.push(`[${i("deprecated: %s",t[4])}]`):o.push(`[${i("deprecated")}]`)),o.length?b.div({text:o.join(" "),padding:[0,0,0,2],align:"right"}):b.div()})),b.div()}const M=(Object.keys(l.alias)||[]).concat(Object.keys(t.parsed.newAliases)||[]);g=g.filter((e=>!t.parsed.newAliases[e]&&M.every((t=>-1===(l.alias[t]||[]).indexOf(e)))));const _=i("Options:");h[_]||(h[_]=[]),function(t,e,s,i){let n=[],r=null;Object.keys(s).forEach((t=>{n=n.concat(s[t])})),t.forEach((t=>{r=[t].concat(e[t]),r.some((t=>-1!==n.indexOf(t)))||s[i].push(t)}))}(g,l.alias,h,_);const k=t=>/^--/.test(I(t)),x=Object.keys(h).filter((t=>h[t].length>0)).map((t=>({groupName:t,normalizedKeys:h[t].filter(C).map((t=>{if(M.includes(t))return t;for(let e,s=0;void 0!==(e=M[s]);s++)if((l.alias[e]||[]).includes(t))return e;return t}))}))).filter((({normalizedKeys:t})=>t.length>0)).map((({groupName:t,normalizedKeys:e})=>{const s=e.reduce(((e,s)=>(e[s]=[s].concat(l.alias[s]||[]).map((e=>t===n.getPositionalGroupName()?e:(/^[0-9]$/.test(e)?l.boolean.includes(s)?"-":"--":e.length>1?"--":"-")+e)).sort(((t,e)=>k(t)===k(e)?0:k(t)?1:-1)).join(", "),e)),{});return{groupName:t,normalizedKeys:e,switches:s}}));if(x.filter((({groupName:t})=>t!==n.getPositionalGroupName())).some((({normalizedKeys:t,switches:e})=>!t.every((t=>k(e[t])))))&&x.filter((({groupName:t})=>t!==n.getPositionalGroupName())).forEach((({normalizedKeys:t,switches:e})=>{t.forEach((t=>{var s,i;k(e[t])&&(e[t]=(s=e[t],i=4,S(s)?{text:s.text,indentation:s.indentation+i}:{text:s,indentation:i}))}))})),x.forEach((({groupName:e,normalizedKeys:s,switches:o})=>{b.div(e),s.forEach((e=>{const s=o[e];let h=p[e]||"",c=null;h.includes(v)&&(h=i(h.substring(16))),l.boolean.includes(e)&&(c=`[${i("boolean")}]`),l.count.includes(e)&&(c=`[${i("count")}]`),l.string.includes(e)&&(c=`[${i("string")}]`),l.normalize.includes(e)&&(c=`[${i("string")}]`),l.array.includes(e)&&(c=`[${i("array")}]`),l.number.includes(e)&&(c=`[${i("number")}]`);const f=[e in a?(d=a[e],"string"==typeof d?`[${i("deprecated: %s",d)}]`:`[${i("deprecated")}]`):null,c,e in r?`[${i("required")}]`:null,l.choices&&l.choices[e]?`[${i("choices:")} ${n.stringifiedValues(l.choices[e])}]`:null,j(l.default[e],l.defaultDescription[e])].filter(Boolean).join(" ");var d;b.span({text:I(s),padding:[0,2,0,2+$(s)],width:O(o,y)+4},h);const u=!0===t.getInternalMethods().getUsageConfiguration()["hide-types"];f&&!u?b.div({text:f,padding:[0,0,0,2],align:"right"}):b.div()})),b.div()})),d.length&&(b.div(i("Examples:")),d.forEach((t=>{t[0]=t[0].replace(/\$0/g,e)})),d.forEach((t=>{""===t[1]?b.div({text:t[0],padding:[0,2,0,2]}):b.div({text:t[0],padding:[0,2,0,2],width:O(d,y)+4},{text:t[1]})})),b.div()),m.length>0){const t=m.map((t=>t.replace(/\$0/g,e))).join("\n");b.div(`${t}\n`)}return b.toString().replace(/\s*$/,"")},n.cacheHelpMessage=function(){w=this.help()},n.clearCachedHelpMessage=function(){w=void 0},n.hasCachedHelpMessage=function(){return!!w},n.showHelp=e=>{const s=t.getInternalMethods().getLoggerInstance();e||(e="error");("function"==typeof e?e:s[e])(n.help())},n.functionDescription=t=>["(",t.name?s.Parser.decamelize(t.name,"-"):i("generated-value"),")"].join(""),n.stringifiedValues=function(t,e){let s="";const i=e||", ",n=[].concat(t);return t&&n.length?(n.forEach((t=>{s.length&&(s+=i),s+=JSON.stringify(t)})),s):s};let M=null;n.version=t=>{M=t},n.showVersion=e=>{const s=t.getInternalMethods().getLoggerInstance();e||(e="error");("function"==typeof e?e:s[e])(M)},n.reset=function(t){return o=null,l=!1,c=[],f=!1,m=[],d=[],u=[],p=g(p,(e=>!t[e])),n};const _=[];return n.freeze=function(){_.push({failMessage:o,failureOutput:l,usages:c,usageDisabled:f,epilogs:m,examples:d,commands:u,descriptions:p})},n.unfreeze=function(t=!1){const e=_.pop();e&&(t?(p={...e.descriptions,...p},u=[...e.commands,...u],c=[...e.usages,...c],d=[...e.examples,...d],m=[...e.epilogs,...m]):({failMessage:o,failureOutput:l,usages:c,usageDisabled:f,epilogs:m,examples:d,commands:u,descriptions:p}=e))},n}function S(t){return"object"==typeof t}function $(t){return S(t)?t.indentation:0}function I(t){return S(t)?t.text:t}class D{constructor(t,e,s,i){var n,r,o;this.yargs=t,this.usage=e,this.command=s,this.shim=i,this.completionKey="get-yargs-completions",this.aliases=null,this.customCompletionFunction=null,this.indexAfterLastReset=0,this.zshShell=null!==(o=(null===(n=this.shim.getEnv("SHELL"))||void 0===n?void 0:n.includes("zsh"))||(null===(r=this.shim.getEnv("ZSH_NAME"))||void 0===r?void 0:r.includes("zsh")))&&void 0!==o&&o}defaultCompletion(t,e,s,i){const n=this.command.getCommandHandlers();for(let e=0,s=t.length;e<s;++e)if(n[t[e]]&&n[t[e]].builder){const s=n[t[e]].builder;if(x(s)){this.indexAfterLastReset=e+1;const t=this.yargs.getInternalMethods().reset();return s(t,!0),t.argv}}const r=[];this.commandCompletions(r,t,s),this.optionCompletions(r,t,e,s),this.choicesFromOptionsCompletions(r,t,e,s),this.choicesFromPositionalsCompletions(r,t,e,s),i(null,r)}commandCompletions(t,e,s){const i=this.yargs.getInternalMethods().getContext().commands;s.match(/^-/)||i[i.length-1]===s||this.previousArgHasChoices(e)||this.usage.getCommands().forEach((s=>{const i=o(s[0]).cmd;if(-1===e.indexOf(i))if(this.zshShell){const e=s[1]||"";t.push(i.replace(/:/g,"\\:")+":"+e)}else t.push(i)}))}optionCompletions(t,e,s,i){if((i.match(/^-/)||""===i&&0===t.length)&&!this.previousArgHasChoices(e)){const s=this.yargs.getOptions(),n=this.yargs.getGroups()[this.usage.getPositionalGroupName()]||[];Object.keys(s.key).forEach((r=>{const o=!!s.configuration["boolean-negation"]&&s.boolean.includes(r);n.includes(r)||s.hiddenOptions.includes(r)||this.argsContainKey(e,r,o)||this.completeOptionKey(r,t,i,o&&!!s.default[r])}))}}choicesFromOptionsCompletions(t,e,s,i){if(this.previousArgHasChoices(e)){const s=this.getPreviousArgChoices(e);s&&s.length>0&&t.push(...s.map((t=>t.replace(/:/g,"\\:"))))}}choicesFromPositionalsCompletions(t,e,s,i){if(""===i&&t.length>0&&this.previousArgHasChoices(e))return;const n=this.yargs.getGroups()[this.usage.getPositionalGroupName()]||[],r=Math.max(this.indexAfterLastReset,this.yargs.getInternalMethods().getContext().commands.length+1),o=n[s._.length-r-1];if(!o)return;const a=this.yargs.getOptions().choices[o]||[];for(const e of a)e.startsWith(i)&&t.push(e.replace(/:/g,"\\:"))}getPreviousArgChoices(t){if(t.length<1)return;let e=t[t.length-1],s="";if(!e.startsWith("-")&&t.length>1&&(s=e,e=t[t.length-2]),!e.startsWith("-"))return;const i=e.replace(/^-+/,""),n=this.yargs.getOptions(),r=[i,...this.yargs.getAliases()[i]||[]];let o;for(const t of r)if(Object.prototype.hasOwnProperty.call(n.key,t)&&Array.isArray(n.choices[t])){o=n.choices[t];break}return o?o.filter((t=>!s||t.startsWith(s))):void 0}previousArgHasChoices(t){const e=this.getPreviousArgChoices(t);return void 0!==e&&e.length>0}argsContainKey(t,e,s){const i=e=>-1!==t.indexOf((/^[^0-9]$/.test(e)?"-":"--")+e);if(i(e))return!0;if(s&&i(`no-${e}`))return!0;if(this.aliases)for(const t of this.aliases[e])if(i(t))return!0;return!1}completeOptionKey(t,e,s,i){var n,r,o,a;let h=t;if(this.zshShell){const e=this.usage.getDescriptions(),s=null===(r=null===(n=null==this?void 0:this.aliases)||void 0===n?void 0:n[t])||void 0===r?void 0:r.find((t=>{const s=e[t];return"string"==typeof s&&s.length>0})),i=s?e[s]:void 0,l=null!==(a=null!==(o=e[t])&&void 0!==o?o:i)&&void 0!==a?a:"";h=`${t.replace(/:/g,"\\:")}:${l.replace("__yargsString__:","").replace(/(\r\n|\n|\r)/gm," ")}`}const l=!/^--/.test(s)&&(t=>/^[^0-9]$/.test(t))(t)?"-":"--";e.push(l+h),i&&e.push(l+"no-"+h)}customCompletion(t,e,s,i){if(d(this.customCompletionFunction,null,this.shim),this.customCompletionFunction.length<3){const t=this.customCompletionFunction(s,e);return f(t)?t.then((t=>{this.shim.process.nextTick((()=>{i(null,t)}))})).catch((t=>{this.shim.process.nextTick((()=>{i(t,void 0)}))})):i(null,t)}return function(t){return t.length>3}(this.customCompletionFunction)?this.customCompletionFunction(s,e,((n=i)=>this.defaultCompletion(t,e,s,n)),(t=>{i(null,t)})):this.customCompletionFunction(s,e,(t=>{i(null,t)}))}getCompletion(t,e){const s=t.length?t[t.length-1]:"",i=this.yargs.parse(t,!0),n=this.customCompletionFunction?i=>this.customCompletion(t,i,s,e):i=>this.defaultCompletion(t,i,s,e);return f(i)?i.then(n):n(i)}generateCompletionScript(t,e){let s=this.zshShell?'#compdef {{app_name}}\n###-begin-{{app_name}}-completions-###\n#\n# yargs command completion script\n#\n# Installation: {{app_path}} {{completion_command}} >> ~/.zshrc\n#    or {{app_path}} {{completion_command}} >> ~/.zprofile on OSX.\n#\n_{{app_name}}_yargs_completions()\n{\n  local reply\n  local si=$IFS\n  IFS=$\'\n\' reply=($(COMP_CWORD="$((CURRENT-1))" COMP_LINE="$BUFFER" COMP_POINT="$CURSOR" {{app_path}} --get-yargs-completions "${words[@]}"))\n  IFS=$si\n  _describe \'values\' reply\n}\ncompdef _{{app_name}}_yargs_completions {{app_name}}\n###-end-{{app_name}}-completions-###\n':'###-begin-{{app_name}}-completions-###\n#\n# yargs command completion script\n#\n# Installation: {{app_path}} {{completion_command}} >> ~/.bashrc\n#    or {{app_path}} {{completion_command}} >> ~/.bash_profile on OSX.\n#\n_{{app_name}}_yargs_completions()\n{\n    local cur_word args type_list\n\n    cur_word="${COMP_WORDS[COMP_CWORD]}"\n    args=("${COMP_WORDS[@]}")\n\n    # ask yargs to generate completions.\n    type_list=$({{app_path}} --get-yargs-completions "${args[@]}")\n\n    COMPREPLY=( $(compgen -W "${type_list}" -- ${cur_word}) )\n\n    # if no match was found, fall back to filename completion\n    if [ ${#COMPREPLY[@]} -eq 0 ]; then\n      COMPREPLY=()\n    fi\n\n    return 0\n}\ncomplete -o bashdefault -o default -F _{{app_name}}_yargs_completions {{app_name}}\n###-end-{{app_name}}-completions-###\n';const i=this.shim.path.basename(t);return t.match(/\.js$/)&&(t=`./${t}`),s=s.replace(/{{app_name}}/g,i),s=s.replace(/{{completion_command}}/g,e),s.replace(/{{app_path}}/g,t)}registerFunction(t){this.customCompletionFunction=t}setParsed(t){this.aliases=t.aliases}}function N(t,e){if(0===t.length)return e.length;if(0===e.length)return t.length;const s=[];let i,n;for(i=0;i<=e.length;i++)s[i]=[i];for(n=0;n<=t.length;n++)s[0][n]=n;for(i=1;i<=e.length;i++)for(n=1;n<=t.length;n++)e.charAt(i-1)===t.charAt(n-1)?s[i][n]=s[i-1][n-1]:i>1&&n>1&&e.charAt(i-2)===t.charAt(n-1)&&e.charAt(i-1)===t.charAt(n-2)?s[i][n]=s[i-2][n-2]+1:s[i][n]=Math.min(s[i-1][n-1]+1,Math.min(s[i][n-1]+1,s[i-1][n]+1));return s[e.length][t.length]}const H=["$0","--","_"];var z,W,q,U,F,L,V,G,R,T,B,Y,K,J,Z,X,Q,tt,et,st,it,nt,rt,ot,at,ht,lt,ct,ft,dt,ut,pt,gt,mt,yt;const bt=Symbol("copyDoubleDash"),vt=Symbol("copyDoubleDash"),Ot=Symbol("deleteFromParserHintObject"),wt=Symbol("emitWarning"),Ct=Symbol("freeze"),jt=Symbol("getDollarZero"),Mt=Symbol("getParserConfiguration"),_t=Symbol("getUsageConfiguration"),kt=Symbol("guessLocale"),xt=Symbol("guessVersion"),Et=Symbol("parsePositionalNumbers"),At=Symbol("pkgUp"),Pt=Symbol("populateParserHintArray"),St=Symbol("populateParserHintSingleValueDictionary"),$t=Symbol("populateParserHintArrayDictionary"),It=Symbol("populateParserHintDictionary"),Dt=Symbol("sanitizeKey"),Nt=Symbol("setKey"),Ht=Symbol("unfreeze"),zt=Symbol("validateAsync"),Wt=Symbol("getCommandInstance"),qt=Symbol("getContext"),Ut=Symbol("getHasOutput"),Ft=Symbol("getLoggerInstance"),Lt=Symbol("getParseContext"),Vt=Symbol("getUsageInstance"),Gt=Symbol("getValidationInstance"),Rt=Symbol("hasParseCallback"),Tt=Symbol("isGlobalContext"),Bt=Symbol("postProcess"),Yt=Symbol("rebase"),Kt=Symbol("reset"),Jt=Symbol("runYargsParserAndExecuteCommands"),Zt=Symbol("runValidation"),Xt=Symbol("setHasOutput"),Qt=Symbol("kTrackManuallySetKeys");class te{constructor(t=[],e,s,i){this.customScriptName=!1,this.parsed=!1,z.set(this,void 0),W.set(this,void 0),q.set(this,{commands:[],fullCommands:[]}),U.set(this,null),F.set(this,null),L.set(this,"show-hidden"),V.set(this,null),G.set(this,!0),R.set(this,{}),T.set(this,!0),B.set(this,[]),Y.set(this,void 0),K.set(this,{}),J.set(this,!1),Z.set(this,null),X.set(this,!0),Q.set(this,void 0),tt.set(this,""),et.set(this,void 0),st.set(this,void 0),it.set(this,{}),nt.set(this,null),rt.set(this,null),ot.set(this,{}),at.set(this,{}),ht.set(this,void 0),lt.set(this,!1),ct.set(this,void 0),ft.set(this,!1),dt.set(this,!1),ut.set(this,!1),pt.set(this,void 0),gt.set(this,{}),mt.set(this,null),yt.set(this,void 0),O(this,ct,i,"f"),O(this,ht,t,"f"),O(this,W,e,"f"),O(this,st,s,"f"),O(this,Y,new w(this),"f"),this.$0=this[jt](),this[Kt](),O(this,z,v(this,z,"f"),"f"),O(this,pt,v(this,pt,"f"),"f"),O(this,yt,v(this,yt,"f"),"f"),O(this,et,v(this,et,"f"),"f"),v(this,et,"f").showHiddenOpt=v(this,L,"f"),O(this,Q,this[vt](),"f")}addHelpOpt(t,e){return h("[string|boolean] [string]",[t,e],arguments.length),v(this,Z,"f")&&(this[Ot](v(this,Z,"f")),O(this,Z,null,"f")),!1===t&&void 0===e||(O(this,Z,"string"==typeof t?t:"help","f"),this.boolean(v(this,Z,"f")),this.describe(v(this,Z,"f"),e||v(this,pt,"f").deferY18nLookup("Show help"))),this}help(t,e){return this.addHelpOpt(t,e)}addShowHiddenOpt(t,e){if(h("[string|boolean] [string]",[t,e],arguments.length),!1===t&&void 0===e)return this;const s="string"==typeof t?t:v(this,L,"f");return this.boolean(s),this.describe(s,e||v(this,pt,"f").deferY18nLookup("Show hidden options")),v(this,et,"f").showHiddenOpt=s,this}showHidden(t,e){return this.addShowHiddenOpt(t,e)}alias(t,e){return h("<object|string|array> [string|array]",[t,e],arguments.length),this[$t](this.alias.bind(this),"alias",t,e),this}array(t){return h("<array|string>",[t],arguments.length),this[Pt]("array",t),this[Qt](t),this}boolean(t){return h("<array|string>",[t],arguments.length),this[Pt]("boolean",t),this[Qt](t),this}check(t,e){return h("<function> [boolean]",[t,e],arguments.length),this.middleware(((e,s)=>j((()=>t(e,s.getOptions())),(s=>(s?("string"==typeof s||s instanceof Error)&&v(this,pt,"f").fail(s.toString(),s):v(this,pt,"f").fail(v(this,ct,"f").y18n.__("Argument check failed: %s",t.toString())),e)),(t=>(v(this,pt,"f").fail(t.message?t.message:t.toString(),t),e)))),!1,e),this}choices(t,e){return h("<object|string|array> [string|array]",[t,e],arguments.length),this[$t](this.choices.bind(this),"choices",t,e),this}coerce(t,s){if(h("<object|string|array> [function]",[t,s],arguments.length),Array.isArray(t)){if(!s)throw new e("coerce callback must be provided");for(const e of t)this.coerce(e,s);return this}if("object"==typeof t){for(const e of Object.keys(t))this.coerce(e,t[e]);return this}if(!s)throw new e("coerce callback must be provided");return v(this,et,"f").key[t]=!0,v(this,Y,"f").addCoerceMiddleware(((i,n)=>{let r;return Object.prototype.hasOwnProperty.call(i,t)?j((()=>(r=n.getAliases(),s(i[t]))),(e=>{i[t]=e;const s=n.getInternalMethods().getParserConfiguration()["strip-aliased"];if(r[t]&&!0!==s)for(const s of r[t])i[s]=e;return i}),(t=>{throw new e(t.message)})):i}),t),this}conflicts(t,e){return h("<string|object> [string|array]",[t,e],arguments.length),v(this,yt,"f").conflicts(t,e),this}config(t="config",e,s){return h("[object|string] [string|function] [function]",[t,e,s],arguments.length),"object"!=typeof t||Array.isArray(t)?("function"==typeof e&&(s=e,e=void 0),this.describe(t,e||v(this,pt,"f").deferY18nLookup("Path to JSON config file")),(Array.isArray(t)?t:[t]).forEach((t=>{v(this,et,"f").config[t]=s||!0})),this):(t=n(t,v(this,W,"f"),this[Mt]()["deep-merge-config"]||!1,v(this,ct,"f")),v(this,et,"f").configObjects=(v(this,et,"f").configObjects||[]).concat(t),this)}completion(t,e,s){return h("[string] [string|boolean|function] [function]",[t,e,s],arguments.length),"function"==typeof e&&(s=e,e=void 0),O(this,F,t||v(this,F,"f")||"completion","f"),e||!1===e||(e="generate completion script"),this.command(v(this,F,"f"),e),s&&v(this,U,"f").registerFunction(s),this}command(t,e,s,i,n,r){return h("<string|array|object> [string|boolean] [function|object] [function] [array] [boolean|string]",[t,e,s,i,n,r],arguments.length),v(this,z,"f").addHandler(t,e,s,i,n,r),this}commands(t,e,s,i,n,r){return this.command(t,e,s,i,n,r)}commandDir(t,e){h("<string> [object]",[t,e],arguments.length);const s=v(this,st,"f")||v(this,ct,"f").require;return v(this,z,"f").addDirectory(t,s,v(this,ct,"f").getCallerFile(),e),this}count(t){return h("<array|string>",[t],arguments.length),this[Pt]("count",t),this[Qt](t),this}default(t,e,s){return h("<object|string|array> [*] [string]",[t,e,s],arguments.length),s&&(u(t,v(this,ct,"f")),v(this,et,"f").defaultDescription[t]=s),"function"==typeof e&&(u(t,v(this,ct,"f")),v(this,et,"f").defaultDescription[t]||(v(this,et,"f").defaultDescription[t]=v(this,pt,"f").functionDescription(e)),e=e.call()),this[St](this.default.bind(this),"default",t,e),this}defaults(t,e,s){return this.default(t,e,s)}demandCommand(t=1,e,s,i){return h("[number] [number|string] [string|null|undefined] [string|null|undefined]",[t,e,s,i],arguments.length),"number"!=typeof e&&(s=e,e=1/0),this.global("_",!1),v(this,et,"f").demandedCommands._={min:t,max:e,minMsg:s,maxMsg:i},this}demand(t,e,s){return Array.isArray(e)?(e.forEach((t=>{d(s,!0,v(this,ct,"f")),this.demandOption(t,s)})),e=1/0):"number"!=typeof e&&(s=e,e=1/0),"number"==typeof t?(d(s,!0,v(this,ct,"f")),this.demandCommand(t,e,s,s)):Array.isArray(t)?t.forEach((t=>{d(s,!0,v(this,ct,"f")),this.demandOption(t,s)})):"string"==typeof s?this.demandOption(t,s):!0!==s&&void 0!==s||this.demandOption(t),this}demandOption(t,e){return h("<object|string|array> [string]",[t,e],arguments.length),this[St](this.demandOption.bind(this),"demandedOptions",t,e),this}deprecateOption(t,e){return h("<string> [string|boolean]",[t,e],arguments.length),v(this,et,"f").deprecatedOptions[t]=e,this}describe(t,e){return h("<object|string|array> [string]",[t,e],arguments.length),this[Nt](t,!0),v(this,pt,"f").describe(t,e),this}detectLocale(t){return h("<boolean>",[t],arguments.length),O(this,G,t,"f"),this}env(t){return h("[string|boolean]",[t],arguments.length),!1===t?delete v(this,et,"f").envPrefix:v(this,et,"f").envPrefix=t||"",this}epilogue(t){return h("<string>",[t],arguments.length),v(this,pt,"f").epilog(t),this}epilog(t){return this.epilogue(t)}example(t,e){return h("<string|array> [string]",[t,e],arguments.length),Array.isArray(t)?t.forEach((t=>this.example(...t))):v(this,pt,"f").example(t,e),this}exit(t,e){O(this,J,!0,"f"),O(this,V,e,"f"),v(this,T,"f")&&v(this,ct,"f").process.exit(t)}exitProcess(t=!0){return h("[boolean]",[t],arguments.length),O(this,T,t,"f"),this}fail(t){if(h("<function|boolean>",[t],arguments.length),"boolean"==typeof t&&!1!==t)throw new e("Invalid first argument. Expected function or boolean 'false'");return v(this,pt,"f").failFn(t),this}getAliases(){return this.parsed?this.parsed.aliases:{}}async getCompletion(t,e){return h("<array> [function]",[t,e],arguments.length),e?v(this,U,"f").getCompletion(t,e):new Promise(((e,s)=>{v(this,U,"f").getCompletion(t,((t,i)=>{t?s(t):e(i)}))}))}getDemandedOptions(){return h([],0),v(this,et,"f").demandedOptions}getDemandedCommands(){return h([],0),v(this,et,"f").demandedCommands}getDeprecatedOptions(){return h([],0),v(this,et,"f").deprecatedOptions}getDetectLocale(){return v(this,G,"f")}getExitProcess(){return v(this,T,"f")}getGroups(){return Object.assign({},v(this,K,"f"),v(this,at,"f"))}getHelp(){if(O(this,J,!0,"f"),!v(this,pt,"f").hasCachedHelpMessage()){if(!this.parsed){const t=this[Jt](v(this,ht,"f"),void 0,void 0,0,!0);if(f(t))return t.then((()=>v(this,pt,"f").help()))}const t=v(this,z,"f").runDefaultBuilderOn(this);if(f(t))return t.then((()=>v(this,pt,"f").help()))}return Promise.resolve(v(this,pt,"f").help())}getOptions(){return v(this,et,"f")}getStrict(){return v(this,ft,"f")}getStrictCommands(){return v(this,dt,"f")}getStrictOptions(){return v(this,ut,"f")}global(t,e){return h("<string|array> [boolean]",[t,e],arguments.length),t=[].concat(t),!1!==e?v(this,et,"f").local=v(this,et,"f").local.filter((e=>-1===t.indexOf(e))):t.forEach((t=>{v(this,et,"f").local.includes(t)||v(this,et,"f").local.push(t)})),this}group(t,e){h("<string|array> <string>",[t,e],arguments.length);const s=v(this,at,"f")[e]||v(this,K,"f")[e];v(this,at,"f")[e]&&delete v(this,at,"f")[e];const i={};return v(this,K,"f")[e]=(s||[]).concat(t).filter((t=>!i[t]&&(i[t]=!0))),this}hide(t){return h("<string>",[t],arguments.length),v(this,et,"f").hiddenOptions.push(t),this}implies(t,e){return h("<string|object> [number|string|array]",[t,e],arguments.length),v(this,yt,"f").implies(t,e),this}locale(t){return h("[string]",[t],arguments.length),void 0===t?(this[kt](),v(this,ct,"f").y18n.getLocale()):(O(this,G,!1,"f"),v(this,ct,"f").y18n.setLocale(t),this)}middleware(t,e,s){return v(this,Y,"f").addMiddleware(t,!!e,s)}nargs(t,e){return h("<string|object|array> [number]",[t,e],arguments.length),this[St](this.nargs.bind(this),"narg",t,e),this}normalize(t){return h("<array|string>",[t],arguments.length),this[Pt]("normalize",t),this}number(t){return h("<array|string>",[t],arguments.length),this[Pt]("number",t),this[Qt](t),this}option(t,e){if(h("<string|object> [object]",[t,e],arguments.length),"object"==typeof t)Object.keys(t).forEach((e=>{this.options(e,t[e])}));else{"object"!=typeof e&&(e={}),this[Qt](t),!v(this,mt,"f")||"version"!==t&&"version"!==(null==e?void 0:e.alias)||this[wt](['"version" is a reserved word.',"Please do one of the following:",'- Disable version with `yargs.version(false)` if using "version" as an option',"- Use the built-in `yargs.version` method instead (if applicable)","- Use a different option key","https://yargs.js.org/docs/#api-reference-version"].join("\n"),void 0,"versionWarning"),v(this,et,"f").key[t]=!0,e.alias&&this.alias(t,e.alias);const s=e.deprecate||e.deprecated;s&&this.deprecateOption(t,s);const i=e.demand||e.required||e.require;i&&this.demand(t,i),e.demandOption&&this.demandOption(t,"string"==typeof e.demandOption?e.demandOption:void 0),e.conflicts&&this.conflicts(t,e.conflicts),"default"in e&&this.default(t,e.default),void 0!==e.implies&&this.implies(t,e.implies),void 0!==e.nargs&&this.nargs(t,e.nargs),e.config&&this.config(t,e.configParser),e.normalize&&this.normalize(t),e.choices&&this.choices(t,e.choices),e.coerce&&this.coerce(t,e.coerce),e.group&&this.group(t,e.group),(e.boolean||"boolean"===e.type)&&(this.boolean(t),e.alias&&this.boolean(e.alias)),(e.array||"array"===e.type)&&(this.array(t),e.alias&&this.array(e.alias)),(e.number||"number"===e.type)&&(this.number(t),e.alias&&this.number(e.alias)),(e.string||"string"===e.type)&&(this.string(t),e.alias&&this.string(e.alias)),(e.count||"count"===e.type)&&this.count(t),"boolean"==typeof e.global&&this.global(t,e.global),e.defaultDescription&&(v(this,et,"f").defaultDescription[t]=e.defaultDescription),e.skipValidation&&this.skipValidation(t);const n=e.describe||e.description||e.desc,r=v(this,pt,"f").getDescriptions();Object.prototype.hasOwnProperty.call(r,t)&&"string"!=typeof n||this.describe(t,n),e.hidden&&this.hide(t),e.requiresArg&&this.requiresArg(t)}return this}options(t,e){return this.option(t,e)}parse(t,e,s){h("[string|array] [function|boolean|object] [function]",[t,e,s],arguments.length),this[Ct](),void 0===t&&(t=v(this,ht,"f")),"object"==typeof e&&(O(this,rt,e,"f"),e=s),"function"==typeof e&&(O(this,nt,e,"f"),e=!1),e||O(this,ht,t,"f"),v(this,nt,"f")&&O(this,T,!1,"f");const i=this[Jt](t,!!e),n=this.parsed;return v(this,U,"f").setParsed(this.parsed),f(i)?i.then((t=>(v(this,nt,"f")&&v(this,nt,"f").call(this,v(this,V,"f"),t,v(this,tt,"f")),t))).catch((t=>{throw v(this,nt,"f")&&v(this,nt,"f")(t,this.parsed.argv,v(this,tt,"f")),t})).finally((()=>{this[Ht](),this.parsed=n})):(v(this,nt,"f")&&v(this,nt,"f").call(this,v(this,V,"f"),i,v(this,tt,"f")),this[Ht](),this.parsed=n,i)}parseAsync(t,e,s){const i=this.parse(t,e,s);return f(i)?i:Promise.resolve(i)}parseSync(t,s,i){const n=this.parse(t,s,i);if(f(n))throw new e(".parseSync() must not be used with asynchronous builders, handlers, or middleware");return n}parserConfiguration(t){return h("<object>",[t],arguments.length),O(this,it,t,"f"),this}pkgConf(t,e){h("<string> [string]",[t,e],arguments.length);let s=null;const i=this[At](e||v(this,W,"f"));return i[t]&&"object"==typeof i[t]&&(s=n(i[t],e||v(this,W,"f"),this[Mt]()["deep-merge-config"]||!1,v(this,ct,"f")),v(this,et,"f").configObjects=(v(this,et,"f").configObjects||[]).concat(s)),this}positional(t,e){h("<string> <object>",[t,e],arguments.length);const s=["default","defaultDescription","implies","normalize","choices","conflicts","coerce","type","describe","desc","description","alias"];e=g(e,((t,e)=>!("type"===t&&!["string","number","boolean"].includes(e))&&s.includes(t)));const i=v(this,q,"f").fullCommands[v(this,q,"f").fullCommands.length-1],n=i?v(this,z,"f").cmdToParseOptions(i):{array:[],alias:{},default:{},demand:{}};return p(n).forEach((s=>{const i=n[s];Array.isArray(i)?-1!==i.indexOf(t)&&(e[s]=!0):i[t]&&!(s in e)&&(e[s]=i[t])})),this.group(t,v(this,pt,"f").getPositionalGroupName()),this.option(t,e)}recommendCommands(t=!0){return h("[boolean]",[t],arguments.length),O(this,lt,t,"f"),this}required(t,e,s){return this.demand(t,e,s)}require(t,e,s){return this.demand(t,e,s)}requiresArg(t){return h("<array|string|object> [number]",[t],arguments.length),"string"==typeof t&&v(this,et,"f").narg[t]||this[St](this.requiresArg.bind(this),"narg",t,NaN),this}showCompletionScript(t,e){return h("[string] [string]",[t,e],arguments.length),t=t||this.$0,v(this,Q,"f").log(v(this,U,"f").generateCompletionScript(t,e||v(this,F,"f")||"completion")),this}showHelp(t){if(h("[string|function]",[t],arguments.length),O(this,J,!0,"f"),!v(this,pt,"f").hasCachedHelpMessage()){if(!this.parsed){const e=this[Jt](v(this,ht,"f"),void 0,void 0,0,!0);if(f(e))return e.then((()=>{v(this,pt,"f").showHelp(t)})),this}const e=v(this,z,"f").runDefaultBuilderOn(this);if(f(e))return e.then((()=>{v(this,pt,"f").showHelp(t)})),this}return v(this,pt,"f").showHelp(t),this}scriptName(t){return this.customScriptName=!0,this.$0=t,this}showHelpOnFail(t,e){return h("[boolean|string] [string]",[t,e],arguments.length),v(this,pt,"f").showHelpOnFail(t,e),this}showVersion(t){return h("[string|function]",[t],arguments.length),v(this,pt,"f").showVersion(t),this}skipValidation(t){return h("<array|string>",[t],arguments.length),this[Pt]("skipValidation",t),this}strict(t){return h("[boolean]",[t],arguments.length),O(this,ft,!1!==t,"f"),this}strictCommands(t){return h("[boolean]",[t],arguments.length),O(this,dt,!1!==t,"f"),this}strictOptions(t){return h("[boolean]",[t],arguments.length),O(this,ut,!1!==t,"f"),this}string(t){return h("<array|string>",[t],arguments.length),this[Pt]("string",t),this[Qt](t),this}terminalWidth(){return h([],0),v(this,ct,"f").process.stdColumns}updateLocale(t){return this.updateStrings(t)}updateStrings(t){return h("<object>",[t],arguments.length),O(this,G,!1,"f"),v(this,ct,"f").y18n.updateLocale(t),this}usage(t,s,i,n){if(h("<string|null|undefined> [string|boolean] [function|object] [function]",[t,s,i,n],arguments.length),void 0!==s){if(d(t,null,v(this,ct,"f")),(t||"").match(/^\$0( |$)/))return this.command(t,s,i,n);throw new e(".usage() description must start with $0 if being used as alias for .command()")}return v(this,pt,"f").usage(t),this}usageConfiguration(t){return h("<object>",[t],arguments.length),O(this,gt,t,"f"),this}version(t,e,s){const i="version";if(h("[boolean|string] [string] [string]",[t,e,s],arguments.length),v(this,mt,"f")&&(this[Ot](v(this,mt,"f")),v(this,pt,"f").version(void 0),O(this,mt,null,"f")),0===arguments.length)s=this[xt](),t=i;else if(1===arguments.length){if(!1===t)return this;s=t,t=i}else 2===arguments.length&&(s=e,e=void 0);return O(this,mt,"string"==typeof t?t:i,"f"),e=e||v(this,pt,"f").deferY18nLookup("Show version number"),v(this,pt,"f").version(s||void 0),this.boolean(v(this,mt,"f")),this.describe(v(this,mt,"f"),e),this}wrap(t){return h("<number|null|undefined>",[t],arguments.length),v(this,pt,"f").wrap(t),this}[(z=new WeakMap,W=new WeakMap,q=new WeakMap,U=new WeakMap,F=new WeakMap,L=new WeakMap,V=new WeakMap,G=new WeakMap,R=new WeakMap,T=new WeakMap,B=new WeakMap,Y=new WeakMap,K=new WeakMap,J=new WeakMap,Z=new WeakMap,X=new WeakMap,Q=new WeakMap,tt=new WeakMap,et=new WeakMap,st=new WeakMap,it=new WeakMap,nt=new WeakMap,rt=new WeakMap,ot=new WeakMap,at=new WeakMap,ht=new WeakMap,lt=new WeakMap,ct=new WeakMap,ft=new WeakMap,dt=new WeakMap,ut=new WeakMap,pt=new WeakMap,gt=new WeakMap,mt=new WeakMap,yt=new WeakMap,bt)](t){if(!t._||!t["--"])return t;t._.push.apply(t._,t["--"]);try{delete t["--"]}catch(t){}return t}[vt](){return{log:(...t)=>{this[Rt]()||console.log(...t),O(this,J,!0,"f"),v(this,tt,"f").length&&O(this,tt,v(this,tt,"f")+"\n","f"),O(this,tt,v(this,tt,"f")+t.join(" "),"f")},error:(...t)=>{this[Rt]()||console.error(...t),O(this,J,!0,"f"),v(this,tt,"f").length&&O(this,tt,v(this,tt,"f")+"\n","f"),O(this,tt,v(this,tt,"f")+t.join(" "),"f")}}}[Ot](t){p(v(this,et,"f")).forEach((e=>{if("configObjects"===e)return;const s=v(this,et,"f")[e];Array.isArray(s)?s.includes(t)&&s.splice(s.indexOf(t),1):"object"==typeof s&&delete s[t]})),delete v(this,pt,"f").getDescriptions()[t]}[wt](t,e,s){v(this,R,"f")[s]||(v(this,ct,"f").process.emitWarning(t,e),v(this,R,"f")[s]=!0)}[Ct](){v(this,B,"f").push({options:v(this,et,"f"),configObjects:v(this,et,"f").configObjects.slice(0),exitProcess:v(this,T,"f"),groups:v(this,K,"f"),strict:v(this,ft,"f"),strictCommands:v(this,dt,"f"),strictOptions:v(this,ut,"f"),completionCommand:v(this,F,"f"),output:v(this,tt,"f"),exitError:v(this,V,"f"),hasOutput:v(this,J,"f"),parsed:this.parsed,parseFn:v(this,nt,"f"),parseContext:v(this,rt,"f")}),v(this,pt,"f").freeze(),v(this,yt,"f").freeze(),v(this,z,"f").freeze(),v(this,Y,"f").freeze()}[jt](){let t,e="";return t=/\b(node|iojs|electron)(\.exe)?$/.test(v(this,ct,"f").process.argv()[0])?v(this,ct,"f").process.argv().slice(1,2):v(this,ct,"f").process.argv().slice(0,1),e=t.map((t=>{const e=this[Yt](v(this,W,"f"),t);return t.match(/^(\/|([a-zA-Z]:)?\\)/)&&e.length<t.length?e:t})).join(" ").trim(),v(this,ct,"f").getEnv("_")&&v(this,ct,"f").getProcessArgvBin()===v(this,ct,"f").getEnv("_")&&(e=v(this,ct,"f").getEnv("_").replace(`${v(this,ct,"f").path.dirname(v(this,ct,"f").process.execPath())}/`,"")),e}[Mt](){return v(this,it,"f")}[_t](){return v(this,gt,"f")}[kt](){if(!v(this,G,"f"))return;const t=v(this,ct,"f").getEnv("LC_ALL")||v(this,ct,"f").getEnv("LC_MESSAGES")||v(this,ct,"f").getEnv("LANG")||v(this,ct,"f").getEnv("LANGUAGE")||"en_US";this.locale(t.replace(/[.:].*/,""))}[xt](){return this[At]().version||"unknown"}[Et](t){const e=t["--"]?t["--"]:t._;for(let t,s=0;void 0!==(t=e[s]);s++)v(this,ct,"f").Parser.looksLikeNumber(t)&&Number.isSafeInteger(Math.floor(parseFloat(`${t}`)))&&(e[s]=Number(t));return t}[At](t){const e=t||"*";if(v(this,ot,"f")[e])return v(this,ot,"f")[e];let s={};try{let e=t||v(this,ct,"f").mainFilename;!t&&v(this,ct,"f").path.extname(e)&&(e=v(this,ct,"f").path.dirname(e));const i=v(this,ct,"f").findUp(e,((t,e)=>e.includes("package.json")?"package.json":void 0));d(i,void 0,v(this,ct,"f")),s=JSON.parse(v(this,ct,"f").readFileSync(i,"utf8"))}catch(t){}return v(this,ot,"f")[e]=s||{},v(this,ot,"f")[e]}[Pt](t,e){(e=[].concat(e)).forEach((e=>{e=this[Dt](e),v(this,et,"f")[t].push(e)}))}[St](t,e,s,i){this[It](t,e,s,i,((t,e,s)=>{v(this,et,"f")[t][e]=s}))}[$t](t,e,s,i){this[It](t,e,s,i,((t,e,s)=>{v(this,et,"f")[t][e]=(v(this,et,"f")[t][e]||[]).concat(s)}))}[It](t,e,s,i,n){if(Array.isArray(s))s.forEach((e=>{t(e,i)}));else if((t=>"object"==typeof t)(s))for(const e of p(s))t(e,s[e]);else n(e,this[Dt](s),i)}[Dt](t){return"__proto__"===t?"___proto___":t}[Nt](t,e){return this[St](this[Nt].bind(this),"key",t,e),this}[Ht](){var t,e,s,i,n,r,o,a,h,l,c,f;const u=v(this,B,"f").pop();let p;d(u,void 0,v(this,ct,"f")),t=this,e=this,s=this,i=this,n=this,r=this,o=this,a=this,h=this,l=this,c=this,f=this,({options:{set value(e){O(t,et,e,"f")}}.value,configObjects:p,exitProcess:{set value(t){O(e,T,t,"f")}}.value,groups:{set value(t){O(s,K,t,"f")}}.value,output:{set value(t){O(i,tt,t,"f")}}.value,exitError:{set value(t){O(n,V,t,"f")}}.value,hasOutput:{set value(t){O(r,J,t,"f")}}.value,parsed:this.parsed,strict:{set value(t){O(o,ft,t,"f")}}.value,strictCommands:{set value(t){O(a,dt,t,"f")}}.value,strictOptions:{set value(t){O(h,ut,t,"f")}}.value,completionCommand:{set value(t){O(l,F,t,"f")}}.value,parseFn:{set value(t){O(c,nt,t,"f")}}.value,parseContext:{set value(t){O(f,rt,t,"f")}}.value}=u),v(this,et,"f").configObjects=p,v(this,pt,"f").unfreeze(),v(this,yt,"f").unfreeze(),v(this,z,"f").unfreeze(),v(this,Y,"f").unfreeze()}[zt](t,e){return j(e,(e=>(t(e),e)))}getInternalMethods(){return{getCommandInstance:this[Wt].bind(this),getContext:this[qt].bind(this),getHasOutput:this[Ut].bind(this),getLoggerInstance:this[Ft].bind(this),getParseContext:this[Lt].bind(this),getParserConfiguration:this[Mt].bind(this),getUsageConfiguration:this[_t].bind(this),getUsageInstance:this[Vt].bind(this),getValidationInstance:this[Gt].bind(this),hasParseCallback:this[Rt].bind(this),isGlobalContext:this[Tt].bind(this),postProcess:this[Bt].bind(this),reset:this[Kt].bind(this),runValidation:this[Zt].bind(this),runYargsParserAndExecuteCommands:this[Jt].bind(this),setHasOutput:this[Xt].bind(this)}}[Wt](){return v(this,z,"f")}[qt](){return v(this,q,"f")}[Ut](){return v(this,J,"f")}[Ft](){return v(this,Q,"f")}[Lt](){return v(this,rt,"f")||{}}[Vt](){return v(this,pt,"f")}[Gt](){return v(this,yt,"f")}[Rt](){return!!v(this,nt,"f")}[Tt](){return v(this,X,"f")}[Bt](t,e,s,i){if(s)return t;if(f(t))return t;e||(t=this[bt](t));return(this[Mt]()["parse-positional-numbers"]||void 0===this[Mt]()["parse-positional-numbers"])&&(t=this[Et](t)),i&&(t=C(t,this,v(this,Y,"f").getMiddleware(),!1)),t}[Kt](t={}){O(this,et,v(this,et,"f")||{},"f");const e={};e.local=v(this,et,"f").local||[],e.configObjects=v(this,et,"f").configObjects||[];const s={};e.local.forEach((e=>{s[e]=!0,(t[e]||[]).forEach((t=>{s[t]=!0}))})),Object.assign(v(this,at,"f"),Object.keys(v(this,K,"f")).reduce(((t,e)=>{const i=v(this,K,"f")[e].filter((t=>!(t in s)));return i.length>0&&(t[e]=i),t}),{})),O(this,K,{},"f");return["array","boolean","string","skipValidation","count","normalize","number","hiddenOptions"].forEach((t=>{e[t]=(v(this,et,"f")[t]||[]).filter((t=>!s[t]))})),["narg","key","alias","default","defaultDescription","config","choices","demandedOptions","demandedCommands","deprecatedOptions"].forEach((t=>{e[t]=g(v(this,et,"f")[t],(t=>!s[t]))})),e.envPrefix=v(this,et,"f").envPrefix,O(this,et,e,"f"),O(this,pt,v(this,pt,"f")?v(this,pt,"f").reset(s):P(this,v(this,ct,"f")),"f"),O(this,yt,v(this,yt,"f")?v(this,yt,"f").reset(s):function(t,e,s){const i=s.y18n.__,n=s.y18n.__n,r={nonOptionCount:function(s){const i=t.getDemandedCommands(),r=s._.length+(s["--"]?s["--"].length:0)-t.getInternalMethods().getContext().commands.length;i._&&(r<i._.min||r>i._.max)&&(r<i._.min?void 0!==i._.minMsg?e.fail(i._.minMsg?i._.minMsg.replace(/\$0/g,r.toString()).replace(/\$1/,i._.min.toString()):null):e.fail(n("Not enough non-option arguments: got %s, need at least %s","Not enough non-option arguments: got %s, need at least %s",r,r.toString(),i._.min.toString())):r>i._.max&&(void 0!==i._.maxMsg?e.fail(i._.maxMsg?i._.maxMsg.replace(/\$0/g,r.toString()).replace(/\$1/,i._.max.toString()):null):e.fail(n("Too many non-option arguments: got %s, maximum of %s","Too many non-option arguments: got %s, maximum of %s",r,r.toString(),i._.max.toString()))))},positionalCount:function(t,s){s<t&&e.fail(n("Not enough non-option arguments: got %s, need at least %s","Not enough non-option arguments: got %s, need at least %s",s,s+"",t+""))},requiredArguments:function(t,s){let i=null;for(const e of Object.keys(s))Object.prototype.hasOwnProperty.call(t,e)&&void 0!==t[e]||(i=i||{},i[e]=s[e]);if(i){const t=[];for(const e of Object.keys(i)){const s=i[e];s&&t.indexOf(s)<0&&t.push(s)}const s=t.length?`\n${t.join("\n")}`:"";e.fail(n("Missing required argument: %s","Missing required arguments: %s",Object.keys(i).length,Object.keys(i).join(", ")+s))}},unknownArguments:function(s,i,o,a,h=!0){var l;const c=t.getInternalMethods().getCommandInstance().getCommands(),f=[],d=t.getInternalMethods().getContext();if(Object.keys(s).forEach((e=>{H.includes(e)||Object.prototype.hasOwnProperty.call(o,e)||Object.prototype.hasOwnProperty.call(t.getInternalMethods().getParseContext(),e)||r.isValidAndSomeAliasIsNotNew(e,i)||f.push(e)})),h&&(d.commands.length>0||c.length>0||a)&&s._.slice(d.commands.length).forEach((t=>{c.includes(""+t)||f.push(""+t)})),h){const e=(null===(l=t.getDemandedCommands()._)||void 0===l?void 0:l.max)||0,i=d.commands.length+e;i<s._.length&&s._.slice(i).forEach((t=>{t=String(t),d.commands.includes(t)||f.includes(t)||f.push(t)}))}f.length&&e.fail(n("Unknown argument: %s","Unknown arguments: %s",f.length,f.map((t=>t.trim()?t:`"${t}"`)).join(", ")))},unknownCommands:function(s){const i=t.getInternalMethods().getCommandInstance().getCommands(),r=[],o=t.getInternalMethods().getContext();return(o.commands.length>0||i.length>0)&&s._.slice(o.commands.length).forEach((t=>{i.includes(""+t)||r.push(""+t)})),r.length>0&&(e.fail(n("Unknown command: %s","Unknown commands: %s",r.length,r.join(", "))),!0)},isValidAndSomeAliasIsNotNew:function(e,s){if(!Object.prototype.hasOwnProperty.call(s,e))return!1;const i=t.parsed.newAliases;return[e,...s[e]].some((t=>!Object.prototype.hasOwnProperty.call(i,t)||!i[e]))},limitedChoices:function(s){const n=t.getOptions(),r={};if(!Object.keys(n.choices).length)return;Object.keys(s).forEach((t=>{-1===H.indexOf(t)&&Object.prototype.hasOwnProperty.call(n.choices,t)&&[].concat(s[t]).forEach((e=>{-1===n.choices[t].indexOf(e)&&void 0!==e&&(r[t]=(r[t]||[]).concat(e))}))}));const o=Object.keys(r);if(!o.length)return;let a=i("Invalid values:");o.forEach((t=>{a+=`\n  ${i("Argument: %s, Given: %s, Choices: %s",t,e.stringifiedValues(r[t]),e.stringifiedValues(n.choices[t]))}`})),e.fail(a)}};let o={};function a(t,e){const s=Number(e);return"number"==typeof(e=isNaN(s)?e:s)?e=t._.length>=e:e.match(/^--no-.+/)?(e=e.match(/^--no-(.+)/)[1],e=!Object.prototype.hasOwnProperty.call(t,e)):e=Object.prototype.hasOwnProperty.call(t,e),e}r.implies=function(e,i){h("<string|object> [array|number|string]",[e,i],arguments.length),"object"==typeof e?Object.keys(e).forEach((t=>{r.implies(t,e[t])})):(t.global(e),o[e]||(o[e]=[]),Array.isArray(i)?i.forEach((t=>r.implies(e,t))):(d(i,void 0,s),o[e].push(i)))},r.getImplied=function(){return o},r.implications=function(t){const s=[];if(Object.keys(o).forEach((e=>{const i=e;(o[e]||[]).forEach((e=>{let n=i;const r=e;n=a(t,n),e=a(t,e),n&&!e&&s.push(` ${i} -> ${r}`)}))})),s.length){let t=`${i("Implications failed:")}\n`;s.forEach((e=>{t+=e})),e.fail(t)}};let l={};r.conflicts=function(e,s){h("<string|object> [array|string]",[e,s],arguments.length),"object"==typeof e?Object.keys(e).forEach((t=>{r.conflicts(t,e[t])})):(t.global(e),l[e]||(l[e]=[]),Array.isArray(s)?s.forEach((t=>r.conflicts(e,t))):l[e].push(s))},r.getConflicting=()=>l,r.conflicting=function(n){Object.keys(n).forEach((t=>{l[t]&&l[t].forEach((s=>{s&&void 0!==n[t]&&void 0!==n[s]&&e.fail(i("Arguments %s and %s are mutually exclusive",t,s))}))})),t.getInternalMethods().getParserConfiguration()["strip-dashed"]&&Object.keys(l).forEach((t=>{l[t].forEach((r=>{r&&void 0!==n[s.Parser.camelCase(t)]&&void 0!==n[s.Parser.camelCase(r)]&&e.fail(i("Arguments %s and %s are mutually exclusive",t,r))}))}))},r.recommendCommands=function(t,s){s=s.sort(((t,e)=>e.length-t.length));let n=null,r=1/0;for(let e,i=0;void 0!==(e=s[i]);i++){const s=N(t,e);s<=3&&s<r&&(r=s,n=e)}n&&e.fail(i("Did you mean %s?",n))},r.reset=function(t){return o=g(o,(e=>!t[e])),l=g(l,(e=>!t[e])),r};const c=[];return r.freeze=function(){c.push({implied:o,conflicting:l})},r.unfreeze=function(){const t=c.pop();d(t,void 0,s),({implied:o,conflicting:l}=t)},r}(this,v(this,pt,"f"),v(this,ct,"f")),"f"),O(this,z,v(this,z,"f")?v(this,z,"f").reset():function(t,e,s,i){return new _(t,e,s,i)}(v(this,pt,"f"),v(this,yt,"f"),v(this,Y,"f"),v(this,ct,"f")),"f"),v(this,U,"f")||O(this,U,function(t,e,s,i){return new D(t,e,s,i)}(this,v(this,pt,"f"),v(this,z,"f"),v(this,ct,"f")),"f"),v(this,Y,"f").reset(),O(this,F,null,"f"),O(this,tt,"","f"),O(this,V,null,"f"),O(this,J,!1,"f"),this.parsed=!1,this}[Yt](t,e){return v(this,ct,"f").path.relative(t,e)}[Jt](t,s,i,n=0,r=!1){let o=!!i||r;t=t||v(this,ht,"f"),v(this,et,"f").__=v(this,ct,"f").y18n.__,v(this,et,"f").configuration=this[Mt]();const a=!!v(this,et,"f").configuration["populate--"],h=Object.assign({},v(this,et,"f").configuration,{"populate--":!0}),l=v(this,ct,"f").Parser.detailed(t,Object.assign({},v(this,et,"f"),{configuration:{"parse-positional-numbers":!1,...h}})),c=Object.assign(l.argv,v(this,rt,"f"));let d;const u=l.aliases;let p=!1,g=!1;Object.keys(c).forEach((t=>{t===v(this,Z,"f")&&c[t]?p=!0:t===v(this,mt,"f")&&c[t]&&(g=!0)})),c.$0=this.$0,this.parsed=l,0===n&&v(this,pt,"f").clearCachedHelpMessage();try{if(this[kt](),s)return this[Bt](c,a,!!i,!1);if(v(this,Z,"f")){[v(this,Z,"f")].concat(u[v(this,Z,"f")]||[]).filter((t=>t.length>1)).includes(""+c._[c._.length-1])&&(c._.pop(),p=!0)}O(this,X,!1,"f");const h=v(this,z,"f").getCommands(),m=v(this,U,"f").completionKey in c,y=p||m||r;if(c._.length){if(h.length){let t;for(let e,s=n||0;void 0!==c._[s];s++){if(e=String(c._[s]),h.includes(e)&&e!==v(this,F,"f")){const t=v(this,z,"f").runCommand(e,this,l,s+1,r,p||g||r);return this[Bt](t,a,!!i,!1)}if(!t&&e!==v(this,F,"f")){t=e;break}}!v(this,z,"f").hasDefaultCommand()&&v(this,lt,"f")&&t&&!y&&v(this,yt,"f").recommendCommands(t,h)}v(this,F,"f")&&c._.includes(v(this,F,"f"))&&!m&&(v(this,T,"f")&&E(!0),this.showCompletionScript(),this.exit(0))}if(v(this,z,"f").hasDefaultCommand()&&!y){const t=v(this,z,"f").runCommand(null,this,l,0,r,p||g||r);return this[Bt](t,a,!!i,!1)}if(m){v(this,T,"f")&&E(!0);const s=(t=[].concat(t)).slice(t.indexOf(`--${v(this,U,"f").completionKey}`)+1);return v(this,U,"f").getCompletion(s,((t,s)=>{if(t)throw new e(t.message);(s||[]).forEach((t=>{v(this,Q,"f").log(t)})),this.exit(0)})),this[Bt](c,!a,!!i,!1)}if(v(this,J,"f")||(p?(v(this,T,"f")&&E(!0),o=!0,this.showHelp("log"),this.exit(0)):g&&(v(this,T,"f")&&E(!0),o=!0,v(this,pt,"f").showVersion("log"),this.exit(0))),!o&&v(this,et,"f").skipValidation.length>0&&(o=Object.keys(c).some((t=>v(this,et,"f").skipValidation.indexOf(t)>=0&&!0===c[t]))),!o){if(l.error)throw new e(l.error.message);if(!m){const t=this[Zt](u,{},l.error);i||(d=C(c,this,v(this,Y,"f").getMiddleware(),!0)),d=this[zt](t,null!=d?d:c),f(d)&&!i&&(d=d.then((()=>C(c,this,v(this,Y,"f").getMiddleware(),!1))))}}}catch(t){if(!(t instanceof e))throw t;v(this,pt,"f").fail(t.message,t)}return this[Bt](null!=d?d:c,a,!!i,!0)}[Zt](t,s,i,n){const r={...this.getDemandedOptions()};return o=>{if(i)throw new e(i.message);v(this,yt,"f").nonOptionCount(o),v(this,yt,"f").requiredArguments(o,r);let a=!1;v(this,dt,"f")&&(a=v(this,yt,"f").unknownCommands(o)),v(this,ft,"f")&&!a?v(this,yt,"f").unknownArguments(o,t,s,!!n):v(this,ut,"f")&&v(this,yt,"f").unknownArguments(o,t,{},!1,!1),v(this,yt,"f").limitedChoices(o),v(this,yt,"f").implications(o),v(this,yt,"f").conflicting(o)}}[Xt](){O(this,J,!0,"f")}[Qt](t){if("string"==typeof t)v(this,et,"f").key[t]=!0;else for(const e of t)v(this,et,"f").key[e]=!0}}var ee,se;const{readFileSync:ie}=__nccwpck_require__(7147),{inspect:ne}=__nccwpck_require__(3837),{resolve:re}=__nccwpck_require__(1017),oe=__nccwpck_require__(452),ae=__nccwpck_require__(1970);var he,le={assert:{notStrictEqual:t.notStrictEqual,strictEqual:t.strictEqual},cliui:__nccwpck_require__(7059),findUp:__nccwpck_require__(2644),getEnv:t=>process.env[t],getCallerFile:__nccwpck_require__(351),getProcessArgvBin:y,inspect:ne,mainFilename:null!==(se=null===(ee= false||void 0===__nccwpck_require__(9167)?void 0:__nccwpck_require__.c[__nccwpck_require__.s])||void 0===ee?void 0:ee.filename)&&void 0!==se?se:process.cwd(),Parser:ae,path:__nccwpck_require__(1017),process:{argv:()=>process.argv,cwd:process.cwd,emitWarning:(t,e)=>process.emitWarning(t,e),execPath:()=>process.execPath,exit:t=>{process.exit(t)},nextTick:process.nextTick,stdColumns:void 0!==process.stdout.columns?process.stdout.columns:null},readFileSync:ie,require:__nccwpck_require__(9167),requireDirectory:__nccwpck_require__(9200),stringWidth:__nccwpck_require__(2577),y18n:oe({directory:re(__dirname,"../locales"),updateFiles:!1})};const ce=(null===(he=null===process||void 0===process?void 0:process.env)||void 0===he?void 0:he.YARGS_MIN_NODE_VERSION)?Number(process.env.YARGS_MIN_NODE_VERSION):12;if(process&&process.version){if(Number(process.version.match(/v([^.]+)/)[1])<ce)throw Error(`yargs supports a minimum Node.js version of ${ce}. Read our version support policy: https://github.com/yargs/yargs#supported-nodejs-versions`)}const fe=__nccwpck_require__(1970);var de,ue={applyExtends:n,cjsPlatformShim:le,Yargs:(de=le,(t=[],e=de.process.cwd(),s)=>{const i=new te(t,e,s,de);return Object.defineProperty(i,"argv",{get:()=>i.parse(),enumerable:!0}),i.help(),i.version(),i}),argsert:h,isPromise:f,objFilter:g,parseCommand:o,Parser:fe,processArgv:b,YError:e};module.exports=ue;


/***/ }),

/***/ 8822:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

// classic singleton yargs API, to use yargs
// without running as a singleton do:
// require('yargs/yargs')(process.argv.slice(2))
const {Yargs, processArgv} = __nccwpck_require__(9562);

Argv(processArgv.hideBin(process.argv));

module.exports = Argv;

function Argv(processArgs, cwd) {
  const argv = Yargs(processArgs, cwd, __nccwpck_require__(4907));
  singletonify(argv);
  // TODO(bcoe): warn if argv.parse() or argv.argv is used directly.
  return argv;
}

function defineGetter(obj, key, getter) {
  Object.defineProperty(obj, key, {
    configurable: true,
    enumerable: true,
    get: getter,
  });
}
function lookupGetter(obj, key) {
  const desc = Object.getOwnPropertyDescriptor(obj, key);
  if (typeof desc !== 'undefined') {
    return desc.get;
  }
}

/*  Hack an instance of Argv with process.argv into Argv
    so people can do
    require('yargs')(['--beeble=1','-z','zizzle']).argv
    to parse a list of args and
    require('yargs').argv
    to get a parsed version of process.argv.
*/
function singletonify(inst) {
  [
    ...Object.keys(inst),
    ...Object.getOwnPropertyNames(inst.constructor.prototype),
  ].forEach(key => {
    if (key === 'argv') {
      defineGetter(Argv, key, lookupGetter(inst, key));
    } else if (typeof inst[key] === 'function') {
      Argv[key] = inst[key].bind(inst);
    } else {
      defineGetter(Argv, '$0', () => inst.$0);
      defineGetter(Argv, 'parsed', () => inst.parsed);
    }
  });
}


/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __nccwpck_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			id: moduleId,
/******/ 			loaded: false,
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			__webpack_modules__[moduleId].call(module.exports, module, module.exports, __nccwpck_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete __webpack_module_cache__[moduleId];
/******/ 		}
/******/ 	
/******/ 		// Flag the module as loaded
/******/ 		module.loaded = true;
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/******/ 	// expose the module cache
/******/ 	__nccwpck_require__.c = __webpack_module_cache__;
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__nccwpck_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/node module decorator */
/******/ 	(() => {
/******/ 		__nccwpck_require__.nmd = (module) => {
/******/ 			module.paths = [];
/******/ 			if (!module.children) module.children = [];
/******/ 			return module;
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/compat */
/******/ 	
/******/ 	if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = __dirname + "/";
/******/ 	
/************************************************************************/
/******/ 	
/******/ 	// module cache are used so entry inlining is disabled
/******/ 	// startup
/******/ 	// Load entry module and return exports
/******/ 	var __webpack_exports__ = __nccwpck_require__(__nccwpck_require__.s = 3109);
/******/ 	module.exports = __webpack_exports__;
/******/ 	
/******/ })()
;
//# sourceMappingURL=index.js.map