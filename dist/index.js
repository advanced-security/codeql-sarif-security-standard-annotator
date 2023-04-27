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
const yargs_1 = __importDefault(__nccwpck_require__(8822));
const helpers_1 = __nccwpck_require__(6658);
const fs = __importStar(__nccwpck_require__(7147));
const core = __importStar(__nccwpck_require__(2186));
const parse_xml_1 = __nccwpck_require__(8532);
const process_1 = __nccwpck_require__(7282);
function isXmlElement(xmlThing) {
    return xmlThing instanceof parse_xml_1.XmlElement;
}
// parse inputs or arguments from command line
var sarifFile = core.getInput('sarifFile');
var cweFile = core.getInput('cweFile');
if (process_1.env.CI !== 'true') {
    const argv = (0, yargs_1.default)((0, helpers_1.hideBin)(process.argv))
        .options({
        sarifFile: { type: 'string', demandOption: true },
        cweFile: { type: 'string', demandOption: true }
    })
        .parseSync();
    sarifFile = argv.sarifFile;
    cweFile = argv.cweFile;
}
// load SARIF file
try {
    var sarifResults = JSON.parse(fs.readFileSync(sarifFile, 'utf8'));
}
catch (err) {
    core.setFailed(`Unable to load SARIF file: ${err}`);
    process.exit(1);
}
// load security standard CWE list
try {
    var cweList = (0, parse_xml_1.parseXml)(fs.readFileSync(cweFile, 'utf8'));
}
catch (err) {
    core.setFailed(`Unable to load CWE list: ${err}`);
    process.exit(1);
}
var cweIDList = [];
cweList.children.filter(isXmlElement).forEach(child => {
    if (child.name === 'Weakness_Catalog') {
        child.children.filter(isXmlElement).forEach(child => {
            if (child.name === 'Weaknesses') {
                child.children.filter(isXmlElement).forEach(weakness => {
                    cweIDList.push(parseInt(weakness.attributes.ID));
                });
            }
        });
    }
});
cweIDList.sort();
// Annotate SARIF file
sarifResults.runs.forEach((run) => {
    var _a;
    (_a = run.tool.extensions) === null || _a === void 0 ? void 0 : _a.forEach((extension) => {
        var _a;
        (_a = extension.rules) === null || _a === void 0 ? void 0 : _a.forEach((rule) => {
            var _a, _b;
            (_b = (_a = rule.properties) === null || _a === void 0 ? void 0 : _a.tags) === null || _b === void 0 ? void 0 : _b.forEach((tag) => {
                if (tag.startsWith('external/cwe/cwe-')) {
                    const cweId = tag.split('-').pop();
                    if (cweId !== undefined && cweIDList.includes(parseInt(cweId))) {
                        rule.properties.tags.push('owasp-2021');
                    }
                }
            });
        });
    });
});
// Output report
try {
    fs.writeFileSync(sarifFile, JSON.stringify(sarifResults));
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

/***/ 8532:
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
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.parseXml = exports.XmlText = exports.XmlProcessingInstruction = exports.XmlNode = exports.XmlError = exports.XmlElement = exports.XmlDocumentType = exports.XmlDocument = exports.XmlDeclaration = exports.XmlComment = exports.XmlCdata = void 0;
const Parser_js_1 = __nccwpck_require__(3793);
__exportStar(__nccwpck_require__(2162), exports);
var XmlCdata_js_1 = __nccwpck_require__(3769);
Object.defineProperty(exports, "XmlCdata", ({ enumerable: true, get: function () { return XmlCdata_js_1.XmlCdata; } }));
var XmlComment_js_1 = __nccwpck_require__(1306);
Object.defineProperty(exports, "XmlComment", ({ enumerable: true, get: function () { return XmlComment_js_1.XmlComment; } }));
var XmlDeclaration_js_1 = __nccwpck_require__(1383);
Object.defineProperty(exports, "XmlDeclaration", ({ enumerable: true, get: function () { return XmlDeclaration_js_1.XmlDeclaration; } }));
var XmlDocument_js_1 = __nccwpck_require__(5455);
Object.defineProperty(exports, "XmlDocument", ({ enumerable: true, get: function () { return XmlDocument_js_1.XmlDocument; } }));
var XmlDocumentType_js_1 = __nccwpck_require__(5777);
Object.defineProperty(exports, "XmlDocumentType", ({ enumerable: true, get: function () { return XmlDocumentType_js_1.XmlDocumentType; } }));
var XmlElement_js_1 = __nccwpck_require__(7265);
Object.defineProperty(exports, "XmlElement", ({ enumerable: true, get: function () { return XmlElement_js_1.XmlElement; } }));
var XmlError_js_1 = __nccwpck_require__(706);
Object.defineProperty(exports, "XmlError", ({ enumerable: true, get: function () { return XmlError_js_1.XmlError; } }));
var XmlNode_js_1 = __nccwpck_require__(5899);
Object.defineProperty(exports, "XmlNode", ({ enumerable: true, get: function () { return XmlNode_js_1.XmlNode; } }));
var XmlProcessingInstruction_js_1 = __nccwpck_require__(3688);
Object.defineProperty(exports, "XmlProcessingInstruction", ({ enumerable: true, get: function () { return XmlProcessingInstruction_js_1.XmlProcessingInstruction; } }));
var XmlText_js_1 = __nccwpck_require__(2247);
Object.defineProperty(exports, "XmlText", ({ enumerable: true, get: function () { return XmlText_js_1.XmlText; } }));
/**
 * Parses the given XML string and returns an `XmlDocument` instance
 * representing the document tree.
 *
 * @example
 *
 * import { parseXml } from '@rgrove/parse-xml';
 * let doc = parseXml('<kittens fuzzy="yes">I like fuzzy kittens.</kittens>');
 *
 * @param xml XML string to parse.
 * @param options Parser options.
 */
function parseXml(xml, options) {
    return (new Parser_js_1.Parser(xml, options)).document;
}
exports.parseXml = parseXml;
//# sourceMappingURL=index.js.map

/***/ }),

/***/ 3793:
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
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Parser = void 0;
const StringScanner_js_1 = __nccwpck_require__(4902);
const syntax = __importStar(__nccwpck_require__(3420));
const XmlCdata_js_1 = __nccwpck_require__(3769);
const XmlComment_js_1 = __nccwpck_require__(1306);
const XmlDeclaration_js_1 = __nccwpck_require__(1383);
const XmlDocument_js_1 = __nccwpck_require__(5455);
const XmlDocumentType_js_1 = __nccwpck_require__(5777);
const XmlElement_js_1 = __nccwpck_require__(7265);
const XmlError_js_1 = __nccwpck_require__(706);
const XmlNode_js_1 = __nccwpck_require__(5899);
const XmlProcessingInstruction_js_1 = __nccwpck_require__(3688);
const XmlText_js_1 = __nccwpck_require__(2247);
const emptyString = '';
/**
 * Parses an XML string into an `XmlDocument`.
 *
 * @private
 */
class Parser {
    /**
     * @param xml XML string to parse.
     * @param options Parser options.
     */
    constructor(xml, options = {}) {
        let doc = this.document = new XmlDocument_js_1.XmlDocument();
        let scanner = this.scanner = new StringScanner_js_1.StringScanner(xml);
        this.currentNode = doc;
        this.options = options;
        if (this.options.includeOffsets) {
            doc.start = 0;
            doc.end = xml.length;
        }
        scanner.consumeStringFast('\uFEFF'); // byte order mark
        this.consumeProlog();
        if (!this.consumeElement()) {
            throw this.error('Root element is missing or invalid');
        }
        while (this.consumeMisc()) { } // eslint-disable-line no-empty
        if (!scanner.isEnd) {
            throw this.error('Extra content at the end of the document');
        }
    }
    /**
     * Adds the given `XmlNode` as a child of `this.currentNode`.
     */
    addNode(node, charIndex) {
        node.parent = this.currentNode;
        if (this.options.includeOffsets) {
            node.start = this.scanner.charIndexToByteIndex(charIndex);
            node.end = this.scanner.charIndexToByteIndex();
        }
        // @ts-expect-error: XmlDocument has a more limited set of possible children
        // than XmlElement so TypeScript is unhappy, but we always do the right
        // thing.
        this.currentNode.children.push(node);
        return true;
    }
    /**
     * Adds the given _text_ to the document, either by appending it to a
     * preceding `XmlText` node (if possible) or by creating a new `XmlText` node.
     */
    addText(text, charIndex) {
        let { children } = this.currentNode;
        let { length } = children;
        text = normalizeLineBreaks(text);
        if (length > 0) {
            let prevNode = children[length - 1];
            if (prevNode?.type === XmlNode_js_1.XmlNode.TYPE_TEXT) {
                let textNode = prevNode;
                // The previous node is a text node, so we can append to it and avoid
                // creating another node.
                textNode.text += text;
                if (this.options.includeOffsets) {
                    textNode.end = this.scanner.charIndexToByteIndex();
                }
                return true;
            }
        }
        return this.addNode(new XmlText_js_1.XmlText(text), charIndex);
    }
    /**
     * Consumes element attributes.
     *
     * @see https://www.w3.org/TR/2008/REC-xml-20081126/#sec-starttags
     */
    consumeAttributes() {
        let attributes = Object.create(null);
        while (this.consumeWhitespace()) {
            let attrName = this.consumeName();
            if (!attrName) {
                break;
            }
            let attrValue = this.consumeEqual() && this.consumeAttributeValue();
            if (attrValue === false) {
                throw this.error('Attribute value expected');
            }
            if (attrName in attributes) {
                throw this.error(`Duplicate attribute: ${attrName}`);
            }
            if (attrName === 'xml:space'
                && attrValue !== 'default'
                && attrValue !== 'preserve') {
                throw this.error('Value of the `xml:space` attribute must be "default" or "preserve"');
            }
            attributes[attrName] = attrValue;
        }
        if (this.options.sortAttributes) {
            let attrNames = Object.keys(attributes).sort();
            let sortedAttributes = Object.create(null);
            for (let i = 0; i < attrNames.length; ++i) {
                let attrName = attrNames[i];
                sortedAttributes[attrName] = attributes[attrName];
            }
            attributes = sortedAttributes;
        }
        return attributes;
    }
    /**
     * Consumes an `AttValue` (attribute value) if possible.
     *
     * @returns
     *   Contents of the `AttValue` minus quotes, or `false` if nothing was
     *   consumed. An empty string indicates that an `AttValue` was consumed but
     *   was empty.
     *
     * @see https://www.w3.org/TR/2008/REC-xml-20081126/#NT-AttValue
     */
    consumeAttributeValue() {
        let { scanner } = this;
        let quote = scanner.peek();
        if (quote !== '"' && quote !== "'") {
            return false;
        }
        scanner.advance();
        let chars;
        let isClosed = false;
        let value = emptyString;
        let regex = quote === '"'
            ? syntax.attValueCharDoubleQuote
            : syntax.attValueCharSingleQuote;
        matchLoop: while (!scanner.isEnd) {
            chars = scanner.consumeMatch(regex);
            if (chars) {
                this.validateChars(chars);
                value += chars.replace(syntax.attValueNormalizedWhitespace, ' ');
            }
            switch (scanner.peek()) {
                case quote:
                    isClosed = true;
                    break matchLoop;
                case '&':
                    value += this.consumeReference();
                    continue;
                case '<':
                    throw this.error('Unescaped `<` is not allowed in an attribute value');
                case emptyString:
                    break matchLoop;
            }
        }
        if (!isClosed) {
            throw this.error('Unclosed attribute');
        }
        scanner.advance();
        return value;
    }
    /**
     * Consumes a CDATA section if possible.
     *
     * @returns Whether a CDATA section was consumed.
     * @see https://www.w3.org/TR/2008/REC-xml-20081126/#sec-cdata-sect
     */
    consumeCdataSection() {
        let { scanner } = this;
        let startIndex = scanner.charIndex;
        if (!scanner.consumeStringFast('<![CDATA[')) {
            return false;
        }
        let text = scanner.consumeUntilString(']]>');
        this.validateChars(text);
        if (!scanner.consumeStringFast(']]>')) {
            throw this.error('Unclosed CDATA section');
        }
        return this.options.preserveCdata
            ? this.addNode(new XmlCdata_js_1.XmlCdata(normalizeLineBreaks(text)), startIndex)
            : this.addText(text, startIndex);
    }
    /**
     * Consumes character data if possible.
     *
     * @returns Whether character data was consumed.
     * @see https://www.w3.org/TR/2008/REC-xml-20081126/#dt-chardata
     */
    consumeCharData() {
        let { scanner } = this;
        let startIndex = scanner.charIndex;
        let charData = scanner.consumeUntilMatch(syntax.endCharData);
        if (!charData) {
            return false;
        }
        this.validateChars(charData);
        if (scanner.peek(3) === ']]>') {
            throw this.error('Element content may not contain the CDATA section close delimiter `]]>`');
        }
        return this.addText(charData, startIndex);
    }
    /**
     * Consumes a comment if possible.
     *
     * @returns Whether a comment was consumed.
     * @see https://www.w3.org/TR/2008/REC-xml-20081126/#NT-Comment
     */
    consumeComment() {
        let { scanner } = this;
        let startIndex = scanner.charIndex;
        if (!scanner.consumeStringFast('<!--')) {
            return false;
        }
        let content = scanner.consumeUntilString('--');
        this.validateChars(content);
        if (!scanner.consumeStringFast('-->')) {
            if (scanner.peek(2) === '--') {
                throw this.error("The string `--` isn't allowed inside a comment");
            }
            throw this.error('Unclosed comment');
        }
        return this.options.preserveComments
            ? this.addNode(new XmlComment_js_1.XmlComment(normalizeLineBreaks(content)), startIndex)
            : true;
    }
    /**
     * Consumes a reference in a content context if possible.
     *
     * This differs from `consumeReference()` in that a consumed reference will be
     * added to the document as a text node instead of returned.
     *
     * @returns Whether a reference was consumed.
     * @see https://www.w3.org/TR/2008/REC-xml-20081126/#entproc
     */
    consumeContentReference() {
        let startIndex = this.scanner.charIndex;
        let ref = this.consumeReference();
        return ref
            ? this.addText(ref, startIndex)
            : false;
    }
    /**
     * Consumes a doctype declaration if possible.
     *
     * This is a loose implementation since doctype declarations are currently
     * discarded without further parsing.
     *
     * @returns Whether a doctype declaration was consumed.
     * @see https://www.w3.org/TR/2008/REC-xml-20081126/#dtd
     */
    consumeDoctypeDeclaration() {
        let { scanner } = this;
        let startIndex = scanner.charIndex;
        if (!scanner.consumeStringFast('<!DOCTYPE')) {
            return false;
        }
        let name = this.consumeWhitespace()
            && this.consumeName();
        if (!name) {
            throw this.error('Expected a name');
        }
        let publicId;
        let systemId;
        if (this.consumeWhitespace()) {
            if (scanner.consumeStringFast('PUBLIC')) {
                publicId = this.consumeWhitespace()
                    && this.consumePubidLiteral();
                if (publicId === false) {
                    throw this.error('Expected a public identifier');
                }
                this.consumeWhitespace();
            }
            if (publicId !== undefined || scanner.consumeStringFast('SYSTEM')) {
                this.consumeWhitespace();
                systemId = this.consumeSystemLiteral();
                if (systemId === false) {
                    throw this.error('Expected a system identifier');
                }
                this.consumeWhitespace();
            }
        }
        let internalSubset;
        if (scanner.consumeStringFast('[')) {
            // The internal subset may contain comments that contain `]` characters,
            // so we can't use `consumeUntilString()` here.
            internalSubset = scanner.consumeUntilMatch(/\][\x20\t\r\n]*>/);
            if (!scanner.consumeStringFast(']')) {
                throw this.error('Unclosed internal subset');
            }
            this.consumeWhitespace();
        }
        if (!scanner.consumeStringFast('>')) {
            throw this.error('Unclosed doctype declaration');
        }
        return this.options.preserveDocumentType
            ? this.addNode(new XmlDocumentType_js_1.XmlDocumentType(name, publicId, systemId, internalSubset), startIndex)
            : true;
    }
    /**
     * Consumes an element if possible.
     *
     * @returns Whether an element was consumed.
     * @see https://www.w3.org/TR/2008/REC-xml-20081126/#NT-element
     */
    consumeElement() {
        let { scanner } = this;
        let startIndex = scanner.charIndex;
        if (!scanner.consumeStringFast('<')) {
            return false;
        }
        let name = this.consumeName();
        if (!name) {
            scanner.reset(startIndex);
            return false;
        }
        let attributes = this.consumeAttributes();
        let isEmpty = !!scanner.consumeStringFast('/>');
        let element = new XmlElement_js_1.XmlElement(name, attributes);
        element.parent = this.currentNode;
        if (!isEmpty) {
            if (!scanner.consumeStringFast('>')) {
                throw this.error(`Unclosed start tag for element \`${name}\``);
            }
            this.currentNode = element;
            do {
                this.consumeCharData();
            } while (this.consumeElement()
                || this.consumeContentReference()
                || this.consumeCdataSection()
                || this.consumeProcessingInstruction()
                || this.consumeComment());
            let endTagMark = scanner.charIndex;
            let endTagName;
            if (!scanner.consumeStringFast('</')
                || !(endTagName = this.consumeName())
                || endTagName !== name) {
                scanner.reset(endTagMark);
                throw this.error(`Missing end tag for element ${name}`);
            }
            this.consumeWhitespace();
            if (!scanner.consumeStringFast('>')) {
                throw this.error(`Unclosed end tag for element ${name}`);
            }
            this.currentNode = element.parent;
        }
        return this.addNode(element, startIndex);
    }
    /**
     * Consumes an `Eq` production if possible.
     *
     * @returns Whether an `Eq` production was consumed.
     * @see https://www.w3.org/TR/2008/REC-xml-20081126/#NT-Eq
     */
    consumeEqual() {
        this.consumeWhitespace();
        if (this.scanner.consumeStringFast('=')) {
            this.consumeWhitespace();
            return true;
        }
        return false;
    }
    /**
     * Consumes `Misc` content if possible.
     *
     * @returns Whether anything was consumed.
     * @see https://www.w3.org/TR/2008/REC-xml-20081126/#NT-Misc
     */
    consumeMisc() {
        return this.consumeComment()
            || this.consumeProcessingInstruction()
            || this.consumeWhitespace();
    }
    /**
     * Consumes one or more `Name` characters if possible.
     *
     * @returns `Name` characters, or an empty string if none were consumed.
     * @see https://www.w3.org/TR/2008/REC-xml-20081126/#NT-Name
     */
    consumeName() {
        return syntax.isNameStartChar(this.scanner.peek())
            ? this.scanner.consumeMatchFn(syntax.isNameChar)
            : emptyString;
    }
    /**
     * Consumes a processing instruction if possible.
     *
     * @returns Whether a processing instruction was consumed.
     * @see https://www.w3.org/TR/2008/REC-xml-20081126/#sec-pi
     */
    consumeProcessingInstruction() {
        let { scanner } = this;
        let startIndex = scanner.charIndex;
        if (!scanner.consumeStringFast('<?')) {
            return false;
        }
        let name = this.consumeName();
        if (name) {
            if (name.toLowerCase() === 'xml') {
                scanner.reset(startIndex);
                throw this.error("XML declaration isn't allowed here");
            }
        }
        else {
            throw this.error('Invalid processing instruction');
        }
        if (!this.consumeWhitespace()) {
            if (scanner.consumeStringFast('?>')) {
                return this.addNode(new XmlProcessingInstruction_js_1.XmlProcessingInstruction(name), startIndex);
            }
            throw this.error('Whitespace is required after a processing instruction name');
        }
        let content = scanner.consumeUntilString('?>');
        this.validateChars(content);
        if (!scanner.consumeStringFast('?>')) {
            throw this.error('Unterminated processing instruction');
        }
        return this.addNode(new XmlProcessingInstruction_js_1.XmlProcessingInstruction(name, normalizeLineBreaks(content)), startIndex);
    }
    /**
     * Consumes a prolog if possible.
     *
     * @returns Whether a prolog was consumed.
     * @see https://www.w3.org/TR/2008/REC-xml-20081126/#sec-prolog-dtd
     */
    consumeProlog() {
        let { scanner } = this;
        let startIndex = scanner.charIndex;
        this.consumeXmlDeclaration();
        while (this.consumeMisc()) { } // eslint-disable-line no-empty
        if (this.consumeDoctypeDeclaration()) {
            while (this.consumeMisc()) { } // eslint-disable-line no-empty
        }
        return startIndex < scanner.charIndex;
    }
    /**
     * Consumes a public identifier literal if possible.
     *
     * @returns
     *   Value of the public identifier literal minus quotes, or `false` if
     *   nothing was consumed. An empty string indicates that a public id literal
     *   was consumed but was empty.
     *
     * @see https://www.w3.org/TR/2008/REC-xml-20081126/#NT-PubidLiteral
     */
    consumePubidLiteral() {
        let startIndex = this.scanner.charIndex;
        let value = this.consumeSystemLiteral();
        if (value !== false && !/^[-\x20\r\na-zA-Z0-9'()+,./:=?;!*#@$_%]*$/.test(value)) {
            this.scanner.reset(startIndex);
            throw this.error('Invalid character in public identifier');
        }
        return value;
    }
    /**
     * Consumes a reference if possible.
     *
     * This differs from `consumeContentReference()` in that a consumed reference
     * will be returned rather than added to the document.
     *
     * @returns
     *   Parsed reference value, or `false` if nothing was consumed (to
     *   distinguish from a reference that resolves to an empty string).
     *
     * @see https://www.w3.org/TR/2008/REC-xml-20081126/#NT-Reference
     */
    consumeReference() {
        let { scanner } = this;
        if (!scanner.consumeStringFast('&')) {
            return false;
        }
        let ref = scanner.consumeMatchFn(syntax.isReferenceChar);
        if (scanner.consume() !== ';') {
            throw this.error('Unterminated reference (a reference must end with `;`)');
        }
        let parsedValue;
        if (ref[0] === '#') {
            // This is a character reference.
            let codePoint = ref[1] === 'x'
                ? parseInt(ref.slice(2), 16) // Hex codepoint.
                : parseInt(ref.slice(1), 10); // Decimal codepoint.
            if (isNaN(codePoint)) {
                throw this.error('Invalid character reference');
            }
            if (!syntax.isXmlCodePoint(codePoint)) {
                throw this.error('Character reference resolves to an invalid character');
            }
            parsedValue = String.fromCodePoint(codePoint);
        }
        else {
            // This is an entity reference.
            parsedValue = syntax.predefinedEntities[ref];
            if (parsedValue === undefined) {
                let { ignoreUndefinedEntities, resolveUndefinedEntity, } = this.options;
                let wrappedRef = `&${ref};`; // for backcompat with <= 2.x
                if (resolveUndefinedEntity) {
                    let resolvedValue = resolveUndefinedEntity(wrappedRef);
                    if (resolvedValue !== null && resolvedValue !== undefined) {
                        let type = typeof resolvedValue;
                        if (type !== 'string') {
                            throw new TypeError(`\`resolveUndefinedEntity()\` must return a string, \`null\`, or \`undefined\`, but returned a value of type ${type}`);
                        }
                        return resolvedValue;
                    }
                }
                if (ignoreUndefinedEntities) {
                    return wrappedRef;
                }
                scanner.reset(-wrappedRef.length);
                throw this.error(`Named entity isn't defined: ${wrappedRef}`);
            }
        }
        return parsedValue;
    }
    /**
     * Consumes a `SystemLiteral` if possible.
     *
     * A `SystemLiteral` is similar to an attribute value, but allows the
     * characters `<` and `&` and doesn't replace references.
     *
     * @returns
     *   Value of the `SystemLiteral` minus quotes, or `false` if nothing was
     *   consumed. An empty string indicates that a `SystemLiteral` was consumed
     *   but was empty.
     *
     * @see https://www.w3.org/TR/2008/REC-xml-20081126/#NT-SystemLiteral
     */
    consumeSystemLiteral() {
        let { scanner } = this;
        let quote = scanner.consumeStringFast('"') || scanner.consumeStringFast("'");
        if (!quote) {
            return false;
        }
        let value = scanner.consumeUntilString(quote);
        this.validateChars(value);
        if (!scanner.consumeStringFast(quote)) {
            throw this.error('Missing end quote');
        }
        return value;
    }
    /**
     * Consumes one or more whitespace characters if possible.
     *
     * @returns Whether any whitespace characters were consumed.
     * @see https://www.w3.org/TR/2008/REC-xml-20081126/#white
     */
    consumeWhitespace() {
        return !!this.scanner.consumeMatchFn(syntax.isWhitespace);
    }
    /**
     * Consumes an XML declaration if possible.
     *
     * @returns Whether an XML declaration was consumed.
     * @see https://www.w3.org/TR/2008/REC-xml-20081126/#NT-XMLDecl
     */
    consumeXmlDeclaration() {
        let { scanner } = this;
        let startIndex = scanner.charIndex;
        if (!scanner.consumeStringFast('<?xml')) {
            return false;
        }
        if (!this.consumeWhitespace()) {
            throw this.error('Invalid XML declaration');
        }
        let version = !!scanner.consumeStringFast('version')
            && this.consumeEqual()
            && this.consumeSystemLiteral();
        if (version === false) {
            throw this.error('XML version is missing or invalid');
        }
        else if (!/^1\.[0-9]+$/.test(version)) {
            throw this.error('Invalid character in version number');
        }
        let encoding;
        let standalone;
        if (this.consumeWhitespace()) {
            encoding = !!scanner.consumeStringFast('encoding')
                && this.consumeEqual()
                && this.consumeSystemLiteral();
            if (encoding) {
                this.consumeWhitespace();
            }
            standalone = !!scanner.consumeStringFast('standalone')
                && this.consumeEqual()
                && this.consumeSystemLiteral();
            if (standalone) {
                if (standalone !== 'yes' && standalone !== 'no') {
                    throw this.error('Only "yes" and "no" are permitted as values of `standalone`');
                }
                this.consumeWhitespace();
            }
        }
        if (!scanner.consumeStringFast('?>')) {
            throw this.error('Invalid or unclosed XML declaration');
        }
        return this.options.preserveXmlDeclaration
            ? this.addNode(new XmlDeclaration_js_1.XmlDeclaration(version, encoding || undefined, standalone || undefined), startIndex)
            : true;
    }
    /**
     * Returns an `XmlError` for the current scanner position.
     */
    error(message) {
        let { scanner } = this;
        return new XmlError_js_1.XmlError(message, scanner.charIndex, scanner.string);
    }
    /**
     * Throws an invalid character error if any character in the given _string_
     * isn't a valid XML character.
     */
    validateChars(string) {
        let { length } = string;
        for (let i = 0; i < length; ++i) {
            let cp = string.codePointAt(i);
            if (!syntax.isXmlCodePoint(cp)) {
                this.scanner.reset(-([...string].length - i));
                throw this.error('Invalid character');
            }
            if (cp > 65535) {
                i += 1;
            }
        }
    }
}
exports.Parser = Parser;
// -- Private Functions --------------------------------------------------------
/**
 * Normalizes line breaks in the given text by replacing CRLF sequences and lone
 * CR characters with LF characters.
 */
function normalizeLineBreaks(text) {
    let i = 0;
    while ((i = text.indexOf('\r', i)) !== -1) {
        text = text[i + 1] === '\n'
            ? text.slice(0, i) + text.slice(i + 1)
            : text.slice(0, i) + '\n' + text.slice(i + 1);
    }
    return text;
}
//# sourceMappingURL=Parser.js.map

/***/ }),

/***/ 4902:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.StringScanner = void 0;
const emptyString = '';
const surrogatePair = /[\uD800-\uDBFF][\uDC00-\uDFFF]/g;
/** @private */
class StringScanner {
    constructor(string) {
        this.charCount = this.charLength(string, true);
        this.charIndex = 0;
        this.length = string.length;
        this.multiByteMode = this.charCount !== this.length;
        this.string = string;
        if (this.multiByteMode) {
            let charsToBytes = [];
            // Create a mapping of character indexes to byte indexes. Since the string
            // contains multibyte characters, a byte index may not necessarily align
            // with a character index.
            for (let byteIndex = 0, charIndex = 0; charIndex < this.charCount; ++charIndex) {
                charsToBytes[charIndex] = byteIndex;
                byteIndex += string.codePointAt(byteIndex) > 65535 ? 2 : 1;
            }
            this.charsToBytes = charsToBytes;
        }
    }
    /**
     * Whether the current character index is at the end of the input string.
     */
    get isEnd() {
        return this.charIndex >= this.charCount;
    }
    // -- Protected Methods ------------------------------------------------------
    /**
     * Returns the number of characters in the given string, which may differ from
     * the byte length if the string contains multibyte characters.
     */
    charLength(string, multiByteSafe = this.multiByteMode) {
        // We could get the char length with `[ ...string ].length`, but that's
        // actually slower than replacing surrogate pairs with single-byte
        // characters and then counting the result.
        return multiByteSafe
            ? string.replace(surrogatePair, '_').length
            : string.length;
    }
    // -- Public Methods ---------------------------------------------------------
    /**
     * Advances the scanner by the given number of characters, stopping if the end
     * of the string is reached.
     */
    advance(count = 1) {
        this.charIndex = Math.min(this.charCount, this.charIndex + count);
    }
    /**
     * Returns the byte index of the given character index in the string. The two
     * may differ in strings that contain multibyte characters.
     */
    charIndexToByteIndex(charIndex = this.charIndex) {
        return this.multiByteMode
            ? this.charsToBytes[charIndex] ?? Infinity
            : charIndex;
    }
    /**
     * Consumes and returns the given number of characters if possible, advancing
     * the scanner and stopping if the end of the string is reached.
     *
     * If no characters could be consumed, an empty string will be returned.
     */
    consume(count = 1) {
        let chars = this.peek(count);
        this.advance(count);
        return chars;
    }
    /**
     * Consumes a match for the given sticky regex, advances the scanner, updates
     * the `lastIndex` property of the regex, and returns the matching string.
     *
     * The regex must have a sticky flag ("y") so that its `lastIndex` prop can be
     * used to anchor the match at the current scanner position.
     *
     * Returns the consumed string, or an empty string if nothing was consumed.
     */
    consumeMatch(regex) {
        if (!regex.sticky) {
            throw new Error('`regex` must have a sticky flag ("y")');
        }
        regex.lastIndex = this.charIndexToByteIndex();
        let result = regex.exec(this.string);
        if (result === null || result.length === 0) {
            return emptyString;
        }
        let match = result[0];
        this.advance(this.charLength(match));
        return match;
    }
    /**
     * Consumes and returns all characters for which the given function returns a
     * truthy value, stopping on the first falsy return value or if the end of the
     * input is reached.
     */
    consumeMatchFn(fn) {
        let char;
        let match = emptyString;
        while ((char = this.peek()) && fn(char)) {
            match += char;
            this.advance();
        }
        return match;
    }
    /**
     * Consumes the given string if it exists at the current character index, and
     * advances the scanner.
     *
     * If the given string doesn't exist at the current character index, an empty
     * string will be returned and the scanner will not be advanced.
     */
    consumeString(stringToConsume) {
        if (this.consumeStringFast(stringToConsume)) {
            return stringToConsume;
        }
        if (this.multiByteMode) {
            let { length } = stringToConsume;
            let charLengthToMatch = this.charLength(stringToConsume);
            if (charLengthToMatch !== length
                && stringToConsume === this.peek(charLengthToMatch)) {
                this.advance(charLengthToMatch);
                return stringToConsume;
            }
        }
        return emptyString;
    }
    /**
     * Does the same thing as `consumeString()`, but doesn't support consuming
     * multibyte characters. This can be faster if you only need to match single
     * byte characters.
     */
    consumeStringFast(stringToConsume) {
        let { length } = stringToConsume;
        if (this.peek(length) === stringToConsume) {
            this.advance(length);
            return stringToConsume;
        }
        return emptyString;
    }
    /**
     * Consumes characters until the given global regex is matched, advancing the
     * scanner up to (but not beyond) the beginning of the match. If the regex
     * doesn't match, nothing will be consumed.
     *
     * Returns the consumed string, or an empty string if nothing was consumed.
     */
    consumeUntilMatch(regex) {
        let restOfString = this.string.slice(this.charIndexToByteIndex());
        let matchByteIndex = restOfString.search(regex);
        if (matchByteIndex <= 0) {
            return emptyString;
        }
        let result = restOfString.slice(0, matchByteIndex);
        this.advance(this.charLength(result));
        return result;
    }
    /**
     * Consumes characters until the given string is found, advancing the scanner
     * up to (but not beyond) that point. If the string is never found, nothing
     * will be consumed.
     *
     * Returns the consumed string, or an empty string if nothing was consumed.
     */
    consumeUntilString(searchString) {
        let { string } = this;
        let byteIndex = this.charIndexToByteIndex();
        let matchByteIndex = string.indexOf(searchString, byteIndex);
        if (matchByteIndex <= 0) {
            return emptyString;
        }
        let result = string.slice(byteIndex, matchByteIndex);
        this.advance(this.charLength(result));
        return result;
    }
    /**
     * Returns the given number of characters starting at the current character
     * index, without advancing the scanner and without exceeding the end of the
     * input string.
     */
    peek(count = 1) {
        let { charIndex, multiByteMode, string } = this;
        if (multiByteMode) {
            // Inlining this comparison instead of checking `this.isEnd` improves perf
            // slightly since `peek()` is called so frequently.
            if (charIndex >= this.charCount) {
                return emptyString;
            }
            return string.slice(this.charIndexToByteIndex(charIndex), this.charIndexToByteIndex(charIndex + count));
        }
        return string.slice(charIndex, charIndex + count);
    }
    /**
     * Resets the scanner position to the given character _index_, or to the start
     * of the input string if no index is given.
     *
     * If _index_ is negative, the scanner position will be moved backward by that
     * many characters, stopping if the beginning of the string is reached.
     */
    reset(index = 0) {
        this.charIndex = index >= 0
            ? Math.min(this.charCount, index)
            : Math.max(0, this.charIndex + index);
    }
}
exports.StringScanner = StringScanner;
//# sourceMappingURL=StringScanner.js.map

/***/ }),

/***/ 3769:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.XmlCdata = void 0;
const XmlNode_js_1 = __nccwpck_require__(5899);
const XmlText_js_1 = __nccwpck_require__(2247);
/**
 * A CDATA section within an XML document.
 */
class XmlCdata extends XmlText_js_1.XmlText {
    get type() {
        return XmlNode_js_1.XmlNode.TYPE_CDATA;
    }
}
exports.XmlCdata = XmlCdata;
//# sourceMappingURL=XmlCdata.js.map

/***/ }),

/***/ 1306:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.XmlComment = void 0;
const XmlNode_js_1 = __nccwpck_require__(5899);
/**
 * A comment within an XML document.
 */
class XmlComment extends XmlNode_js_1.XmlNode {
    constructor(content = '') {
        super();
        this.content = content;
    }
    get type() {
        return XmlNode_js_1.XmlNode.TYPE_COMMENT;
    }
    toJSON() {
        return Object.assign(XmlNode_js_1.XmlNode.prototype.toJSON.call(this), {
            content: this.content,
        });
    }
}
exports.XmlComment = XmlComment;
//# sourceMappingURL=XmlComment.js.map

/***/ }),

/***/ 1383:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.XmlDeclaration = void 0;
const XmlNode_js_1 = __nccwpck_require__(5899);
/**
 * An XML declaration within an XML document.
 *
 * @example
 *
 * ```xml
 * <?xml version="1.0" encoding="UTF-8"?>
 * ```
 */
class XmlDeclaration extends XmlNode_js_1.XmlNode {
    constructor(version, encoding, standalone) {
        super();
        this.version = version;
        this.encoding = encoding ?? null;
        this.standalone = standalone ?? null;
    }
    get type() {
        return XmlNode_js_1.XmlNode.TYPE_XML_DECLARATION;
    }
    toJSON() {
        let json = XmlNode_js_1.XmlNode.prototype.toJSON.call(this);
        json.version = this.version;
        for (let key of ['encoding', 'standalone']) {
            if (this[key] !== null) {
                json[key] = this[key];
            }
        }
        return json;
    }
}
exports.XmlDeclaration = XmlDeclaration;
//# sourceMappingURL=XmlDeclaration.js.map

/***/ }),

/***/ 5455:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.XmlDocument = void 0;
const XmlElement_js_1 = __nccwpck_require__(7265);
const XmlNode_js_1 = __nccwpck_require__(5899);
/**
 * Represents an XML document. All elements within the document are descendants
 * of this node.
 */
class XmlDocument extends XmlNode_js_1.XmlNode {
    constructor(children = []) {
        super();
        this.children = children;
    }
    get document() {
        return this;
    }
    /**
     * Root element of this document, or `null` if this document is empty.
     */
    get root() {
        for (let child of this.children) {
            if (child instanceof XmlElement_js_1.XmlElement) {
                return child;
            }
        }
        return null;
    }
    /**
     * Text content of this document and all its descendants.
     */
    get text() {
        return this.children
            .map(child => 'text' in child ? child.text : '')
            .join('');
    }
    get type() {
        return XmlNode_js_1.XmlNode.TYPE_DOCUMENT;
    }
    toJSON() {
        return Object.assign(XmlNode_js_1.XmlNode.prototype.toJSON.call(this), {
            children: this.children.map(child => child.toJSON()),
        });
    }
}
exports.XmlDocument = XmlDocument;
//# sourceMappingURL=XmlDocument.js.map

/***/ }),

/***/ 5777:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.XmlDocumentType = void 0;
const XmlNode_js_1 = __nccwpck_require__(5899);
/**
 * A document type declaration within an XML document.
 *
 * @example
 *
 * ```xml
 * <!DOCTYPE kittens [
 *   <!ELEMENT kittens (#PCDATA)>
 * ]>
 * ```
 */
class XmlDocumentType extends XmlNode_js_1.XmlNode {
    constructor(name, publicId, systemId, internalSubset) {
        super();
        this.name = name;
        this.publicId = publicId ?? null;
        this.systemId = systemId ?? null;
        this.internalSubset = internalSubset ?? null;
    }
    get type() {
        return XmlNode_js_1.XmlNode.TYPE_DOCUMENT_TYPE;
    }
    toJSON() {
        let json = XmlNode_js_1.XmlNode.prototype.toJSON.call(this);
        json.name = this.name;
        for (let key of ['publicId', 'systemId', 'internalSubset']) {
            if (this[key] !== null) {
                json[key] = this[key];
            }
        }
        return json;
    }
}
exports.XmlDocumentType = XmlDocumentType;
//# sourceMappingURL=XmlDocumentType.js.map

/***/ }),

/***/ 7265:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.XmlElement = void 0;
const XmlNode_js_1 = __nccwpck_require__(5899);
/**
 * Element in an XML document.
 */
class XmlElement extends XmlNode_js_1.XmlNode {
    constructor(name, attributes = Object.create(null), children = []) {
        super();
        this.name = name;
        this.attributes = attributes;
        this.children = children;
    }
    /**
     * Whether this element is empty (meaning it has no children).
     */
    get isEmpty() {
        return this.children.length === 0;
    }
    get preserveWhitespace() {
        let node = this; // eslint-disable-line @typescript-eslint/no-this-alias
        while (node instanceof XmlElement) {
            if ('xml:space' in node.attributes) {
                return node.attributes['xml:space'] === 'preserve';
            }
            node = node.parent;
        }
        return false;
    }
    /**
     * Text content of this element and all its descendants.
     */
    get text() {
        return this.children
            .map(child => 'text' in child ? child.text : '')
            .join('');
    }
    get type() {
        return XmlNode_js_1.XmlNode.TYPE_ELEMENT;
    }
    toJSON() {
        return Object.assign(XmlNode_js_1.XmlNode.prototype.toJSON.call(this), {
            name: this.name,
            attributes: this.attributes,
            children: this.children.map(child => child.toJSON()),
        });
    }
}
exports.XmlElement = XmlElement;
//# sourceMappingURL=XmlElement.js.map

/***/ }),

/***/ 706:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.XmlError = void 0;
/**
 * An error that occurred while parsing XML.
 */
class XmlError extends Error {
    constructor(message, charIndex, xml) {
        let column = 1;
        let excerpt = '';
        let line = 1;
        // Find the line and column where the error occurred.
        for (let i = 0; i < charIndex; ++i) {
            let char = xml[i];
            if (char === '\n') {
                column = 1;
                excerpt = '';
                line += 1;
            }
            else {
                column += 1;
                excerpt += char;
            }
        }
        let eol = xml.indexOf('\n', charIndex);
        excerpt += eol === -1
            ? xml.slice(charIndex)
            : xml.slice(charIndex, eol);
        let excerptStart = 0;
        // Keep the excerpt below 50 chars, but always keep the error position in
        // view.
        if (excerpt.length > 50) {
            if (column < 40) {
                excerpt = excerpt.slice(0, 50);
            }
            else {
                excerptStart = column - 20;
                excerpt = excerpt.slice(excerptStart, column + 30);
            }
        }
        super(`${message} (line ${line}, column ${column})\n`
            + `  ${excerpt}\n`
            + ' '.repeat(column - excerptStart + 1) + '^\n');
        this.column = column;
        this.excerpt = excerpt;
        this.line = line;
        this.name = 'XmlError';
        this.pos = charIndex;
    }
}
exports.XmlError = XmlError;
//# sourceMappingURL=XmlError.js.map

/***/ }),

/***/ 5899:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.XmlNode = void 0;
/**
 * Base interface for a node in an XML document.
 */
class XmlNode {
    constructor() {
        /**
         * Parent node of this node, or `null` if this node has no parent.
         */
        this.parent = null;
        /**
         * Starting byte offset of this node in the original XML string, or `-1` if
         * the offset is unknown.
         */
        this.start = -1;
        /**
         * Ending byte offset of this node in the original XML string, or `-1` if the
         * offset is unknown.
         */
        this.end = -1;
    }
    /**
     * Document that contains this node, or `null` if this node is not associated
     * with a document.
     */
    get document() {
        return this.parent?.document ?? null;
    }
    /**
     * Whether this node is the root node of the document (also known as the
     * document element).
     */
    get isRootNode() {
        return this.parent !== null
            && this.parent === this.document
            && this.type === XmlNode.TYPE_ELEMENT;
    }
    /**
     * Whether whitespace should be preserved in the content of this element and
     * its children.
     *
     * This is influenced by the value of the special `xml:space` attribute, and
     * will be `true` for any node whose `xml:space` attribute is set to
     * "preserve". If a node has no such attribute, it will inherit the value of
     * the nearest ancestor that does (if any).
     *
     * @see https://www.w3.org/TR/2008/REC-xml-20081126/#sec-white-space
     */
    get preserveWhitespace() {
        return !!this.parent?.preserveWhitespace;
    }
    /**
     * Type of this node.
     *
     * The value of this property is a string that matches one of the static
     * `TYPE_*` properties on the `XmlNode` class (e.g. `TYPE_ELEMENT`,
     * `TYPE_TEXT`, etc.).
     *
     * The `XmlNode` class itself is a base class and doesn't have its own type
     * name.
     */
    get type() {
        return '';
    }
    /**
     * Returns a JSON-serializable object representing this node, minus properties
     * that could result in circular references.
     */
    toJSON() {
        let json = {
            type: this.type,
        };
        if (this.isRootNode) {
            json.isRootNode = true;
        }
        if (this.preserveWhitespace) {
            json.preserveWhitespace = true;
        }
        if (this.start !== -1) {
            json.start = this.start;
            json.end = this.end;
        }
        return json;
    }
}
exports.XmlNode = XmlNode;
/**
 * Type value for an `XmlCdata` node.
 */
XmlNode.TYPE_CDATA = 'cdata';
/**
 * Type value for an `XmlComment` node.
 */
XmlNode.TYPE_COMMENT = 'comment';
/**
 * Type value for an `XmlDocument` node.
 */
XmlNode.TYPE_DOCUMENT = 'document';
/**
 * Type value for an `XmlDocumentType` node.
 */
XmlNode.TYPE_DOCUMENT_TYPE = 'doctype';
/**
 * Type value for an `XmlElement` node.
 */
XmlNode.TYPE_ELEMENT = 'element';
/**
 * Type value for an `XmlProcessingInstruction` node.
 */
XmlNode.TYPE_PROCESSING_INSTRUCTION = 'pi';
/**
 * Type value for an `XmlText` node.
 */
XmlNode.TYPE_TEXT = 'text';
/**
 * Type value for an `XmlDeclaration` node.
 */
XmlNode.TYPE_XML_DECLARATION = 'xmldecl';
//# sourceMappingURL=XmlNode.js.map

/***/ }),

/***/ 3688:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.XmlProcessingInstruction = void 0;
const XmlNode_js_1 = __nccwpck_require__(5899);
/**
 * A processing instruction within an XML document.
 */
class XmlProcessingInstruction extends XmlNode_js_1.XmlNode {
    constructor(name, content = '') {
        super();
        this.name = name;
        this.content = content;
    }
    get type() {
        return XmlNode_js_1.XmlNode.TYPE_PROCESSING_INSTRUCTION;
    }
    toJSON() {
        return Object.assign(XmlNode_js_1.XmlNode.prototype.toJSON.call(this), {
            name: this.name,
            content: this.content,
        });
    }
}
exports.XmlProcessingInstruction = XmlProcessingInstruction;
//# sourceMappingURL=XmlProcessingInstruction.js.map

/***/ }),

/***/ 2247:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.XmlText = void 0;
const XmlNode_js_1 = __nccwpck_require__(5899);
/**
 * Text content within an XML document.
 */
class XmlText extends XmlNode_js_1.XmlNode {
    constructor(text = '') {
        super();
        this.text = text;
    }
    get type() {
        return XmlNode_js_1.XmlNode.TYPE_TEXT;
    }
    toJSON() {
        return Object.assign(XmlNode_js_1.XmlNode.prototype.toJSON.call(this), {
            text: this.text,
        });
    }
}
exports.XmlText = XmlText;
//# sourceMappingURL=XmlText.js.map

/***/ }),

/***/ 3420:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.isXmlCodePoint = exports.isWhitespace = exports.isReferenceChar = exports.isNameStartChar = exports.isNameChar = exports.predefinedEntities = exports.endCharData = exports.attValueNormalizedWhitespace = exports.attValueCharSingleQuote = exports.attValueCharDoubleQuote = void 0;
/**
 * Regular expression that matches one or more `AttValue` characters in a
 * double-quoted attribute value.
 *
 * @see https://www.w3.org/TR/2008/REC-xml-20081126/#NT-AttValue
 */
exports.attValueCharDoubleQuote = /[^"&<]+/y;
/**
 * Regular expression that matches one or more `AttValue` characters in a
 * single-quoted attribute value.
 *
 * @see https://www.w3.org/TR/2008/REC-xml-20081126/#NT-AttValue
 */
exports.attValueCharSingleQuote = /[^'&<]+/y;
/**
 * Regular expression that matches a whitespace character that should be
 * normalized to a space character in an attribute value.
 *
 * @see https://www.w3.org/TR/2008/REC-xml-20081126/#AVNormalize
 */
exports.attValueNormalizedWhitespace = /\r\n|[\n\r\t]/g;
/**
 * Regular expression that matches one or more characters that signal the end of
 * XML `CharData` content.
 *
 * @see https://www.w3.org/TR/2008/REC-xml-20081126/#dt-chardata
 */
exports.endCharData = /<|&|]]>/;
/**
 * Mapping of predefined entity names to their replacement values.
 *
 * @see https://www.w3.org/TR/2008/REC-xml-20081126/#sec-predefined-ent
 */
exports.predefinedEntities = Object.freeze(Object.assign(Object.create(null), {
    amp: '&',
    apos: "'",
    gt: '>',
    lt: '<',
    quot: '"',
}));
/**
 * Returns `true` if _char_ is an XML `NameChar`, `false` if it isn't.
 *
 * @see https://www.w3.org/TR/2008/REC-xml-20081126/#NT-NameChar
 */
function isNameChar(char) {
    let cp = getCodePoint(char);
    // Including the most common NameStartChars here improves performance
    // slightly.
    return (cp >= 0x61 && cp <= 0x7A) // a-z
        || (cp >= 0x41 && cp <= 0x5A) // A-Z
        || (cp >= 0x30 && cp <= 0x39) // 0-9
        || cp === 0x2D // -
        || cp === 0x2E // .
        || cp === 0xB7
        || (cp >= 0x300 && cp <= 0x36F)
        || (cp >= 0x203F && cp <= 0x2040)
        || isNameStartChar(char, cp);
}
exports.isNameChar = isNameChar;
/**
 * Returns `true` if _char_ is an XML `NameStartChar`, `false` if it isn't.
 *
 * @see https://www.w3.org/TR/2008/REC-xml-20081126/#NT-NameStartChar
 */
function isNameStartChar(char, cp = getCodePoint(char)) {
    return (cp >= 0x61 && cp <= 0x7A) // a-z
        || (cp >= 0x41 && cp <= 0x5A) // A-Z
        || cp === 0x3A // :
        || cp === 0x5F // _
        || (cp >= 0xC0 && cp <= 0xD6)
        || (cp >= 0xD8 && cp <= 0xF6)
        || (cp >= 0xF8 && cp <= 0x2FF)
        || (cp >= 0x370 && cp <= 0x37D)
        || (cp >= 0x37F && cp <= 0x1FFF)
        || (cp >= 0x200C && cp <= 0x200D)
        || (cp >= 0x2070 && cp <= 0x218F)
        || (cp >= 0x2C00 && cp <= 0x2FEF)
        || (cp >= 0x3001 && cp <= 0xD7FF)
        || (cp >= 0xF900 && cp <= 0xFDCF)
        || (cp >= 0xFDF0 && cp <= 0xFFFD)
        || (cp >= 0x10000 && cp <= 0xEFFFF);
}
exports.isNameStartChar = isNameStartChar;
/**
 * Returns `true` if _char_ is a valid reference character (which may appear
 * between `&` and `;` in a reference), `false` otherwise.
 *
 * @see https://www.w3.org/TR/2008/REC-xml-20081126/#sec-references
 */
function isReferenceChar(char) {
    return char === '#' || isNameChar(char);
}
exports.isReferenceChar = isReferenceChar;
/**
 * Returns `true` if _char_ is an XML whitespace character, `false` otherwise.
 *
 * @see https://www.w3.org/TR/2008/REC-xml-20081126/#white
 */
function isWhitespace(char) {
    let cp = getCodePoint(char);
    return cp === 0x20
        || cp === 0x9
        || cp === 0xA
        || cp === 0xD;
}
exports.isWhitespace = isWhitespace;
/**
 * Returns `true` if _codepoint_ is a valid XML `Char` code point, `false`
 * otherwise.
 *
 * @see https://www.w3.org/TR/2008/REC-xml-20081126/#NT-Char
 */
function isXmlCodePoint(cp) {
    return cp === 0x9
        || cp === 0xA
        || cp === 0xD
        || (cp >= 0x20 && cp <= 0xD7FF)
        || (cp >= 0xE000 && cp <= 0xFFFD)
        || (cp >= 0x10000 && cp <= 0x10FFFF);
}
exports.isXmlCodePoint = isXmlCodePoint;
/**
 * Returns the Unicode code point value of the given character, or `-1` if
 * _char_ is empty.
 */
function getCodePoint(char) {
    return char.codePointAt(0) || -1;
}
//# sourceMappingURL=syntax.js.map

/***/ }),

/***/ 2162:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
//# sourceMappingURL=types.js.map

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
var t=__nccwpck_require__(9491);class e extends Error{constructor(t){super(t||"yargs error"),this.name="YError",Error.captureStackTrace&&Error.captureStackTrace(this,e)}}let s,i=[];function n(t,o,a,h){s=h;let l={};if(Object.prototype.hasOwnProperty.call(t,"extends")){if("string"!=typeof t.extends)return l;const r=/\.json|\..*rc$/.test(t.extends);let h=null;if(r)h=function(t,e){return s.path.resolve(t,e)}(o,t.extends);else try{h=/*require.resolve*/(__nccwpck_require__(9167).resolve(t.extends))}catch(e){return t}!function(t){if(i.indexOf(t)>-1)throw new e(`Circular extended configurations: '${t}'.`)}(h),i.push(h),l=r?JSON.parse(s.readFileSync(h,"utf8")):__nccwpck_require__(9167)(t.extends),delete t.extends,l=n(l,s.path.dirname(h),a,s)}return i=[],a?r(l,t):Object.assign({},l,t)}function r(t,e){const s={};function i(t){return t&&"object"==typeof t&&!Array.isArray(t)}Object.assign(s,t);for(const n of Object.keys(e))i(e[n])&&i(s[n])?s[n]=r(t[n],e[n]):s[n]=e[n];return s}function o(t){const e=t.replace(/\s{2,}/g," ").split(/\s+(?![^[]*]|[^<]*>)/),s=/\.*[\][<>]/g,i=e.shift();if(!i)throw new Error(`No command found in: ${t}`);const n={cmd:i.replace(s,""),demanded:[],optional:[]};return e.forEach(((t,i)=>{let r=!1;t=t.replace(/\s/g,""),/\.+[\]>]/.test(t)&&i===e.length-1&&(r=!0),/^\[/.test(t)?n.optional.push({cmd:t.replace(s,"").split("|"),variadic:r}):n.demanded.push({cmd:t.replace(s,"").split("|"),variadic:r})})),n}const a=["first","second","third","fourth","fifth","sixth"];function h(t,s,i){try{let n=0;const[r,a,h]="object"==typeof t?[{demanded:[],optional:[]},t,s]:[o(`cmd ${t}`),s,i],f=[].slice.call(a);for(;f.length&&void 0===f[f.length-1];)f.pop();const d=h||f.length;if(d<r.demanded.length)throw new e(`Not enough arguments provided. Expected ${r.demanded.length} but received ${f.length}.`);const u=r.demanded.length+r.optional.length;if(d>u)throw new e(`Too many arguments provided. Expected max ${u} but received ${d}.`);r.demanded.forEach((t=>{const e=l(f.shift());0===t.cmd.filter((t=>t===e||"*"===t)).length&&c(e,t.cmd,n),n+=1})),r.optional.forEach((t=>{if(0===f.length)return;const e=l(f.shift());0===t.cmd.filter((t=>t===e||"*"===t)).length&&c(e,t.cmd,n),n+=1}))}catch(t){console.warn(t.stack)}}function l(t){return Array.isArray(t)?"array":null===t?"null":typeof t}function c(t,s,i){throw new e(`Invalid ${a[i]||"manyith"} argument. Expected ${s.join(" or ")} but received ${t}.`)}function f(t){return!!t&&!!t.then&&"function"==typeof t.then}function d(t,e,s,i){s.assert.notStrictEqual(t,e,i)}function u(t,e){e.assert.strictEqual(typeof t,"string")}function p(t){return Object.keys(t)}function g(t={},e=(()=>!0)){const s={};return p(t).forEach((i=>{e(i,t[i])&&(s[i]=t[i])})),s}function m(){return process.versions.electron&&!process.defaultApp?0:1}function y(){return process.argv[m()]}var b=Object.freeze({__proto__:null,hideBin:function(t){return t.slice(m()+1)},getProcessArgvBin:y});function v(t,e,s,i){if("a"===s&&!i)throw new TypeError("Private accessor was defined without a getter");if("function"==typeof e?t!==e||!i:!e.has(t))throw new TypeError("Cannot read private member from an object whose class did not declare it");return"m"===s?i:"a"===s?i.call(t):i?i.value:e.get(t)}function O(t,e,s,i,n){if("m"===i)throw new TypeError("Private method is not writable");if("a"===i&&!n)throw new TypeError("Private accessor was defined without a setter");if("function"==typeof e?t!==e||!n:!e.has(t))throw new TypeError("Cannot write private member to an object whose class did not declare it");return"a"===i?n.call(t,s):n?n.value=s:e.set(t,s),s}class w{constructor(t){this.globalMiddleware=[],this.frozens=[],this.yargs=t}addMiddleware(t,e,s=!0,i=!1){if(h("<array|function> [boolean] [boolean] [boolean]",[t,e,s],arguments.length),Array.isArray(t)){for(let i=0;i<t.length;i++){if("function"!=typeof t[i])throw Error("middleware must be a function");const n=t[i];n.applyBeforeValidation=e,n.global=s}Array.prototype.push.apply(this.globalMiddleware,t)}else if("function"==typeof t){const n=t;n.applyBeforeValidation=e,n.global=s,n.mutates=i,this.globalMiddleware.push(t)}return this.yargs}addCoerceMiddleware(t,e){const s=this.yargs.getAliases();return this.globalMiddleware=this.globalMiddleware.filter((t=>{const i=[...s[e]||[],e];return!t.option||!i.includes(t.option)})),t.option=e,this.addMiddleware(t,!0,!0,!0)}getMiddleware(){return this.globalMiddleware}freeze(){this.frozens.push([...this.globalMiddleware])}unfreeze(){const t=this.frozens.pop();void 0!==t&&(this.globalMiddleware=t)}reset(){this.globalMiddleware=this.globalMiddleware.filter((t=>t.global))}}function C(t,e,s,i){return s.reduce(((t,s)=>{if(s.applyBeforeValidation!==i)return t;if(s.mutates){if(s.applied)return t;s.applied=!0}if(f(t))return t.then((t=>Promise.all([t,s(t,e)]))).then((([t,e])=>Object.assign(t,e)));{const i=s(t,e);return f(i)?i.then((e=>Object.assign(t,e))):Object.assign(t,i)}}),t)}function j(t,e,s=(t=>{throw t})){try{const s="function"==typeof t?t():t;return f(s)?s.then((t=>e(t))):e(s)}catch(t){return s(t)}}const M=/(^\*)|(^\$0)/;class _{constructor(t,e,s,i){this.requireCache=new Set,this.handlers={},this.aliasMap={},this.frozens=[],this.shim=i,this.usage=t,this.globalMiddleware=s,this.validation=e}addDirectory(t,e,s,i){"boolean"!=typeof(i=i||{}).recurse&&(i.recurse=!1),Array.isArray(i.extensions)||(i.extensions=["js"]);const n="function"==typeof i.visit?i.visit:t=>t;i.visit=(t,e,s)=>{const i=n(t,e,s);if(i){if(this.requireCache.has(e))return i;this.requireCache.add(e),this.addHandler(i)}return i},this.shim.requireDirectory({require:e,filename:s},t,i)}addHandler(t,e,s,i,n,r){let a=[];const h=function(t){return t?t.map((t=>(t.applyBeforeValidation=!1,t))):[]}(n);if(i=i||(()=>{}),Array.isArray(t))if(function(t){return t.every((t=>"string"==typeof t))}(t))[t,...a]=t;else for(const e of t)this.addHandler(e);else{if(function(t){return"object"==typeof t&&!Array.isArray(t)}(t)){let e=Array.isArray(t.command)||"string"==typeof t.command?t.command:this.moduleName(t);return t.aliases&&(e=[].concat(e).concat(t.aliases)),void this.addHandler(e,this.extractDesc(t),t.builder,t.handler,t.middlewares,t.deprecated)}if(k(s))return void this.addHandler([t].concat(a),e,s.builder,s.handler,s.middlewares,s.deprecated)}if("string"==typeof t){const n=o(t);a=a.map((t=>o(t).cmd));let l=!1;const c=[n.cmd].concat(a).filter((t=>!M.test(t)||(l=!0,!1)));0===c.length&&l&&c.push("$0"),l&&(n.cmd=c[0],a=c.slice(1),t=t.replace(M,n.cmd)),a.forEach((t=>{this.aliasMap[t]=n.cmd})),!1!==e&&this.usage.command(t,e,l,a,r),this.handlers[n.cmd]={original:t,description:e,handler:i,builder:s||{},middlewares:h,deprecated:r,demanded:n.demanded,optional:n.optional},l&&(this.defaultCommand=this.handlers[n.cmd])}}getCommandHandlers(){return this.handlers}getCommands(){return Object.keys(this.handlers).concat(Object.keys(this.aliasMap))}hasDefaultCommand(){return!!this.defaultCommand}runCommand(t,e,s,i,n,r){const o=this.handlers[t]||this.handlers[this.aliasMap[t]]||this.defaultCommand,a=e.getInternalMethods().getContext(),h=a.commands.slice(),l=!t;t&&(a.commands.push(t),a.fullCommands.push(o.original));const c=this.applyBuilderUpdateUsageAndParse(l,o,e,s.aliases,h,i,n,r);return f(c)?c.then((t=>this.applyMiddlewareAndGetResult(l,o,t.innerArgv,a,n,t.aliases,e))):this.applyMiddlewareAndGetResult(l,o,c.innerArgv,a,n,c.aliases,e)}applyBuilderUpdateUsageAndParse(t,e,s,i,n,r,o,a){const h=e.builder;let l=s;if(x(h)){s.getInternalMethods().getUsageInstance().freeze();const c=h(s.getInternalMethods().reset(i),a);if(f(c))return c.then((i=>{var a;return l=(a=i)&&"function"==typeof a.getInternalMethods?i:s,this.parseAndUpdateUsage(t,e,l,n,r,o)}))}else(function(t){return"object"==typeof t})(h)&&(s.getInternalMethods().getUsageInstance().freeze(),l=s.getInternalMethods().reset(i),Object.keys(e.builder).forEach((t=>{l.option(t,h[t])})));return this.parseAndUpdateUsage(t,e,l,n,r,o)}parseAndUpdateUsage(t,e,s,i,n,r){t&&s.getInternalMethods().getUsageInstance().unfreeze(!0),this.shouldUpdateUsage(s)&&s.getInternalMethods().getUsageInstance().usage(this.usageFromParentCommandsCommandHandler(i,e),e.description);const o=s.getInternalMethods().runYargsParserAndExecuteCommands(null,void 0,!0,n,r);return f(o)?o.then((t=>({aliases:s.parsed.aliases,innerArgv:t}))):{aliases:s.parsed.aliases,innerArgv:o}}shouldUpdateUsage(t){return!t.getInternalMethods().getUsageInstance().getUsageDisabled()&&0===t.getInternalMethods().getUsageInstance().getUsage().length}usageFromParentCommandsCommandHandler(t,e){const s=M.test(e.original)?e.original.replace(M,"").trim():e.original,i=t.filter((t=>!M.test(t)));return i.push(s),`$0 ${i.join(" ")}`}handleValidationAndGetResult(t,e,s,i,n,r,o,a){if(!r.getInternalMethods().getHasOutput()){const e=r.getInternalMethods().runValidation(n,a,r.parsed.error,t);s=j(s,(t=>(e(t),t)))}if(e.handler&&!r.getInternalMethods().getHasOutput()){r.getInternalMethods().setHasOutput();const i=!!r.getOptions().configuration["populate--"];r.getInternalMethods().postProcess(s,i,!1,!1),s=j(s=C(s,r,o,!1),(t=>{const s=e.handler(t);return f(s)?s.then((()=>t)):t})),t||r.getInternalMethods().getUsageInstance().cacheHelpMessage(),f(s)&&!r.getInternalMethods().hasParseCallback()&&s.catch((t=>{try{r.getInternalMethods().getUsageInstance().fail(null,t)}catch(t){}}))}return t||(i.commands.pop(),i.fullCommands.pop()),s}applyMiddlewareAndGetResult(t,e,s,i,n,r,o){let a={};if(n)return s;o.getInternalMethods().getHasOutput()||(a=this.populatePositionals(e,s,i,o));const h=this.globalMiddleware.getMiddleware().slice(0).concat(e.middlewares),l=C(s,o,h,!0);return f(l)?l.then((s=>this.handleValidationAndGetResult(t,e,s,i,r,o,h,a))):this.handleValidationAndGetResult(t,e,l,i,r,o,h,a)}populatePositionals(t,e,s,i){e._=e._.slice(s.commands.length);const n=t.demanded.slice(0),r=t.optional.slice(0),o={};for(this.validation.positionalCount(n.length,e._.length);n.length;){const t=n.shift();this.populatePositional(t,e,o)}for(;r.length;){const t=r.shift();this.populatePositional(t,e,o)}return e._=s.commands.concat(e._.map((t=>""+t))),this.postProcessPositionals(e,o,this.cmdToParseOptions(t.original),i),o}populatePositional(t,e,s){const i=t.cmd[0];t.variadic?s[i]=e._.splice(0).map(String):e._.length&&(s[i]=[String(e._.shift())])}cmdToParseOptions(t){const e={array:[],default:{},alias:{},demand:{}},s=o(t);return s.demanded.forEach((t=>{const[s,...i]=t.cmd;t.variadic&&(e.array.push(s),e.default[s]=[]),e.alias[s]=i,e.demand[s]=!0})),s.optional.forEach((t=>{const[s,...i]=t.cmd;t.variadic&&(e.array.push(s),e.default[s]=[]),e.alias[s]=i})),e}postProcessPositionals(t,e,s,i){const n=Object.assign({},i.getOptions());n.default=Object.assign(s.default,n.default);for(const t of Object.keys(s.alias))n.alias[t]=(n.alias[t]||[]).concat(s.alias[t]);n.array=n.array.concat(s.array),n.config={};const r=[];if(Object.keys(e).forEach((t=>{e[t].map((e=>{n.configuration["unknown-options-as-args"]&&(n.key[t]=!0),r.push(`--${t}`),r.push(e)}))})),!r.length)return;const o=Object.assign({},n.configuration,{"populate--":!1}),a=this.shim.Parser.detailed(r,Object.assign({},n,{configuration:o}));if(a.error)i.getInternalMethods().getUsageInstance().fail(a.error.message,a.error);else{const s=Object.keys(e);Object.keys(e).forEach((t=>{s.push(...a.aliases[t])})),Object.keys(a.argv).forEach((n=>{s.includes(n)&&(e[n]||(e[n]=a.argv[n]),!this.isInConfigs(i,n)&&!this.isDefaulted(i,n)&&Object.prototype.hasOwnProperty.call(t,n)&&Object.prototype.hasOwnProperty.call(a.argv,n)&&(Array.isArray(t[n])||Array.isArray(a.argv[n]))?t[n]=[].concat(t[n],a.argv[n]):t[n]=a.argv[n])}))}}isDefaulted(t,e){const{default:s}=t.getOptions();return Object.prototype.hasOwnProperty.call(s,e)||Object.prototype.hasOwnProperty.call(s,this.shim.Parser.camelCase(e))}isInConfigs(t,e){const{configObjects:s}=t.getOptions();return s.some((t=>Object.prototype.hasOwnProperty.call(t,e)))||s.some((t=>Object.prototype.hasOwnProperty.call(t,this.shim.Parser.camelCase(e))))}runDefaultBuilderOn(t){if(!this.defaultCommand)return;if(this.shouldUpdateUsage(t)){const e=M.test(this.defaultCommand.original)?this.defaultCommand.original:this.defaultCommand.original.replace(/^[^[\]<>]*/,"$0 ");t.getInternalMethods().getUsageInstance().usage(e,this.defaultCommand.description)}const e=this.defaultCommand.builder;if(x(e))return e(t,!0);k(e)||Object.keys(e).forEach((s=>{t.option(s,e[s])}))}moduleName(t){const e=function(t){if(false){}for(let e,s=0,i=Object.keys(__nccwpck_require__.c);s<i.length;s++)if(e=__nccwpck_require__.c[i[s]],e.exports===t)return e;return null}(t);if(!e)throw new Error(`No command name given for module: ${this.shim.inspect(t)}`);return this.commandFromFilename(e.filename)}commandFromFilename(t){return this.shim.path.basename(t,this.shim.path.extname(t))}extractDesc({describe:t,description:e,desc:s}){for(const i of[t,e,s]){if("string"==typeof i||!1===i)return i;d(i,!0,this.shim)}return!1}freeze(){this.frozens.push({handlers:this.handlers,aliasMap:this.aliasMap,defaultCommand:this.defaultCommand})}unfreeze(){const t=this.frozens.pop();d(t,void 0,this.shim),({handlers:this.handlers,aliasMap:this.aliasMap,defaultCommand:this.defaultCommand}=t)}reset(){return this.handlers={},this.aliasMap={},this.defaultCommand=void 0,this.requireCache=new Set,this}}function k(t){return"object"==typeof t&&!!t.builder&&"function"==typeof t.handler}function x(t){return"function"==typeof t}function E(t){"undefined"!=typeof process&&[process.stdout,process.stderr].forEach((e=>{const s=e;s._handle&&s.isTTY&&"function"==typeof s._handle.setBlocking&&s._handle.setBlocking(t)}))}function A(t){return"boolean"==typeof t}function P(t,s){const i=s.y18n.__,n={},r=[];n.failFn=function(t){r.push(t)};let o=null,a=null,h=!0;n.showHelpOnFail=function(e=!0,s){const[i,r]="string"==typeof e?[!0,e]:[e,s];return t.getInternalMethods().isGlobalContext()&&(a=r),o=r,h=i,n};let l=!1;n.fail=function(s,i){const c=t.getInternalMethods().getLoggerInstance();if(!r.length){if(t.getExitProcess()&&E(!0),!l){l=!0,h&&(t.showHelp("error"),c.error()),(s||i)&&c.error(s||i);const e=o||a;e&&((s||i)&&c.error(""),c.error(e))}if(i=i||new e(s),t.getExitProcess())return t.exit(1);if(t.getInternalMethods().hasParseCallback())return t.exit(1,i);throw i}for(let t=r.length-1;t>=0;--t){const e=r[t];if(A(e)){if(i)throw i;if(s)throw Error(s)}else e(s,i,n)}};let c=[],f=!1;n.usage=(t,e)=>null===t?(f=!0,c=[],n):(f=!1,c.push([t,e||""]),n),n.getUsage=()=>c,n.getUsageDisabled=()=>f,n.getPositionalGroupName=()=>i("Positionals:");let d=[];n.example=(t,e)=>{d.push([t,e||""])};let u=[];n.command=function(t,e,s,i,n=!1){s&&(u=u.map((t=>(t[2]=!1,t)))),u.push([t,e||"",s,i,n])},n.getCommands=()=>u;let p={};n.describe=function(t,e){Array.isArray(t)?t.forEach((t=>{n.describe(t,e)})):"object"==typeof t?Object.keys(t).forEach((e=>{n.describe(e,t[e])})):p[t]=e},n.getDescriptions=()=>p;let m=[];n.epilog=t=>{m.push(t)};let y,b=!1;n.wrap=t=>{b=!0,y=t},n.getWrap=()=>s.getEnv("YARGS_DISABLE_WRAP")?null:(b||(y=function(){const t=80;return s.process.stdColumns?Math.min(t,s.process.stdColumns):t}(),b=!0),y);const v="__yargsString__:";function O(t,e,i){let n=0;return Array.isArray(t)||(t=Object.values(t).map((t=>[t]))),t.forEach((t=>{n=Math.max(s.stringWidth(i?`${i} ${I(t[0])}`:I(t[0]))+$(t[0]),n)})),e&&(n=Math.min(n,parseInt((.5*e).toString(),10))),n}let w;function C(e){return t.getOptions().hiddenOptions.indexOf(e)<0||t.parsed.argv[t.getOptions().showHiddenOpt]}function j(t,e){let s=`[${i("default:")} `;if(void 0===t&&!e)return null;if(e)s+=e;else switch(typeof t){case"string":s+=`"${t}"`;break;case"object":s+=JSON.stringify(t);break;default:s+=t}return`${s}]`}n.deferY18nLookup=t=>v+t,n.help=function(){if(w)return w;!function(){const e=t.getDemandedOptions(),s=t.getOptions();(Object.keys(s.alias)||[]).forEach((i=>{s.alias[i].forEach((r=>{p[r]&&n.describe(i,p[r]),r in e&&t.demandOption(i,e[r]),s.boolean.includes(r)&&t.boolean(i),s.count.includes(r)&&t.count(i),s.string.includes(r)&&t.string(i),s.normalize.includes(r)&&t.normalize(i),s.array.includes(r)&&t.array(i),s.number.includes(r)&&t.number(i)}))}))}();const e=t.customScriptName?t.$0:s.path.basename(t.$0),r=t.getDemandedOptions(),o=t.getDemandedCommands(),a=t.getDeprecatedOptions(),h=t.getGroups(),l=t.getOptions();let g=[];g=g.concat(Object.keys(p)),g=g.concat(Object.keys(r)),g=g.concat(Object.keys(o)),g=g.concat(Object.keys(l.default)),g=g.filter(C),g=Object.keys(g.reduce(((t,e)=>("_"!==e&&(t[e]=!0),t)),{}));const y=n.getWrap(),b=s.cliui({width:y,wrap:!!y});if(!f)if(c.length)c.forEach((t=>{b.div({text:`${t[0].replace(/\$0/g,e)}`}),t[1]&&b.div({text:`${t[1]}`,padding:[1,0,0,0]})})),b.div();else if(u.length){let t=null;t=o._?`${e} <${i("command")}>\n`:`${e} [${i("command")}]\n`,b.div(`${t}`)}if(u.length>1||1===u.length&&!u[0][2]){b.div(i("Commands:"));const s=t.getInternalMethods().getContext(),n=s.commands.length?`${s.commands.join(" ")} `:"";!0===t.getInternalMethods().getParserConfiguration()["sort-commands"]&&(u=u.sort(((t,e)=>t[0].localeCompare(e[0]))));const r=e?`${e} `:"";u.forEach((t=>{const s=`${r}${n}${t[0].replace(/^\$0 ?/,"")}`;b.span({text:s,padding:[0,2,0,2],width:O(u,y,`${e}${n}`)+4},{text:t[1]});const o=[];t[2]&&o.push(`[${i("default")}]`),t[3]&&t[3].length&&o.push(`[${i("aliases:")} ${t[3].join(", ")}]`),t[4]&&("string"==typeof t[4]?o.push(`[${i("deprecated: %s",t[4])}]`):o.push(`[${i("deprecated")}]`)),o.length?b.div({text:o.join(" "),padding:[0,0,0,2],align:"right"}):b.div()})),b.div()}const M=(Object.keys(l.alias)||[]).concat(Object.keys(t.parsed.newAliases)||[]);g=g.filter((e=>!t.parsed.newAliases[e]&&M.every((t=>-1===(l.alias[t]||[]).indexOf(e)))));const _=i("Options:");h[_]||(h[_]=[]),function(t,e,s,i){let n=[],r=null;Object.keys(s).forEach((t=>{n=n.concat(s[t])})),t.forEach((t=>{r=[t].concat(e[t]),r.some((t=>-1!==n.indexOf(t)))||s[i].push(t)}))}(g,l.alias,h,_);const k=t=>/^--/.test(I(t)),x=Object.keys(h).filter((t=>h[t].length>0)).map((t=>({groupName:t,normalizedKeys:h[t].filter(C).map((t=>{if(M.includes(t))return t;for(let e,s=0;void 0!==(e=M[s]);s++)if((l.alias[e]||[]).includes(t))return e;return t}))}))).filter((({normalizedKeys:t})=>t.length>0)).map((({groupName:t,normalizedKeys:e})=>{const s=e.reduce(((e,s)=>(e[s]=[s].concat(l.alias[s]||[]).map((e=>t===n.getPositionalGroupName()?e:(/^[0-9]$/.test(e)?l.boolean.includes(s)?"-":"--":e.length>1?"--":"-")+e)).sort(((t,e)=>k(t)===k(e)?0:k(t)?1:-1)).join(", "),e)),{});return{groupName:t,normalizedKeys:e,switches:s}}));if(x.filter((({groupName:t})=>t!==n.getPositionalGroupName())).some((({normalizedKeys:t,switches:e})=>!t.every((t=>k(e[t])))))&&x.filter((({groupName:t})=>t!==n.getPositionalGroupName())).forEach((({normalizedKeys:t,switches:e})=>{t.forEach((t=>{var s,i;k(e[t])&&(e[t]=(s=e[t],i="-x, ".length,S(s)?{text:s.text,indentation:s.indentation+i}:{text:s,indentation:i}))}))})),x.forEach((({groupName:e,normalizedKeys:s,switches:o})=>{b.div(e),s.forEach((e=>{const s=o[e];let h=p[e]||"",c=null;h.includes(v)&&(h=i(h.substring(v.length))),l.boolean.includes(e)&&(c=`[${i("boolean")}]`),l.count.includes(e)&&(c=`[${i("count")}]`),l.string.includes(e)&&(c=`[${i("string")}]`),l.normalize.includes(e)&&(c=`[${i("string")}]`),l.array.includes(e)&&(c=`[${i("array")}]`),l.number.includes(e)&&(c=`[${i("number")}]`);const f=[e in a?(d=a[e],"string"==typeof d?`[${i("deprecated: %s",d)}]`:`[${i("deprecated")}]`):null,c,e in r?`[${i("required")}]`:null,l.choices&&l.choices[e]?`[${i("choices:")} ${n.stringifiedValues(l.choices[e])}]`:null,j(l.default[e],l.defaultDescription[e])].filter(Boolean).join(" ");var d;b.span({text:I(s),padding:[0,2,0,2+$(s)],width:O(o,y)+4},h);const u=!0===t.getInternalMethods().getUsageConfiguration()["hide-types"];f&&!u?b.div({text:f,padding:[0,0,0,2],align:"right"}):b.div()})),b.div()})),d.length&&(b.div(i("Examples:")),d.forEach((t=>{t[0]=t[0].replace(/\$0/g,e)})),d.forEach((t=>{""===t[1]?b.div({text:t[0],padding:[0,2,0,2]}):b.div({text:t[0],padding:[0,2,0,2],width:O(d,y)+4},{text:t[1]})})),b.div()),m.length>0){const t=m.map((t=>t.replace(/\$0/g,e))).join("\n");b.div(`${t}\n`)}return b.toString().replace(/\s*$/,"")},n.cacheHelpMessage=function(){w=this.help()},n.clearCachedHelpMessage=function(){w=void 0},n.hasCachedHelpMessage=function(){return!!w},n.showHelp=e=>{const s=t.getInternalMethods().getLoggerInstance();e||(e="error");("function"==typeof e?e:s[e])(n.help())},n.functionDescription=t=>["(",t.name?s.Parser.decamelize(t.name,"-"):i("generated-value"),")"].join(""),n.stringifiedValues=function(t,e){let s="";const i=e||", ",n=[].concat(t);return t&&n.length?(n.forEach((t=>{s.length&&(s+=i),s+=JSON.stringify(t)})),s):s};let M=null;n.version=t=>{M=t},n.showVersion=e=>{const s=t.getInternalMethods().getLoggerInstance();e||(e="error");("function"==typeof e?e:s[e])(M)},n.reset=function(t){return o=null,l=!1,c=[],f=!1,m=[],d=[],u=[],p=g(p,(e=>!t[e])),n};const _=[];return n.freeze=function(){_.push({failMessage:o,failureOutput:l,usages:c,usageDisabled:f,epilogs:m,examples:d,commands:u,descriptions:p})},n.unfreeze=function(t=!1){const e=_.pop();e&&(t?(p={...e.descriptions,...p},u=[...e.commands,...u],c=[...e.usages,...c],d=[...e.examples,...d],m=[...e.epilogs,...m]):({failMessage:o,failureOutput:l,usages:c,usageDisabled:f,epilogs:m,examples:d,commands:u,descriptions:p}=e))},n}function S(t){return"object"==typeof t}function $(t){return S(t)?t.indentation:0}function I(t){return S(t)?t.text:t}class D{constructor(t,e,s,i){var n,r,o;this.yargs=t,this.usage=e,this.command=s,this.shim=i,this.completionKey="get-yargs-completions",this.aliases=null,this.customCompletionFunction=null,this.indexAfterLastReset=0,this.zshShell=null!==(o=(null===(n=this.shim.getEnv("SHELL"))||void 0===n?void 0:n.includes("zsh"))||(null===(r=this.shim.getEnv("ZSH_NAME"))||void 0===r?void 0:r.includes("zsh")))&&void 0!==o&&o}defaultCompletion(t,e,s,i){const n=this.command.getCommandHandlers();for(let e=0,s=t.length;e<s;++e)if(n[t[e]]&&n[t[e]].builder){const s=n[t[e]].builder;if(x(s)){this.indexAfterLastReset=e+1;const t=this.yargs.getInternalMethods().reset();return s(t,!0),t.argv}}const r=[];this.commandCompletions(r,t,s),this.optionCompletions(r,t,e,s),this.choicesFromOptionsCompletions(r,t,e,s),this.choicesFromPositionalsCompletions(r,t,e,s),i(null,r)}commandCompletions(t,e,s){const i=this.yargs.getInternalMethods().getContext().commands;s.match(/^-/)||i[i.length-1]===s||this.previousArgHasChoices(e)||this.usage.getCommands().forEach((s=>{const i=o(s[0]).cmd;if(-1===e.indexOf(i))if(this.zshShell){const e=s[1]||"";t.push(i.replace(/:/g,"\\:")+":"+e)}else t.push(i)}))}optionCompletions(t,e,s,i){if((i.match(/^-/)||""===i&&0===t.length)&&!this.previousArgHasChoices(e)){const s=this.yargs.getOptions(),n=this.yargs.getGroups()[this.usage.getPositionalGroupName()]||[];Object.keys(s.key).forEach((r=>{const o=!!s.configuration["boolean-negation"]&&s.boolean.includes(r);n.includes(r)||s.hiddenOptions.includes(r)||this.argsContainKey(e,r,o)||(this.completeOptionKey(r,t,i),o&&s.default[r]&&this.completeOptionKey(`no-${r}`,t,i))}))}}choicesFromOptionsCompletions(t,e,s,i){if(this.previousArgHasChoices(e)){const s=this.getPreviousArgChoices(e);s&&s.length>0&&t.push(...s.map((t=>t.replace(/:/g,"\\:"))))}}choicesFromPositionalsCompletions(t,e,s,i){if(""===i&&t.length>0&&this.previousArgHasChoices(e))return;const n=this.yargs.getGroups()[this.usage.getPositionalGroupName()]||[],r=Math.max(this.indexAfterLastReset,this.yargs.getInternalMethods().getContext().commands.length+1),o=n[s._.length-r-1];if(!o)return;const a=this.yargs.getOptions().choices[o]||[];for(const e of a)e.startsWith(i)&&t.push(e.replace(/:/g,"\\:"))}getPreviousArgChoices(t){if(t.length<1)return;let e=t[t.length-1],s="";if(!e.startsWith("-")&&t.length>1&&(s=e,e=t[t.length-2]),!e.startsWith("-"))return;const i=e.replace(/^-+/,""),n=this.yargs.getOptions(),r=[i,...this.yargs.getAliases()[i]||[]];let o;for(const t of r)if(Object.prototype.hasOwnProperty.call(n.key,t)&&Array.isArray(n.choices[t])){o=n.choices[t];break}return o?o.filter((t=>!s||t.startsWith(s))):void 0}previousArgHasChoices(t){const e=this.getPreviousArgChoices(t);return void 0!==e&&e.length>0}argsContainKey(t,e,s){const i=e=>-1!==t.indexOf((/^[^0-9]$/.test(e)?"-":"--")+e);if(i(e))return!0;if(s&&i(`no-${e}`))return!0;if(this.aliases)for(const t of this.aliases[e])if(i(t))return!0;return!1}completeOptionKey(t,e,s){var i,n,r;const o=this.usage.getDescriptions(),a=!/^--/.test(s)&&(t=>/^[^0-9]$/.test(t))(t)?"-":"--";if(this.zshShell){const s=null===(i=null==this?void 0:this.aliases)||void 0===i?void 0:i[t].find((t=>{const e=o[t];return"string"==typeof e&&e.length>0})),h=s?o[s]:void 0,l=null!==(r=null!==(n=o[t])&&void 0!==n?n:h)&&void 0!==r?r:"";e.push(a+`${t.replace(/:/g,"\\:")}:${l.replace("__yargsString__:","").replace(/(\r\n|\n|\r)/gm," ")}`)}else e.push(a+t)}customCompletion(t,e,s,i){if(d(this.customCompletionFunction,null,this.shim),this.customCompletionFunction.length<3){const t=this.customCompletionFunction(s,e);return f(t)?t.then((t=>{this.shim.process.nextTick((()=>{i(null,t)}))})).catch((t=>{this.shim.process.nextTick((()=>{i(t,void 0)}))})):i(null,t)}return function(t){return t.length>3}(this.customCompletionFunction)?this.customCompletionFunction(s,e,((n=i)=>this.defaultCompletion(t,e,s,n)),(t=>{i(null,t)})):this.customCompletionFunction(s,e,(t=>{i(null,t)}))}getCompletion(t,e){const s=t.length?t[t.length-1]:"",i=this.yargs.parse(t,!0),n=this.customCompletionFunction?i=>this.customCompletion(t,i,s,e):i=>this.defaultCompletion(t,i,s,e);return f(i)?i.then(n):n(i)}generateCompletionScript(t,e){let s=this.zshShell?'#compdef {{app_name}}\n###-begin-{{app_name}}-completions-###\n#\n# yargs command completion script\n#\n# Installation: {{app_path}} {{completion_command}} >> ~/.zshrc\n#    or {{app_path}} {{completion_command}} >> ~/.zprofile on OSX.\n#\n_{{app_name}}_yargs_completions()\n{\n  local reply\n  local si=$IFS\n  IFS=$\'\n\' reply=($(COMP_CWORD="$((CURRENT-1))" COMP_LINE="$BUFFER" COMP_POINT="$CURSOR" {{app_path}} --get-yargs-completions "${words[@]}"))\n  IFS=$si\n  _describe \'values\' reply\n}\ncompdef _{{app_name}}_yargs_completions {{app_name}}\n###-end-{{app_name}}-completions-###\n':'###-begin-{{app_name}}-completions-###\n#\n# yargs command completion script\n#\n# Installation: {{app_path}} {{completion_command}} >> ~/.bashrc\n#    or {{app_path}} {{completion_command}} >> ~/.bash_profile on OSX.\n#\n_{{app_name}}_yargs_completions()\n{\n    local cur_word args type_list\n\n    cur_word="${COMP_WORDS[COMP_CWORD]}"\n    args=("${COMP_WORDS[@]}")\n\n    # ask yargs to generate completions.\n    type_list=$({{app_path}} --get-yargs-completions "${args[@]}")\n\n    COMPREPLY=( $(compgen -W "${type_list}" -- ${cur_word}) )\n\n    # if no match was found, fall back to filename completion\n    if [ ${#COMPREPLY[@]} -eq 0 ]; then\n      COMPREPLY=()\n    fi\n\n    return 0\n}\ncomplete -o bashdefault -o default -F _{{app_name}}_yargs_completions {{app_name}}\n###-end-{{app_name}}-completions-###\n';const i=this.shim.path.basename(t);return t.match(/\.js$/)&&(t=`./${t}`),s=s.replace(/{{app_name}}/g,i),s=s.replace(/{{completion_command}}/g,e),s.replace(/{{app_path}}/g,t)}registerFunction(t){this.customCompletionFunction=t}setParsed(t){this.aliases=t.aliases}}function N(t,e){if(0===t.length)return e.length;if(0===e.length)return t.length;const s=[];let i,n;for(i=0;i<=e.length;i++)s[i]=[i];for(n=0;n<=t.length;n++)s[0][n]=n;for(i=1;i<=e.length;i++)for(n=1;n<=t.length;n++)e.charAt(i-1)===t.charAt(n-1)?s[i][n]=s[i-1][n-1]:i>1&&n>1&&e.charAt(i-2)===t.charAt(n-1)&&e.charAt(i-1)===t.charAt(n-2)?s[i][n]=s[i-2][n-2]+1:s[i][n]=Math.min(s[i-1][n-1]+1,Math.min(s[i][n-1]+1,s[i-1][n]+1));return s[e.length][t.length]}const H=["$0","--","_"];var z,W,q,U,F,L,V,G,R,T,B,K,Y,J,Z,X,Q,tt,et,st,it,nt,rt,ot,at,ht,lt,ct,ft,dt,ut,pt,gt,mt,yt;const bt=Symbol("copyDoubleDash"),vt=Symbol("copyDoubleDash"),Ot=Symbol("deleteFromParserHintObject"),wt=Symbol("emitWarning"),Ct=Symbol("freeze"),jt=Symbol("getDollarZero"),Mt=Symbol("getParserConfiguration"),_t=Symbol("getUsageConfiguration"),kt=Symbol("guessLocale"),xt=Symbol("guessVersion"),Et=Symbol("parsePositionalNumbers"),At=Symbol("pkgUp"),Pt=Symbol("populateParserHintArray"),St=Symbol("populateParserHintSingleValueDictionary"),$t=Symbol("populateParserHintArrayDictionary"),It=Symbol("populateParserHintDictionary"),Dt=Symbol("sanitizeKey"),Nt=Symbol("setKey"),Ht=Symbol("unfreeze"),zt=Symbol("validateAsync"),Wt=Symbol("getCommandInstance"),qt=Symbol("getContext"),Ut=Symbol("getHasOutput"),Ft=Symbol("getLoggerInstance"),Lt=Symbol("getParseContext"),Vt=Symbol("getUsageInstance"),Gt=Symbol("getValidationInstance"),Rt=Symbol("hasParseCallback"),Tt=Symbol("isGlobalContext"),Bt=Symbol("postProcess"),Kt=Symbol("rebase"),Yt=Symbol("reset"),Jt=Symbol("runYargsParserAndExecuteCommands"),Zt=Symbol("runValidation"),Xt=Symbol("setHasOutput"),Qt=Symbol("kTrackManuallySetKeys");class te{constructor(t=[],e,s,i){this.customScriptName=!1,this.parsed=!1,z.set(this,void 0),W.set(this,void 0),q.set(this,{commands:[],fullCommands:[]}),U.set(this,null),F.set(this,null),L.set(this,"show-hidden"),V.set(this,null),G.set(this,!0),R.set(this,{}),T.set(this,!0),B.set(this,[]),K.set(this,void 0),Y.set(this,{}),J.set(this,!1),Z.set(this,null),X.set(this,!0),Q.set(this,void 0),tt.set(this,""),et.set(this,void 0),st.set(this,void 0),it.set(this,{}),nt.set(this,null),rt.set(this,null),ot.set(this,{}),at.set(this,{}),ht.set(this,void 0),lt.set(this,!1),ct.set(this,void 0),ft.set(this,!1),dt.set(this,!1),ut.set(this,!1),pt.set(this,void 0),gt.set(this,{}),mt.set(this,null),yt.set(this,void 0),O(this,ct,i,"f"),O(this,ht,t,"f"),O(this,W,e,"f"),O(this,st,s,"f"),O(this,K,new w(this),"f"),this.$0=this[jt](),this[Yt](),O(this,z,v(this,z,"f"),"f"),O(this,pt,v(this,pt,"f"),"f"),O(this,yt,v(this,yt,"f"),"f"),O(this,et,v(this,et,"f"),"f"),v(this,et,"f").showHiddenOpt=v(this,L,"f"),O(this,Q,this[vt](),"f")}addHelpOpt(t,e){return h("[string|boolean] [string]",[t,e],arguments.length),v(this,Z,"f")&&(this[Ot](v(this,Z,"f")),O(this,Z,null,"f")),!1===t&&void 0===e||(O(this,Z,"string"==typeof t?t:"help","f"),this.boolean(v(this,Z,"f")),this.describe(v(this,Z,"f"),e||v(this,pt,"f").deferY18nLookup("Show help"))),this}help(t,e){return this.addHelpOpt(t,e)}addShowHiddenOpt(t,e){if(h("[string|boolean] [string]",[t,e],arguments.length),!1===t&&void 0===e)return this;const s="string"==typeof t?t:v(this,L,"f");return this.boolean(s),this.describe(s,e||v(this,pt,"f").deferY18nLookup("Show hidden options")),v(this,et,"f").showHiddenOpt=s,this}showHidden(t,e){return this.addShowHiddenOpt(t,e)}alias(t,e){return h("<object|string|array> [string|array]",[t,e],arguments.length),this[$t](this.alias.bind(this),"alias",t,e),this}array(t){return h("<array|string>",[t],arguments.length),this[Pt]("array",t),this[Qt](t),this}boolean(t){return h("<array|string>",[t],arguments.length),this[Pt]("boolean",t),this[Qt](t),this}check(t,e){return h("<function> [boolean]",[t,e],arguments.length),this.middleware(((e,s)=>j((()=>t(e,s.getOptions())),(s=>(s?("string"==typeof s||s instanceof Error)&&v(this,pt,"f").fail(s.toString(),s):v(this,pt,"f").fail(v(this,ct,"f").y18n.__("Argument check failed: %s",t.toString())),e)),(t=>(v(this,pt,"f").fail(t.message?t.message:t.toString(),t),e)))),!1,e),this}choices(t,e){return h("<object|string|array> [string|array]",[t,e],arguments.length),this[$t](this.choices.bind(this),"choices",t,e),this}coerce(t,s){if(h("<object|string|array> [function]",[t,s],arguments.length),Array.isArray(t)){if(!s)throw new e("coerce callback must be provided");for(const e of t)this.coerce(e,s);return this}if("object"==typeof t){for(const e of Object.keys(t))this.coerce(e,t[e]);return this}if(!s)throw new e("coerce callback must be provided");return v(this,et,"f").key[t]=!0,v(this,K,"f").addCoerceMiddleware(((i,n)=>{let r;return Object.prototype.hasOwnProperty.call(i,t)?j((()=>(r=n.getAliases(),s(i[t]))),(e=>{i[t]=e;const s=n.getInternalMethods().getParserConfiguration()["strip-aliased"];if(r[t]&&!0!==s)for(const s of r[t])i[s]=e;return i}),(t=>{throw new e(t.message)})):i}),t),this}conflicts(t,e){return h("<string|object> [string|array]",[t,e],arguments.length),v(this,yt,"f").conflicts(t,e),this}config(t="config",e,s){return h("[object|string] [string|function] [function]",[t,e,s],arguments.length),"object"!=typeof t||Array.isArray(t)?("function"==typeof e&&(s=e,e=void 0),this.describe(t,e||v(this,pt,"f").deferY18nLookup("Path to JSON config file")),(Array.isArray(t)?t:[t]).forEach((t=>{v(this,et,"f").config[t]=s||!0})),this):(t=n(t,v(this,W,"f"),this[Mt]()["deep-merge-config"]||!1,v(this,ct,"f")),v(this,et,"f").configObjects=(v(this,et,"f").configObjects||[]).concat(t),this)}completion(t,e,s){return h("[string] [string|boolean|function] [function]",[t,e,s],arguments.length),"function"==typeof e&&(s=e,e=void 0),O(this,F,t||v(this,F,"f")||"completion","f"),e||!1===e||(e="generate completion script"),this.command(v(this,F,"f"),e),s&&v(this,U,"f").registerFunction(s),this}command(t,e,s,i,n,r){return h("<string|array|object> [string|boolean] [function|object] [function] [array] [boolean|string]",[t,e,s,i,n,r],arguments.length),v(this,z,"f").addHandler(t,e,s,i,n,r),this}commands(t,e,s,i,n,r){return this.command(t,e,s,i,n,r)}commandDir(t,e){h("<string> [object]",[t,e],arguments.length);const s=v(this,st,"f")||v(this,ct,"f").require;return v(this,z,"f").addDirectory(t,s,v(this,ct,"f").getCallerFile(),e),this}count(t){return h("<array|string>",[t],arguments.length),this[Pt]("count",t),this[Qt](t),this}default(t,e,s){return h("<object|string|array> [*] [string]",[t,e,s],arguments.length),s&&(u(t,v(this,ct,"f")),v(this,et,"f").defaultDescription[t]=s),"function"==typeof e&&(u(t,v(this,ct,"f")),v(this,et,"f").defaultDescription[t]||(v(this,et,"f").defaultDescription[t]=v(this,pt,"f").functionDescription(e)),e=e.call()),this[St](this.default.bind(this),"default",t,e),this}defaults(t,e,s){return this.default(t,e,s)}demandCommand(t=1,e,s,i){return h("[number] [number|string] [string|null|undefined] [string|null|undefined]",[t,e,s,i],arguments.length),"number"!=typeof e&&(s=e,e=1/0),this.global("_",!1),v(this,et,"f").demandedCommands._={min:t,max:e,minMsg:s,maxMsg:i},this}demand(t,e,s){return Array.isArray(e)?(e.forEach((t=>{d(s,!0,v(this,ct,"f")),this.demandOption(t,s)})),e=1/0):"number"!=typeof e&&(s=e,e=1/0),"number"==typeof t?(d(s,!0,v(this,ct,"f")),this.demandCommand(t,e,s,s)):Array.isArray(t)?t.forEach((t=>{d(s,!0,v(this,ct,"f")),this.demandOption(t,s)})):"string"==typeof s?this.demandOption(t,s):!0!==s&&void 0!==s||this.demandOption(t),this}demandOption(t,e){return h("<object|string|array> [string]",[t,e],arguments.length),this[St](this.demandOption.bind(this),"demandedOptions",t,e),this}deprecateOption(t,e){return h("<string> [string|boolean]",[t,e],arguments.length),v(this,et,"f").deprecatedOptions[t]=e,this}describe(t,e){return h("<object|string|array> [string]",[t,e],arguments.length),this[Nt](t,!0),v(this,pt,"f").describe(t,e),this}detectLocale(t){return h("<boolean>",[t],arguments.length),O(this,G,t,"f"),this}env(t){return h("[string|boolean]",[t],arguments.length),!1===t?delete v(this,et,"f").envPrefix:v(this,et,"f").envPrefix=t||"",this}epilogue(t){return h("<string>",[t],arguments.length),v(this,pt,"f").epilog(t),this}epilog(t){return this.epilogue(t)}example(t,e){return h("<string|array> [string]",[t,e],arguments.length),Array.isArray(t)?t.forEach((t=>this.example(...t))):v(this,pt,"f").example(t,e),this}exit(t,e){O(this,J,!0,"f"),O(this,V,e,"f"),v(this,T,"f")&&v(this,ct,"f").process.exit(t)}exitProcess(t=!0){return h("[boolean]",[t],arguments.length),O(this,T,t,"f"),this}fail(t){if(h("<function|boolean>",[t],arguments.length),"boolean"==typeof t&&!1!==t)throw new e("Invalid first argument. Expected function or boolean 'false'");return v(this,pt,"f").failFn(t),this}getAliases(){return this.parsed?this.parsed.aliases:{}}async getCompletion(t,e){return h("<array> [function]",[t,e],arguments.length),e?v(this,U,"f").getCompletion(t,e):new Promise(((e,s)=>{v(this,U,"f").getCompletion(t,((t,i)=>{t?s(t):e(i)}))}))}getDemandedOptions(){return h([],0),v(this,et,"f").demandedOptions}getDemandedCommands(){return h([],0),v(this,et,"f").demandedCommands}getDeprecatedOptions(){return h([],0),v(this,et,"f").deprecatedOptions}getDetectLocale(){return v(this,G,"f")}getExitProcess(){return v(this,T,"f")}getGroups(){return Object.assign({},v(this,Y,"f"),v(this,at,"f"))}getHelp(){if(O(this,J,!0,"f"),!v(this,pt,"f").hasCachedHelpMessage()){if(!this.parsed){const t=this[Jt](v(this,ht,"f"),void 0,void 0,0,!0);if(f(t))return t.then((()=>v(this,pt,"f").help()))}const t=v(this,z,"f").runDefaultBuilderOn(this);if(f(t))return t.then((()=>v(this,pt,"f").help()))}return Promise.resolve(v(this,pt,"f").help())}getOptions(){return v(this,et,"f")}getStrict(){return v(this,ft,"f")}getStrictCommands(){return v(this,dt,"f")}getStrictOptions(){return v(this,ut,"f")}global(t,e){return h("<string|array> [boolean]",[t,e],arguments.length),t=[].concat(t),!1!==e?v(this,et,"f").local=v(this,et,"f").local.filter((e=>-1===t.indexOf(e))):t.forEach((t=>{v(this,et,"f").local.includes(t)||v(this,et,"f").local.push(t)})),this}group(t,e){h("<string|array> <string>",[t,e],arguments.length);const s=v(this,at,"f")[e]||v(this,Y,"f")[e];v(this,at,"f")[e]&&delete v(this,at,"f")[e];const i={};return v(this,Y,"f")[e]=(s||[]).concat(t).filter((t=>!i[t]&&(i[t]=!0))),this}hide(t){return h("<string>",[t],arguments.length),v(this,et,"f").hiddenOptions.push(t),this}implies(t,e){return h("<string|object> [number|string|array]",[t,e],arguments.length),v(this,yt,"f").implies(t,e),this}locale(t){return h("[string]",[t],arguments.length),void 0===t?(this[kt](),v(this,ct,"f").y18n.getLocale()):(O(this,G,!1,"f"),v(this,ct,"f").y18n.setLocale(t),this)}middleware(t,e,s){return v(this,K,"f").addMiddleware(t,!!e,s)}nargs(t,e){return h("<string|object|array> [number]",[t,e],arguments.length),this[St](this.nargs.bind(this),"narg",t,e),this}normalize(t){return h("<array|string>",[t],arguments.length),this[Pt]("normalize",t),this}number(t){return h("<array|string>",[t],arguments.length),this[Pt]("number",t),this[Qt](t),this}option(t,e){if(h("<string|object> [object]",[t,e],arguments.length),"object"==typeof t)Object.keys(t).forEach((e=>{this.options(e,t[e])}));else{"object"!=typeof e&&(e={}),this[Qt](t),!v(this,mt,"f")||"version"!==t&&"version"!==(null==e?void 0:e.alias)||this[wt](['"version" is a reserved word.',"Please do one of the following:",'- Disable version with `yargs.version(false)` if using "version" as an option',"- Use the built-in `yargs.version` method instead (if applicable)","- Use a different option key","https://yargs.js.org/docs/#api-reference-version"].join("\n"),void 0,"versionWarning"),v(this,et,"f").key[t]=!0,e.alias&&this.alias(t,e.alias);const s=e.deprecate||e.deprecated;s&&this.deprecateOption(t,s);const i=e.demand||e.required||e.require;i&&this.demand(t,i),e.demandOption&&this.demandOption(t,"string"==typeof e.demandOption?e.demandOption:void 0),e.conflicts&&this.conflicts(t,e.conflicts),"default"in e&&this.default(t,e.default),void 0!==e.implies&&this.implies(t,e.implies),void 0!==e.nargs&&this.nargs(t,e.nargs),e.config&&this.config(t,e.configParser),e.normalize&&this.normalize(t),e.choices&&this.choices(t,e.choices),e.coerce&&this.coerce(t,e.coerce),e.group&&this.group(t,e.group),(e.boolean||"boolean"===e.type)&&(this.boolean(t),e.alias&&this.boolean(e.alias)),(e.array||"array"===e.type)&&(this.array(t),e.alias&&this.array(e.alias)),(e.number||"number"===e.type)&&(this.number(t),e.alias&&this.number(e.alias)),(e.string||"string"===e.type)&&(this.string(t),e.alias&&this.string(e.alias)),(e.count||"count"===e.type)&&this.count(t),"boolean"==typeof e.global&&this.global(t,e.global),e.defaultDescription&&(v(this,et,"f").defaultDescription[t]=e.defaultDescription),e.skipValidation&&this.skipValidation(t);const n=e.describe||e.description||e.desc,r=v(this,pt,"f").getDescriptions();Object.prototype.hasOwnProperty.call(r,t)&&"string"!=typeof n||this.describe(t,n),e.hidden&&this.hide(t),e.requiresArg&&this.requiresArg(t)}return this}options(t,e){return this.option(t,e)}parse(t,e,s){h("[string|array] [function|boolean|object] [function]",[t,e,s],arguments.length),this[Ct](),void 0===t&&(t=v(this,ht,"f")),"object"==typeof e&&(O(this,rt,e,"f"),e=s),"function"==typeof e&&(O(this,nt,e,"f"),e=!1),e||O(this,ht,t,"f"),v(this,nt,"f")&&O(this,T,!1,"f");const i=this[Jt](t,!!e),n=this.parsed;return v(this,U,"f").setParsed(this.parsed),f(i)?i.then((t=>(v(this,nt,"f")&&v(this,nt,"f").call(this,v(this,V,"f"),t,v(this,tt,"f")),t))).catch((t=>{throw v(this,nt,"f")&&v(this,nt,"f")(t,this.parsed.argv,v(this,tt,"f")),t})).finally((()=>{this[Ht](),this.parsed=n})):(v(this,nt,"f")&&v(this,nt,"f").call(this,v(this,V,"f"),i,v(this,tt,"f")),this[Ht](),this.parsed=n,i)}parseAsync(t,e,s){const i=this.parse(t,e,s);return f(i)?i:Promise.resolve(i)}parseSync(t,s,i){const n=this.parse(t,s,i);if(f(n))throw new e(".parseSync() must not be used with asynchronous builders, handlers, or middleware");return n}parserConfiguration(t){return h("<object>",[t],arguments.length),O(this,it,t,"f"),this}pkgConf(t,e){h("<string> [string]",[t,e],arguments.length);let s=null;const i=this[At](e||v(this,W,"f"));return i[t]&&"object"==typeof i[t]&&(s=n(i[t],e||v(this,W,"f"),this[Mt]()["deep-merge-config"]||!1,v(this,ct,"f")),v(this,et,"f").configObjects=(v(this,et,"f").configObjects||[]).concat(s)),this}positional(t,e){h("<string> <object>",[t,e],arguments.length);const s=["default","defaultDescription","implies","normalize","choices","conflicts","coerce","type","describe","desc","description","alias"];e=g(e,((t,e)=>!("type"===t&&!["string","number","boolean"].includes(e))&&s.includes(t)));const i=v(this,q,"f").fullCommands[v(this,q,"f").fullCommands.length-1],n=i?v(this,z,"f").cmdToParseOptions(i):{array:[],alias:{},default:{},demand:{}};return p(n).forEach((s=>{const i=n[s];Array.isArray(i)?-1!==i.indexOf(t)&&(e[s]=!0):i[t]&&!(s in e)&&(e[s]=i[t])})),this.group(t,v(this,pt,"f").getPositionalGroupName()),this.option(t,e)}recommendCommands(t=!0){return h("[boolean]",[t],arguments.length),O(this,lt,t,"f"),this}required(t,e,s){return this.demand(t,e,s)}require(t,e,s){return this.demand(t,e,s)}requiresArg(t){return h("<array|string|object> [number]",[t],arguments.length),"string"==typeof t&&v(this,et,"f").narg[t]||this[St](this.requiresArg.bind(this),"narg",t,NaN),this}showCompletionScript(t,e){return h("[string] [string]",[t,e],arguments.length),t=t||this.$0,v(this,Q,"f").log(v(this,U,"f").generateCompletionScript(t,e||v(this,F,"f")||"completion")),this}showHelp(t){if(h("[string|function]",[t],arguments.length),O(this,J,!0,"f"),!v(this,pt,"f").hasCachedHelpMessage()){if(!this.parsed){const e=this[Jt](v(this,ht,"f"),void 0,void 0,0,!0);if(f(e))return e.then((()=>{v(this,pt,"f").showHelp(t)})),this}const e=v(this,z,"f").runDefaultBuilderOn(this);if(f(e))return e.then((()=>{v(this,pt,"f").showHelp(t)})),this}return v(this,pt,"f").showHelp(t),this}scriptName(t){return this.customScriptName=!0,this.$0=t,this}showHelpOnFail(t,e){return h("[boolean|string] [string]",[t,e],arguments.length),v(this,pt,"f").showHelpOnFail(t,e),this}showVersion(t){return h("[string|function]",[t],arguments.length),v(this,pt,"f").showVersion(t),this}skipValidation(t){return h("<array|string>",[t],arguments.length),this[Pt]("skipValidation",t),this}strict(t){return h("[boolean]",[t],arguments.length),O(this,ft,!1!==t,"f"),this}strictCommands(t){return h("[boolean]",[t],arguments.length),O(this,dt,!1!==t,"f"),this}strictOptions(t){return h("[boolean]",[t],arguments.length),O(this,ut,!1!==t,"f"),this}string(t){return h("<array|string>",[t],arguments.length),this[Pt]("string",t),this[Qt](t),this}terminalWidth(){return h([],0),v(this,ct,"f").process.stdColumns}updateLocale(t){return this.updateStrings(t)}updateStrings(t){return h("<object>",[t],arguments.length),O(this,G,!1,"f"),v(this,ct,"f").y18n.updateLocale(t),this}usage(t,s,i,n){if(h("<string|null|undefined> [string|boolean] [function|object] [function]",[t,s,i,n],arguments.length),void 0!==s){if(d(t,null,v(this,ct,"f")),(t||"").match(/^\$0( |$)/))return this.command(t,s,i,n);throw new e(".usage() description must start with $0 if being used as alias for .command()")}return v(this,pt,"f").usage(t),this}usageConfiguration(t){return h("<object>",[t],arguments.length),O(this,gt,t,"f"),this}version(t,e,s){const i="version";if(h("[boolean|string] [string] [string]",[t,e,s],arguments.length),v(this,mt,"f")&&(this[Ot](v(this,mt,"f")),v(this,pt,"f").version(void 0),O(this,mt,null,"f")),0===arguments.length)s=this[xt](),t=i;else if(1===arguments.length){if(!1===t)return this;s=t,t=i}else 2===arguments.length&&(s=e,e=void 0);return O(this,mt,"string"==typeof t?t:i,"f"),e=e||v(this,pt,"f").deferY18nLookup("Show version number"),v(this,pt,"f").version(s||void 0),this.boolean(v(this,mt,"f")),this.describe(v(this,mt,"f"),e),this}wrap(t){return h("<number|null|undefined>",[t],arguments.length),v(this,pt,"f").wrap(t),this}[(z=new WeakMap,W=new WeakMap,q=new WeakMap,U=new WeakMap,F=new WeakMap,L=new WeakMap,V=new WeakMap,G=new WeakMap,R=new WeakMap,T=new WeakMap,B=new WeakMap,K=new WeakMap,Y=new WeakMap,J=new WeakMap,Z=new WeakMap,X=new WeakMap,Q=new WeakMap,tt=new WeakMap,et=new WeakMap,st=new WeakMap,it=new WeakMap,nt=new WeakMap,rt=new WeakMap,ot=new WeakMap,at=new WeakMap,ht=new WeakMap,lt=new WeakMap,ct=new WeakMap,ft=new WeakMap,dt=new WeakMap,ut=new WeakMap,pt=new WeakMap,gt=new WeakMap,mt=new WeakMap,yt=new WeakMap,bt)](t){if(!t._||!t["--"])return t;t._.push.apply(t._,t["--"]);try{delete t["--"]}catch(t){}return t}[vt](){return{log:(...t)=>{this[Rt]()||console.log(...t),O(this,J,!0,"f"),v(this,tt,"f").length&&O(this,tt,v(this,tt,"f")+"\n","f"),O(this,tt,v(this,tt,"f")+t.join(" "),"f")},error:(...t)=>{this[Rt]()||console.error(...t),O(this,J,!0,"f"),v(this,tt,"f").length&&O(this,tt,v(this,tt,"f")+"\n","f"),O(this,tt,v(this,tt,"f")+t.join(" "),"f")}}}[Ot](t){p(v(this,et,"f")).forEach((e=>{if("configObjects"===e)return;const s=v(this,et,"f")[e];Array.isArray(s)?s.includes(t)&&s.splice(s.indexOf(t),1):"object"==typeof s&&delete s[t]})),delete v(this,pt,"f").getDescriptions()[t]}[wt](t,e,s){v(this,R,"f")[s]||(v(this,ct,"f").process.emitWarning(t,e),v(this,R,"f")[s]=!0)}[Ct](){v(this,B,"f").push({options:v(this,et,"f"),configObjects:v(this,et,"f").configObjects.slice(0),exitProcess:v(this,T,"f"),groups:v(this,Y,"f"),strict:v(this,ft,"f"),strictCommands:v(this,dt,"f"),strictOptions:v(this,ut,"f"),completionCommand:v(this,F,"f"),output:v(this,tt,"f"),exitError:v(this,V,"f"),hasOutput:v(this,J,"f"),parsed:this.parsed,parseFn:v(this,nt,"f"),parseContext:v(this,rt,"f")}),v(this,pt,"f").freeze(),v(this,yt,"f").freeze(),v(this,z,"f").freeze(),v(this,K,"f").freeze()}[jt](){let t,e="";return t=/\b(node|iojs|electron)(\.exe)?$/.test(v(this,ct,"f").process.argv()[0])?v(this,ct,"f").process.argv().slice(1,2):v(this,ct,"f").process.argv().slice(0,1),e=t.map((t=>{const e=this[Kt](v(this,W,"f"),t);return t.match(/^(\/|([a-zA-Z]:)?\\)/)&&e.length<t.length?e:t})).join(" ").trim(),v(this,ct,"f").getEnv("_")&&v(this,ct,"f").getProcessArgvBin()===v(this,ct,"f").getEnv("_")&&(e=v(this,ct,"f").getEnv("_").replace(`${v(this,ct,"f").path.dirname(v(this,ct,"f").process.execPath())}/`,"")),e}[Mt](){return v(this,it,"f")}[_t](){return v(this,gt,"f")}[kt](){if(!v(this,G,"f"))return;const t=v(this,ct,"f").getEnv("LC_ALL")||v(this,ct,"f").getEnv("LC_MESSAGES")||v(this,ct,"f").getEnv("LANG")||v(this,ct,"f").getEnv("LANGUAGE")||"en_US";this.locale(t.replace(/[.:].*/,""))}[xt](){return this[At]().version||"unknown"}[Et](t){const e=t["--"]?t["--"]:t._;for(let t,s=0;void 0!==(t=e[s]);s++)v(this,ct,"f").Parser.looksLikeNumber(t)&&Number.isSafeInteger(Math.floor(parseFloat(`${t}`)))&&(e[s]=Number(t));return t}[At](t){const e=t||"*";if(v(this,ot,"f")[e])return v(this,ot,"f")[e];let s={};try{let e=t||v(this,ct,"f").mainFilename;!t&&v(this,ct,"f").path.extname(e)&&(e=v(this,ct,"f").path.dirname(e));const i=v(this,ct,"f").findUp(e,((t,e)=>e.includes("package.json")?"package.json":void 0));d(i,void 0,v(this,ct,"f")),s=JSON.parse(v(this,ct,"f").readFileSync(i,"utf8"))}catch(t){}return v(this,ot,"f")[e]=s||{},v(this,ot,"f")[e]}[Pt](t,e){(e=[].concat(e)).forEach((e=>{e=this[Dt](e),v(this,et,"f")[t].push(e)}))}[St](t,e,s,i){this[It](t,e,s,i,((t,e,s)=>{v(this,et,"f")[t][e]=s}))}[$t](t,e,s,i){this[It](t,e,s,i,((t,e,s)=>{v(this,et,"f")[t][e]=(v(this,et,"f")[t][e]||[]).concat(s)}))}[It](t,e,s,i,n){if(Array.isArray(s))s.forEach((e=>{t(e,i)}));else if((t=>"object"==typeof t)(s))for(const e of p(s))t(e,s[e]);else n(e,this[Dt](s),i)}[Dt](t){return"__proto__"===t?"___proto___":t}[Nt](t,e){return this[St](this[Nt].bind(this),"key",t,e),this}[Ht](){var t,e,s,i,n,r,o,a,h,l,c,f;const u=v(this,B,"f").pop();let p;d(u,void 0,v(this,ct,"f")),t=this,e=this,s=this,i=this,n=this,r=this,o=this,a=this,h=this,l=this,c=this,f=this,({options:{set value(e){O(t,et,e,"f")}}.value,configObjects:p,exitProcess:{set value(t){O(e,T,t,"f")}}.value,groups:{set value(t){O(s,Y,t,"f")}}.value,output:{set value(t){O(i,tt,t,"f")}}.value,exitError:{set value(t){O(n,V,t,"f")}}.value,hasOutput:{set value(t){O(r,J,t,"f")}}.value,parsed:this.parsed,strict:{set value(t){O(o,ft,t,"f")}}.value,strictCommands:{set value(t){O(a,dt,t,"f")}}.value,strictOptions:{set value(t){O(h,ut,t,"f")}}.value,completionCommand:{set value(t){O(l,F,t,"f")}}.value,parseFn:{set value(t){O(c,nt,t,"f")}}.value,parseContext:{set value(t){O(f,rt,t,"f")}}.value}=u),v(this,et,"f").configObjects=p,v(this,pt,"f").unfreeze(),v(this,yt,"f").unfreeze(),v(this,z,"f").unfreeze(),v(this,K,"f").unfreeze()}[zt](t,e){return j(e,(e=>(t(e),e)))}getInternalMethods(){return{getCommandInstance:this[Wt].bind(this),getContext:this[qt].bind(this),getHasOutput:this[Ut].bind(this),getLoggerInstance:this[Ft].bind(this),getParseContext:this[Lt].bind(this),getParserConfiguration:this[Mt].bind(this),getUsageConfiguration:this[_t].bind(this),getUsageInstance:this[Vt].bind(this),getValidationInstance:this[Gt].bind(this),hasParseCallback:this[Rt].bind(this),isGlobalContext:this[Tt].bind(this),postProcess:this[Bt].bind(this),reset:this[Yt].bind(this),runValidation:this[Zt].bind(this),runYargsParserAndExecuteCommands:this[Jt].bind(this),setHasOutput:this[Xt].bind(this)}}[Wt](){return v(this,z,"f")}[qt](){return v(this,q,"f")}[Ut](){return v(this,J,"f")}[Ft](){return v(this,Q,"f")}[Lt](){return v(this,rt,"f")||{}}[Vt](){return v(this,pt,"f")}[Gt](){return v(this,yt,"f")}[Rt](){return!!v(this,nt,"f")}[Tt](){return v(this,X,"f")}[Bt](t,e,s,i){if(s)return t;if(f(t))return t;e||(t=this[bt](t));return(this[Mt]()["parse-positional-numbers"]||void 0===this[Mt]()["parse-positional-numbers"])&&(t=this[Et](t)),i&&(t=C(t,this,v(this,K,"f").getMiddleware(),!1)),t}[Yt](t={}){O(this,et,v(this,et,"f")||{},"f");const e={};e.local=v(this,et,"f").local||[],e.configObjects=v(this,et,"f").configObjects||[];const s={};e.local.forEach((e=>{s[e]=!0,(t[e]||[]).forEach((t=>{s[t]=!0}))})),Object.assign(v(this,at,"f"),Object.keys(v(this,Y,"f")).reduce(((t,e)=>{const i=v(this,Y,"f")[e].filter((t=>!(t in s)));return i.length>0&&(t[e]=i),t}),{})),O(this,Y,{},"f");return["array","boolean","string","skipValidation","count","normalize","number","hiddenOptions"].forEach((t=>{e[t]=(v(this,et,"f")[t]||[]).filter((t=>!s[t]))})),["narg","key","alias","default","defaultDescription","config","choices","demandedOptions","demandedCommands","deprecatedOptions"].forEach((t=>{e[t]=g(v(this,et,"f")[t],(t=>!s[t]))})),e.envPrefix=v(this,et,"f").envPrefix,O(this,et,e,"f"),O(this,pt,v(this,pt,"f")?v(this,pt,"f").reset(s):P(this,v(this,ct,"f")),"f"),O(this,yt,v(this,yt,"f")?v(this,yt,"f").reset(s):function(t,e,s){const i=s.y18n.__,n=s.y18n.__n,r={nonOptionCount:function(s){const i=t.getDemandedCommands(),r=s._.length+(s["--"]?s["--"].length:0)-t.getInternalMethods().getContext().commands.length;i._&&(r<i._.min||r>i._.max)&&(r<i._.min?void 0!==i._.minMsg?e.fail(i._.minMsg?i._.minMsg.replace(/\$0/g,r.toString()).replace(/\$1/,i._.min.toString()):null):e.fail(n("Not enough non-option arguments: got %s, need at least %s","Not enough non-option arguments: got %s, need at least %s",r,r.toString(),i._.min.toString())):r>i._.max&&(void 0!==i._.maxMsg?e.fail(i._.maxMsg?i._.maxMsg.replace(/\$0/g,r.toString()).replace(/\$1/,i._.max.toString()):null):e.fail(n("Too many non-option arguments: got %s, maximum of %s","Too many non-option arguments: got %s, maximum of %s",r,r.toString(),i._.max.toString()))))},positionalCount:function(t,s){s<t&&e.fail(n("Not enough non-option arguments: got %s, need at least %s","Not enough non-option arguments: got %s, need at least %s",s,s+"",t+""))},requiredArguments:function(t,s){let i=null;for(const e of Object.keys(s))Object.prototype.hasOwnProperty.call(t,e)&&void 0!==t[e]||(i=i||{},i[e]=s[e]);if(i){const t=[];for(const e of Object.keys(i)){const s=i[e];s&&t.indexOf(s)<0&&t.push(s)}const s=t.length?`\n${t.join("\n")}`:"";e.fail(n("Missing required argument: %s","Missing required arguments: %s",Object.keys(i).length,Object.keys(i).join(", ")+s))}},unknownArguments:function(s,i,o,a,h=!0){var l;const c=t.getInternalMethods().getCommandInstance().getCommands(),f=[],d=t.getInternalMethods().getContext();if(Object.keys(s).forEach((e=>{H.includes(e)||Object.prototype.hasOwnProperty.call(o,e)||Object.prototype.hasOwnProperty.call(t.getInternalMethods().getParseContext(),e)||r.isValidAndSomeAliasIsNotNew(e,i)||f.push(e)})),h&&(d.commands.length>0||c.length>0||a)&&s._.slice(d.commands.length).forEach((t=>{c.includes(""+t)||f.push(""+t)})),h){const e=(null===(l=t.getDemandedCommands()._)||void 0===l?void 0:l.max)||0,i=d.commands.length+e;i<s._.length&&s._.slice(i).forEach((t=>{t=String(t),d.commands.includes(t)||f.includes(t)||f.push(t)}))}f.length&&e.fail(n("Unknown argument: %s","Unknown arguments: %s",f.length,f.map((t=>t.trim()?t:`"${t}"`)).join(", ")))},unknownCommands:function(s){const i=t.getInternalMethods().getCommandInstance().getCommands(),r=[],o=t.getInternalMethods().getContext();return(o.commands.length>0||i.length>0)&&s._.slice(o.commands.length).forEach((t=>{i.includes(""+t)||r.push(""+t)})),r.length>0&&(e.fail(n("Unknown command: %s","Unknown commands: %s",r.length,r.join(", "))),!0)},isValidAndSomeAliasIsNotNew:function(e,s){if(!Object.prototype.hasOwnProperty.call(s,e))return!1;const i=t.parsed.newAliases;return[e,...s[e]].some((t=>!Object.prototype.hasOwnProperty.call(i,t)||!i[e]))},limitedChoices:function(s){const n=t.getOptions(),r={};if(!Object.keys(n.choices).length)return;Object.keys(s).forEach((t=>{-1===H.indexOf(t)&&Object.prototype.hasOwnProperty.call(n.choices,t)&&[].concat(s[t]).forEach((e=>{-1===n.choices[t].indexOf(e)&&void 0!==e&&(r[t]=(r[t]||[]).concat(e))}))}));const o=Object.keys(r);if(!o.length)return;let a=i("Invalid values:");o.forEach((t=>{a+=`\n  ${i("Argument: %s, Given: %s, Choices: %s",t,e.stringifiedValues(r[t]),e.stringifiedValues(n.choices[t]))}`})),e.fail(a)}};let o={};function a(t,e){const s=Number(e);return"number"==typeof(e=isNaN(s)?e:s)?e=t._.length>=e:e.match(/^--no-.+/)?(e=e.match(/^--no-(.+)/)[1],e=!Object.prototype.hasOwnProperty.call(t,e)):e=Object.prototype.hasOwnProperty.call(t,e),e}r.implies=function(e,i){h("<string|object> [array|number|string]",[e,i],arguments.length),"object"==typeof e?Object.keys(e).forEach((t=>{r.implies(t,e[t])})):(t.global(e),o[e]||(o[e]=[]),Array.isArray(i)?i.forEach((t=>r.implies(e,t))):(d(i,void 0,s),o[e].push(i)))},r.getImplied=function(){return o},r.implications=function(t){const s=[];if(Object.keys(o).forEach((e=>{const i=e;(o[e]||[]).forEach((e=>{let n=i;const r=e;n=a(t,n),e=a(t,e),n&&!e&&s.push(` ${i} -> ${r}`)}))})),s.length){let t=`${i("Implications failed:")}\n`;s.forEach((e=>{t+=e})),e.fail(t)}};let l={};r.conflicts=function(e,s){h("<string|object> [array|string]",[e,s],arguments.length),"object"==typeof e?Object.keys(e).forEach((t=>{r.conflicts(t,e[t])})):(t.global(e),l[e]||(l[e]=[]),Array.isArray(s)?s.forEach((t=>r.conflicts(e,t))):l[e].push(s))},r.getConflicting=()=>l,r.conflicting=function(n){Object.keys(n).forEach((t=>{l[t]&&l[t].forEach((s=>{s&&void 0!==n[t]&&void 0!==n[s]&&e.fail(i("Arguments %s and %s are mutually exclusive",t,s))}))})),t.getInternalMethods().getParserConfiguration()["strip-dashed"]&&Object.keys(l).forEach((t=>{l[t].forEach((r=>{r&&void 0!==n[s.Parser.camelCase(t)]&&void 0!==n[s.Parser.camelCase(r)]&&e.fail(i("Arguments %s and %s are mutually exclusive",t,r))}))}))},r.recommendCommands=function(t,s){s=s.sort(((t,e)=>e.length-t.length));let n=null,r=1/0;for(let e,i=0;void 0!==(e=s[i]);i++){const s=N(t,e);s<=3&&s<r&&(r=s,n=e)}n&&e.fail(i("Did you mean %s?",n))},r.reset=function(t){return o=g(o,(e=>!t[e])),l=g(l,(e=>!t[e])),r};const c=[];return r.freeze=function(){c.push({implied:o,conflicting:l})},r.unfreeze=function(){const t=c.pop();d(t,void 0,s),({implied:o,conflicting:l}=t)},r}(this,v(this,pt,"f"),v(this,ct,"f")),"f"),O(this,z,v(this,z,"f")?v(this,z,"f").reset():function(t,e,s,i){return new _(t,e,s,i)}(v(this,pt,"f"),v(this,yt,"f"),v(this,K,"f"),v(this,ct,"f")),"f"),v(this,U,"f")||O(this,U,function(t,e,s,i){return new D(t,e,s,i)}(this,v(this,pt,"f"),v(this,z,"f"),v(this,ct,"f")),"f"),v(this,K,"f").reset(),O(this,F,null,"f"),O(this,tt,"","f"),O(this,V,null,"f"),O(this,J,!1,"f"),this.parsed=!1,this}[Kt](t,e){return v(this,ct,"f").path.relative(t,e)}[Jt](t,s,i,n=0,r=!1){let o=!!i||r;t=t||v(this,ht,"f"),v(this,et,"f").__=v(this,ct,"f").y18n.__,v(this,et,"f").configuration=this[Mt]();const a=!!v(this,et,"f").configuration["populate--"],h=Object.assign({},v(this,et,"f").configuration,{"populate--":!0}),l=v(this,ct,"f").Parser.detailed(t,Object.assign({},v(this,et,"f"),{configuration:{"parse-positional-numbers":!1,...h}})),c=Object.assign(l.argv,v(this,rt,"f"));let d;const u=l.aliases;let p=!1,g=!1;Object.keys(c).forEach((t=>{t===v(this,Z,"f")&&c[t]?p=!0:t===v(this,mt,"f")&&c[t]&&(g=!0)})),c.$0=this.$0,this.parsed=l,0===n&&v(this,pt,"f").clearCachedHelpMessage();try{if(this[kt](),s)return this[Bt](c,a,!!i,!1);if(v(this,Z,"f")){[v(this,Z,"f")].concat(u[v(this,Z,"f")]||[]).filter((t=>t.length>1)).includes(""+c._[c._.length-1])&&(c._.pop(),p=!0)}O(this,X,!1,"f");const h=v(this,z,"f").getCommands(),m=v(this,U,"f").completionKey in c,y=p||m||r;if(c._.length){if(h.length){let t;for(let e,s=n||0;void 0!==c._[s];s++){if(e=String(c._[s]),h.includes(e)&&e!==v(this,F,"f")){const t=v(this,z,"f").runCommand(e,this,l,s+1,r,p||g||r);return this[Bt](t,a,!!i,!1)}if(!t&&e!==v(this,F,"f")){t=e;break}}!v(this,z,"f").hasDefaultCommand()&&v(this,lt,"f")&&t&&!y&&v(this,yt,"f").recommendCommands(t,h)}v(this,F,"f")&&c._.includes(v(this,F,"f"))&&!m&&(v(this,T,"f")&&E(!0),this.showCompletionScript(),this.exit(0))}if(v(this,z,"f").hasDefaultCommand()&&!y){const t=v(this,z,"f").runCommand(null,this,l,0,r,p||g||r);return this[Bt](t,a,!!i,!1)}if(m){v(this,T,"f")&&E(!0);const s=(t=[].concat(t)).slice(t.indexOf(`--${v(this,U,"f").completionKey}`)+1);return v(this,U,"f").getCompletion(s,((t,s)=>{if(t)throw new e(t.message);(s||[]).forEach((t=>{v(this,Q,"f").log(t)})),this.exit(0)})),this[Bt](c,!a,!!i,!1)}if(v(this,J,"f")||(p?(v(this,T,"f")&&E(!0),o=!0,this.showHelp("log"),this.exit(0)):g&&(v(this,T,"f")&&E(!0),o=!0,v(this,pt,"f").showVersion("log"),this.exit(0))),!o&&v(this,et,"f").skipValidation.length>0&&(o=Object.keys(c).some((t=>v(this,et,"f").skipValidation.indexOf(t)>=0&&!0===c[t]))),!o){if(l.error)throw new e(l.error.message);if(!m){const t=this[Zt](u,{},l.error);i||(d=C(c,this,v(this,K,"f").getMiddleware(),!0)),d=this[zt](t,null!=d?d:c),f(d)&&!i&&(d=d.then((()=>C(c,this,v(this,K,"f").getMiddleware(),!1))))}}}catch(t){if(!(t instanceof e))throw t;v(this,pt,"f").fail(t.message,t)}return this[Bt](null!=d?d:c,a,!!i,!0)}[Zt](t,s,i,n){const r={...this.getDemandedOptions()};return o=>{if(i)throw new e(i.message);v(this,yt,"f").nonOptionCount(o),v(this,yt,"f").requiredArguments(o,r);let a=!1;v(this,dt,"f")&&(a=v(this,yt,"f").unknownCommands(o)),v(this,ft,"f")&&!a?v(this,yt,"f").unknownArguments(o,t,s,!!n):v(this,ut,"f")&&v(this,yt,"f").unknownArguments(o,t,{},!1,!1),v(this,yt,"f").limitedChoices(o),v(this,yt,"f").implications(o),v(this,yt,"f").conflicting(o)}}[Xt](){O(this,J,!0,"f")}[Qt](t){if("string"==typeof t)v(this,et,"f").key[t]=!0;else for(const e of t)v(this,et,"f").key[e]=!0}}var ee,se;const{readFileSync:ie}=__nccwpck_require__(7147),{inspect:ne}=__nccwpck_require__(3837),{resolve:re}=__nccwpck_require__(1017),oe=__nccwpck_require__(452),ae=__nccwpck_require__(1970);var he,le={assert:{notStrictEqual:t.notStrictEqual,strictEqual:t.strictEqual},cliui:__nccwpck_require__(7059),findUp:__nccwpck_require__(2644),getEnv:t=>process.env[t],getCallerFile:__nccwpck_require__(351),getProcessArgvBin:y,inspect:ne,mainFilename:null!==(se=null===(ee= false||void 0===__nccwpck_require__(9167)?void 0:__nccwpck_require__.c[__nccwpck_require__.s])||void 0===ee?void 0:ee.filename)&&void 0!==se?se:process.cwd(),Parser:ae,path:__nccwpck_require__(1017),process:{argv:()=>process.argv,cwd:process.cwd,emitWarning:(t,e)=>process.emitWarning(t,e),execPath:()=>process.execPath,exit:t=>{process.exit(t)},nextTick:process.nextTick,stdColumns:void 0!==process.stdout.columns?process.stdout.columns:null},readFileSync:ie,require:__nccwpck_require__(9167),requireDirectory:__nccwpck_require__(9200),stringWidth:__nccwpck_require__(2577),y18n:oe({directory:re(__dirname,"../locales"),updateFiles:!1})};const ce=(null===(he=null===process||void 0===process?void 0:process.env)||void 0===he?void 0:he.YARGS_MIN_NODE_VERSION)?Number(process.env.YARGS_MIN_NODE_VERSION):12;if(process&&process.version){if(Number(process.version.match(/v([^.]+)/)[1])<ce)throw Error(`yargs supports a minimum Node.js version of ${ce}. Read our version support policy: https://github.com/yargs/yargs#supported-nodejs-versions`)}const fe=__nccwpck_require__(1970);var de,ue={applyExtends:n,cjsPlatformShim:le,Yargs:(de=le,(t=[],e=de.process.cwd(),s)=>{const i=new te(t,e,s,de);return Object.defineProperty(i,"argv",{get:()=>i.parse(),enumerable:!0}),i.help(),i.version(),i}),argsert:h,isPromise:f,objFilter:g,parseCommand:o,Parser:fe,processArgv:b,YError:e};module.exports=ue;


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