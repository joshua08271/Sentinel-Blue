(function(){
if(globalThis.__sentinelBluePortalHelperLoaded)return;
globalThis.__sentinelBluePortalHelperLoaded=true;
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));

function assertOrigin(profile){
  const allowed=[profile.portalOrigin,...(profile.allowedFrameOrigins||[])];
  if(!allowed.includes(location.origin))throw new Error('Frame origin is not an approved competition portal origin');
}

async function waitForSingle(selector,timeout=15000){
  const end=Date.now()+timeout;
  while(Date.now()<end){const elements=document.querySelectorAll(selector);if(elements.length>1)throw new Error(`Expected exactly one console input; found ${elements.length}`);if(elements.length===1)return elements[0];await pause(200);}
  throw new Error(`Timed out waiting for ${selector}`);
}

async function inject(element,text){
  element.focus();
  if(element instanceof HTMLInputElement||element instanceof HTMLTextAreaElement){
    const setter=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(element),'value')?.set;
    if(setter)setter.call(element,text);else element.value=text;
    element.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText',data:text}));
  }else if(element.isContentEditable){
    element.textContent=text;element.dispatchEvent(new InputEvent('input',{bubbles:true,data:text}));
  }else{
    await navigator.clipboard.writeText(text);
    element.dispatchEvent(new KeyboardEvent('keydown',{key:'v',code:'KeyV',ctrlKey:true,shiftKey:true,bubbles:true}));
    element.dispatchEvent(new KeyboardEvent('keyup',{key:'v',code:'KeyV',ctrlKey:true,shiftKey:true,bubbles:true}));
  }
  element.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',code:'Enter',bubbles:true}));
  element.dispatchEvent(new KeyboardEvent('keyup',{key:'Enter',code:'Enter',bubbles:true}));
}

chrome.runtime.onMessage.addListener((message,_sender,respond)=>{
  (async()=>{
    const {profile,commands}=message;assertOrigin(profile);
    if(message.action==='discover')return {ok:true,devices:document.querySelectorAll(profile.deviceSelector).length,consoles:document.querySelectorAll(profile.consoleSelector).length};
    if(message.action==='bootstrapCurrent'){
      const consoleInput=await waitForSingle(profile.consoleSelector);await inject(consoleInput,commands[profile.operatingSystem]);
      return {ok:true,message:'Bootstrap injected into the current assigned console.'};
    }
    throw new Error('Unknown portal-helper action');
  })().then(respond).catch(error=>respond({ok:false,error:error.message}));
  return true;
});
})();
