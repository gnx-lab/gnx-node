const status=document.querySelector('#status'),detail=document.querySelector('#detail'),$=id=>document.querySelector(id),phases=[...document.querySelectorAll('#steps li')];
let busy=false;
async function invoke(method,tailscale_auth_key){
  if(busy&&method!=='GetProgress')return;
  busy=method!=='GetProgress';
  try{
    const r=await fetch('gnx://bridge',{method:'POST',body:JSON.stringify({method,tailscale_auth_key})});
    const p=await r.json();if(p.error)throw Error(p.error);render(p.progress||p);
  }catch(e){status.textContent='Could not contact the local service.';detail.textContent=e.message;$('#retry').hidden=false}
  finally{busy=false; if(method==='JoinMesh'){$('#mesh-key').value='';$('#mesh-key').blur()}}
}
function render(p){
  status.textContent=p.message||'Node status';
  detail.textContent=p.error_code?`Code: ${p.error_code}`:'';
  phases.forEach((el,i)=>el.className=p.percent!=null&&i*20<p.percent?'done':'');
  $('#restart').hidden=!p.requires_restart;$('#retry').hidden=!p.retryable;
  if(p.phase==='mesh'){$('#key-label').hidden=false;$('#mesh-key').hidden=false;$('#join').hidden=false}
  if(p.state==='NODE_READY')$('#deprovision').hidden=false;
}
$('#provision').addEventListener('click',()=>{$('#provision').hidden=true;$('#cancel').hidden=false;invoke('Provision')});
$('#join').addEventListener('click',()=>{const key=$('#mesh-key').value;invoke('JoinMesh',key)});
$('#retry').addEventListener('click',()=>invoke('Retry'));$('#cancel').addEventListener('click',()=>invoke('Cancel'));$('#deprovision').addEventListener('click',()=>invoke('Deprovision'));
// Reboot remains an explicit human action. Setup never starts an arbitrary OS command.
$('#restart').addEventListener('click',()=>{status.textContent='Restart Windows from the Start menu, then reopen GnX Setup.';detail.textContent='The host service will continue from its checkpoint.'});
window.addEventListener('load',()=>invoke('GetProgress'));
