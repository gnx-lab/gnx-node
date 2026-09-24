const status=document.querySelector('#status'),detail=document.querySelector('#detail'),$=id=>document.querySelector(id),phases=[...document.querySelectorAll('#steps li')];
let busy=false;
async function invoke(method,tailscale_auth_key,proxmox_password){
  if(busy&&method!=='GetProgress')return;
  busy=method!=='GetProgress';
  $('#provision').disabled=busy;$('#join').disabled=busy;$('#retry').disabled=busy;
  $('#cancel').hidden=true;
  if(method==='JoinMesh'){status.textContent='Joining the private mesh and starting services…';detail.textContent='This can take up to three minutes. Do not close Setup.'}
  if(method==='Provision'){status.textContent='Preparing Windows and the Linux runtime…';detail.textContent='This can take several minutes. Do not close Setup.'}
  try{
    const r=await fetch('/bridge',{method:'POST',body:JSON.stringify({method,tailscale_auth_key,proxmox_password})});
    const p=await r.json();if(p.error)throw Error(p.error);render(p.progress||p);
  }catch(e){status.textContent='Could not contact the local service.';detail.textContent=e.message;$('#retry').hidden=false}
  finally{busy=false;$('#provision').disabled=false;$('#join').disabled=false;$('#retry').disabled=false;$('#cancel').hidden=true; if(method==='JoinMesh'){$('#mesh-key').value='';$('#mesh-key').blur()} if(method==='Provision'){$('#proxmox-password').value='';$('#proxmox-password').blur()}}
}
function render(p){
  status.textContent=p.message||'Node status';
  detail.textContent=p.error_code?`Code: ${p.error_code}`:'';
  phases.forEach((el,i)=>el.className=p.percent!=null&&i*20<p.percent?'done':'');
  const canStart=['NEW','BLOCKED','FAILED','RECOVERY_REQUIRED','REBOOT_REQUIRED'].includes(p.state);
  const canJoin=p.state==='RUNTIME_READY'||p.state==='MESH_PENDING'||(p.state==='BLOCKED'&&p.phase==='mesh');
  $('#provision').hidden=!canStart;$('#proxmox-label').hidden=!canStart;$('#proxmox-password').hidden=!canStart;
  $('#key-label').hidden=!canJoin;$('#mesh-key').hidden=!canJoin;$('#join').hidden=!canJoin;
  $('#restart').hidden=!p.requires_restart;$('#retry').hidden=!p.retryable;
  if(p.node_private_ip||p.tailscale_ip)detail.textContent=`Private node/DNS IP: ${p.node_private_ip||p.tailscale_ip}`;
  if(Array.isArray(p.required_actions)&&p.required_actions.length&&!p.node_private_ip&&!p.tailscale_ip)detail.textContent=p.required_actions.map(a=>a.kind).join(' · ');
}
$('#provision').addEventListener('click',()=>invoke('Provision',undefined,$('#proxmox-password').value));
$('#join').addEventListener('click',()=>{const key=$('#mesh-key').value;invoke('JoinMesh',key)});
$('#retry').addEventListener('click',()=>invoke('Retry'));$('#cancel').addEventListener('click',()=>invoke('Cancel'));
// Reboot remains an explicit human action. Setup never starts an arbitrary OS command.
$('#restart').addEventListener('click',()=>{status.textContent='Restart Windows from the Start menu, then reopen GnX Setup.';detail.textContent='The host service will continue from its checkpoint.'});
window.addEventListener('load',()=>invoke('GetProgress'));
